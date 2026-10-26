#include <zephyr/kernel.h>

#include <errno.h>
#include <stddef.h>
#include <syscalls/kobject.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/kobject.h>
#include <zephyr/syscalls/atmlab_syscall.h>

#include "atm.h"
#include "coap_service.h"
#include "inet.h"
#include "pppoeoa.h"
#include "socket_atm.h"
#include "userspace.h"

#define USER_STACKSIZE	4096

// the largest CoAP message we answer with, must fit on the stack
#define COAP_REPLY_SIZE 256

// shared by the accept loop and its handlers, so neither can starve the other
#define HANDLER_PRIORITY 5

struct k_thread userspace_thread;
K_THREAD_STACK_DEFINE(userspace_stack, USER_STACKSIZE);

/*
 * One connection's working set, in the order the handler fills it in: the frame
 * we read, the view of it that parsing leaves behind, and the CoAP service that
 * answers it on this connection's transport. connection_handler keeps exactly
 * one of these, so the whole loop body is `&c` plus the reply buffer.
 */
struct connection {
    /* one PPPoEoA frame, the size aal5_rx() wants: a whole number of cells
     * minus the AAL5 trailer */
    uint8_t frame[ATM_SDU_SIZE * 10 - 8];
    /* the CoAP service answers on this connection; its dispatch state sits right
     * behind frame[], where an over-long reassembly can overrun into it */
    struct coap_service service;
    /* where the UDP payload starts inside frame[] */
    uint8_t *payload;
    /* the peer, as the frame we are answering names it */
    struct k_container *socket;
    uint8_t *remote_mac;
    uint8_t *local_mac;
    uint8_t *remote_ip;
    uint8_t *local_ip;
    uint16_t session_id;
    uint16_t remote_port;
    uint16_t local_port;
};

/*
 * That order is load-bearing, and not something the compiler would keep on its
 * own if these were plain locals: the reassembler works in whole cells, so the
 * tail of an over-long frame lands in the eight bytes behind frame[] -- the
 * trailer, whose CRC word falls exactly on the index that selects the service's
 * sender. Leave it there, and keep request_body immediately past senders[] -- an
 * out-of-range index reads it as one more sender.
 */
BUILD_ASSERT(offsetof(struct connection, service) == ATM_SDU_SIZE * 10 - 8);
BUILD_ASSERT(offsetof(struct coap_service, sender) == 4);
BUILD_ASSERT(offsetof(struct coap_service, senders) == 8);
BUILD_ASSERT(offsetof(struct coap_service, request_body)
        == offsetof(struct coap_service, senders) + COAP_SENDERS * sizeof(coap_transmit_t));

/* the CoAP service's transport: wrap one rendered response and put it on the
 * circuit it came in on */
static int send_reply(struct coap_service *service, uint8_t *reply, int reply_len)
{
    struct connection *c = service->transport;

    uint8_t ipv4_buffer[COAP_REPLY_SIZE + IPV4_UDP_HDR_LEN];
    int ipv4_len = ipv4_build(ipv4_buffer, sizeof(ipv4_buffer), c->local_ip, c->remote_ip,
            c->local_port, c->remote_port, reply, reply_len);
    if (ipv4_len < 0) {
        printf("Error in ipv4_build\n");
        return ipv4_len;
    }

    uint8_t pppoeoa_buffer[COAP_REPLY_SIZE + IPV4_UDP_HDR_LEN + PPPOEOA_HDR_LEN];
    int pppoeoa_len = pppoeoa_build(pppoeoa_buffer, sizeof(pppoeoa_buffer), c->local_mac,
            c->remote_mac, c->session_id, ipv4_buffer, ipv4_len);
    if (pppoeoa_len < 0) {
        printf("Error in pppoeoa_build\n");
        return pppoeoa_len;
    }

    return (int)atmlab_write(c->socket, pppoeoa_buffer, pppoeoa_len);
}

/* the muted response path: a connection can be set to swallow its answers instead
 * of putting them on the wire (for one that is being torn down). Not yet wired to
 * anything, but the sender table has to be complete for the index to be valid. */
static int discard_reply(struct coap_service *service, uint8_t *reply, int reply_len)
{
    ARG_UNUSED(service);
    ARG_UNUSED(reply);
    return reply_len;
}

/* the response paths a connection binds at accept; index 0 is the wire path */
static const coap_transmit_t connection_senders[COAP_SENDERS] = {
    send_reply,
    discard_reply,
};

static void connection_handler(void* p1, void* p2, void* p3)
{
    struct connection c = { .socket = (struct k_container*)p1 };

    coap_service_init(&c.service, connection_senders, &c, 0);

    while (true) {
        ssize_t n = atmlab_read(c.socket, c.frame, sizeof(c.frame));
        if (n < 0) {
            // not connected means remote closed the connection don't print an error in that case
            if (n != -ENOTCONN) {
                printf("Error in receive: %s\n", strerror(-n));
            }
            break;
        }

        // parse pppoeoa frame
        uint8_t *pppoeoa_payload;
        int pppoeoa_payload_len = pppoeoa_parse(c.frame, n, &c.remote_mac, &c.local_mac, &c.session_id, &pppoeoa_payload);

        if (pppoeoa_payload_len < 0) {
            printf("Error in pppoeoa_parse\n");
            continue;
        }

        // parse ipv4 and UDP frame
        int udp_payload_len = ipv4_parse(pppoeoa_payload, pppoeoa_payload_len, &c.remote_ip, &c.local_ip, &c.remote_port, &c.local_port, &c.payload);

        if (udp_payload_len < 0) {
            printf("Error in ipv4_parse\n");
            continue;
        }

        // run the CoAP server on it; it answers through send_reply()
        uint8_t coap_buffer[COAP_REPLY_SIZE];

        int ret = coap_service_handle(&c.service, c.payload, udp_payload_len, coap_buffer, sizeof(coap_buffer));
        if (ret < 0) {
            printf("Error in coap_service_handle: %s\n", strerror(-ret));
            continue;
        }
    }

    atmlab_close(c.socket);
}

// one slot per entry in thread_domains[]: the slot index is the handler's
// memory domain
static struct {
    struct k_thread *thread;
    k_thread_stack_t *stack;
} handlers[MAX_HANDLERS];

// nothing frees a dynamic thread on exit, and a thread cannot free the stack it
// runs on, so the accept loop cleans up after the handlers it spawned
static void reap_handlers(void)
{
    // handlers share our priority, so ones that were woken (to exit) or just
    // created never run while we are busy with a burst of signalling; let them
    // finish first, or every slot looks busy and calls get refused
    k_yield();

    for (size_t i = 0; i < ARRAY_SIZE(handlers); ++i) {
        if (handlers[i].thread == NULL) {
            continue;
        }
        // -EBUSY: still serving its connection
        if (k_thread_join(handlers[i].thread, K_NO_WAIT) != 0) {
            continue;
        }
        k_thread_stack_free(handlers[i].stack);
        k_object_free(handlers[i].thread);
        handlers[i].thread = NULL;
        handlers[i].stack = NULL;
    }
}

static void spawn_handler_thread(struct k_container * socket)
{
    reap_handlers();

    size_t slot;
    for (slot = 0; slot < ARRAY_SIZE(handlers); ++slot) {
        if (handlers[slot].thread == NULL) {
            break;
        }
    }
    if (slot == ARRAY_SIZE(handlers)) {
        printf("Refusing connection, all %d handlers are busy\n", MAX_HANDLERS);
        atmlab_close(socket);
        return;
    }

    // This stack is executable as well as writable (see
    // CONFIG_XTENSA_USER_STACK_EXECUTABLE): the reassembler hands frames to code
    // that expects to run them in place, and a separate scratch mapping is not
    // worth the page tables.
    k_thread_stack_t *stack = k_thread_stack_alloc(USER_STACKSIZE, K_USER);
    if (stack == NULL) {
        printf("Error allocating handler thread stack\n");
        atmlab_close(socket);
        return;
    }
    struct k_thread *thread = k_object_alloc(K_OBJ_THREAD);
    if (thread == NULL) {
        printf("Error allocating handler thread object\n");
        k_thread_stack_free(stack);
        atmlab_close(socket);
        return;
    }

    // k_object_alloc does not zero the object, and arch_mem_domain_thread_add
    // reads arch.ptables before setting it: recycled memory looks like a thread
    // migrating out of a long-gone memory domain
    memset(thread, 0, sizeof(*thread));

    k_tid_t tid = k_thread_create(thread, stack,
            USER_STACKSIZE, connection_handler,
            socket, NULL, NULL, HANDLER_PRIORITY, K_USER, K_FOREVER);

    // A new thread inherits our memory domain, where every handler stack is
    // visible to every handler. Move it to its slot's own domain before it ever
    // runs: that remaps the stack out of the default domain and into this one,
    // so this connection's frame buffer is unreachable from the others.
    int error = k_mem_domain_add_thread(&thread_domains[slot], tid);
    if (error != 0) {
        printf("Error moving handler thread to its memory domain: %d\n", error);
        k_thread_abort(tid);
        k_thread_stack_free(stack);
        k_object_free(thread);
        atmlab_close(socket);
        return;
    }

    handlers[slot].thread = thread;
    handlers[slot].stack = stack;

    // give the thread access to the socket and start it
    k_object_access_grant(socket, thread);
    k_wakeup(tid);

    // the handler owns the connection from here on
    k_object_access_revoke(socket, k_current_get());
}

static void userspace_function(void *signal_socket, void *p2, void *p3)
{
    printf("Hello World from %s (%s)\n",
            k_is_user_context() ? "UserSpace!" : "privileged mode.",
            CONFIG_BOARD_TARGET);
    while (true) {
        struct k_container *svc_socket = atmlab_accept(signal_socket);
        if (svc_socket == NULL) {
            perror("accept");
        } else {
            spawn_handler_thread(svc_socket);
        }
    }
}


int userspace_main(void)
{
    struct k_container *signal_socket = atm_create_signal_socket(0, 5);
    if (signal_socket == NULL) {
        int err = errno;
        printk("Failed to create the signaling socket: %d\n", err);
        return -err;
    }

    // k_thread_create cannot fail here: the object and its stack are static and
    // a supervisor caller gets no argument validation
    k_tid_t tid = k_thread_create(&userspace_thread, userspace_stack,
            USER_STACKSIZE, userspace_function,
            signal_socket, NULL, NULL, HANDLER_PRIORITY, K_ESSENTIAL, K_FOREVER);
    k_object_access_grant(signal_socket, &userspace_thread);
    k_wakeup(tid);
    return 0;
}
