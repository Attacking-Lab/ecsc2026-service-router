#include <zephyr/kernel.h>

#include <zephyr/logging/log.h>
#include <zephyr/internal/syscall_handler.h>
#include <zephyr/spinlock.h>
#include <zephyr/sys/slist.h>

#include "socket_atm.h"
#include "aal5.h"
#include "signaling.h"
#include "syscall_guard.h"
#include "syscalls/atmlab_syscall.h"
#include "zephyr/sys/internal/kobject_internal.h"
#include "zephyr/sys/kobject.h"

LOG_MODULE_REGISTER(socket_layer, CONFIG_ATM_LOG_LEVEL);

enum atm_ctx_state {
    ATM_CTX_IDLE = 0,
    ATM_CTX_LISTENING,
    ATM_CTX_CONNECTED,
    ATM_CTX_UNCONNECTED,
};

struct atm_ctx {
    enum atm_ctx_state state;
    sys_snode_t reap_node; /* see atm_ctx_destroy() */
    sys_dnode_t live_node; /* see atm_supervise() */
    /* the thread that reads this socket, recorded so the supervisor can abort
     * it; kept here rather than in userspace, where a handler could rewrite it */
    struct k_thread *handler;
    int64_t deadline;  /* uptime at which the call is released, 0 for never */
    int64_t abort_at;  /* uptime at which a lingering handler is aborted, 0 if not due */
    struct k_mutex lock;
    union {
        struct sig_state sig;
        struct {
            struct aal5_vc aal5;
            struct sig_state *parent;
        };
    };
};

/*
 * Deferred context teardown
 *
 * atm_ctx_destroy() runs inside the kernel's unref_check() with obj_lock held
 * and IRQs off (on thread abort additionally under _sched_spinlock), so it must
 * not block, allocate, log or free. It also cannot free right away: another
 * thread may still be inside aal5_close_vc() on this context's circuit.
 * So it only queues the context; the reaper thread does the rest.
 */
static struct k_spinlock reap_lock;
static sys_slist_t reap_list = SYS_SLIST_STATIC_INIT(&reap_list);
/* given by atmlab_close(); the abort path cannot signal, hence the poll */
static K_SEM_DEFINE(reap_sem, 0, 1);

/* Accepted circuits, for the supervisor. Only the reaper thread frees a
 * context, so it may hold one across an unlock. */
static struct k_spinlock live_lock;
static sys_dlist_t live_list = SYS_DLIST_STATIC_INIT(&live_list);

#if CONFIG_ATM_CIRCUIT_LIFETIME_SECONDS > 0
#define CIRCUIT_LIFETIME_MS \
    ((int64_t)CONFIG_ATM_CIRCUIT_LIFETIME_SECONDS * MSEC_PER_SEC)
#else
#define CIRCUIT_LIFETIME_MS 0
#endif

/* how many contexts one supervisor pass acts on, the rest wait for the next */
#define SUPERVISE_BATCH 8

/* moves the checked window along, so a long-lived call cannot hide the ones
 * behind it from the circuit check */
static size_t supervise_cursor;

/* how long a failed accept() is throttled for, see z_impl_atmlab_accept() */
#define ACCEPT_RETRY_MS 50

#define REAP_POLL_MS 100
#define REAP_PRIORITY 4 /* above the accept/handler threads */
#define REAP_STACKSIZE 2048

static void atm_ctx_destroy(struct k_container *obj)
{
    struct atm_ctx *ctx = (struct atm_ctx*)obj->obj;

    k_spinlock_key_t live_lock_key = k_spin_lock(&live_lock);
    if (sys_dnode_is_linked(&ctx->live_node)) {
        sys_dlist_remove(&ctx->live_node);
    }
    // A handler that got here on its own way out must not be aborted: this runs
    // before its thread object can be freed, so the supervisor either sees the
    // handler here or does not see it at all.
    ctx->handler = NULL;
    k_spin_unlock(&live_lock, live_lock_key);

    k_spinlock_key_t reap_lock_key = k_spin_lock(&reap_lock);
    sys_slist_prepend(&reap_list, &ctx->reap_node);
    k_spin_unlock(&reap_lock, reap_lock_key);

    // the kernel object is deleted by the kernel itself
}

/* Returns true once the context is freed (or deliberately leaked) */
static bool atm_ctx_reap(struct atm_ctx *ctx)
{
    switch (ctx->state) {
    case ATM_CTX_CONNECTED:
        // the handler died without closing; a no-op if the circuit is already gone
        sig_release(ctx->parent, &ctx->aal5);
        ctx->state = ATM_CTX_UNCONNECTED;
        __fallthrough;
    case ATM_CTX_UNCONNECTED:
    case ATM_CTX_IDLE:
        // another thread may still be tearing the circuit down (it found the
        // VC before we lost the last reference); retry on the next pass
        if (!atm_vc_is_closed(&ctx->aal5.atm)) {
            return false;
        }
        k_free(ctx);
        return true;
    case ATM_CTX_LISTENING:
    default:
        // the signaling socket is never released; leak rather than panic
        LOG_ERR("refusing to destroy the signaling socket");
        return true;
    }
}

/*
 * Releases calls that outlived their deadline, and aborts handlers that hold on
 * to a circuit that is already gone. A handler whose control flow was taken
 * over never returns to atmlab_read(), so nothing on the read path can reclaim
 * it: both are decided here, out of its reach.
 */
static void atm_supervise(void)
{
    struct atm_ctx *checking[SUPERVISE_BATCH];
    struct atm_ctx *releasing[SUPERVISE_BATCH];
    struct atm_ctx *aborting[SUPERVISE_BATCH];
    size_t check_count = 0, release_count = 0, abort_count = 0;
    size_t eligible = 0;
    int64_t now = k_uptime_get();

    k_spinlock_key_t key = k_spin_lock(&live_lock);
    struct atm_ctx *ctx;
    SYS_DLIST_FOR_EACH_CONTAINER(&live_list, ctx, live_node) {
        if (ctx->state != ATM_CTX_CONNECTED || ctx->handler == NULL) {
            continue;
        }
        if (ctx->abort_at != 0) {
            if (now >= ctx->abort_at && abort_count < SUPERVISE_BATCH) {
                aborting[abort_count++] = ctx;
            }
            continue;
        }
        if (ctx->deadline != 0 && now >= ctx->deadline) {
            // Give the handler the grace period to notice the release and exit
            // on its own, so a healthy one unwinds instead of being cut down
            // mid-syscall.
            ctx->abort_at = now + CONFIG_ATM_HANDLER_ABORT_GRACE_MS;
            if (release_count < SUPERVISE_BATCH) {
                releasing[release_count++] = ctx;
            }
            continue;
        }
        // Asking whether the circuit is still there takes the VC lock, which
        // must not nest inside this one, so it happens after the walk. Only a
        // window of contexts is queued per pass; the cursor moves it along and
        // the deadline catches whatever a pass misses.
        if (eligible++ >= supervise_cursor && check_count < SUPERVISE_BATCH) {
            checking[check_count++] = ctx;
        }
    }
    supervise_cursor = check_count < SUPERVISE_BATCH ? 0 : supervise_cursor + SUPERVISE_BATCH;
    k_spin_unlock(&live_lock, key);

    // Only this thread writes abort_at, and only this thread frees a context,
    // so the queued pointers stay good until we are done with them.
    for (size_t i = 0; i < check_count; ++i) {
        if (atm_vc_is_closed(&checking[i]->aal5.atm)) {
            LOG_DBG("handler outlived its circuit, giving it the grace period");
            checking[i]->abort_at = now + CONFIG_ATM_HANDLER_ABORT_GRACE_MS;
        }
    }
    // Before the releases below, which can block: the longer this waits, the
    // more room a handler has to exit and have its thread object freed.
    for (size_t i = 0; i < abort_count; ++i) {
        k_spinlock_key_t abort_key = k_spin_lock(&live_lock);
        struct k_thread *handler = aborting[i]->handler;
        aborting[i]->handler = NULL;
        k_spin_unlock(&live_lock, abort_key);
        if (handler == NULL) {
            continue; // it let go after all
        }
        // a handler inside a syscall may hold a lock; it aborts itself on the
        // way out instead, and handler is already cleared so this is the only
        // request
        if (syscall_guard_abort(handler)) {
            LOG_WRN("aborting a handler that did not let go of its circuit");
        } else {
            LOG_WRN("deferring the abort of a handler inside a syscall");
        }
    }
    for (size_t i = 0; i < release_count; ++i) {
        LOG_INF("releasing a circuit past its deadline");
        sig_release(releasing[i]->parent, &releasing[i]->aal5);
    }
}

static void atm_reaper_task(void)
{
    sys_slist_t pending;
    sys_slist_init(&pending);

    while (true) {
        (void)k_sem_take(&reap_sem, K_MSEC(REAP_POLL_MS));

        // before reaping: a context the supervisor still points at must not be
        // freed underneath it
        atm_supervise();

        k_spinlock_key_t reap_lock_key = k_spin_lock(&reap_lock);
        sys_slist_merge_slist(&pending, &reap_list);
        k_spin_unlock(&reap_lock, reap_lock_key);

        // pop before reaping: the node lives inside the context being freed
        sys_slist_t retry;
        sys_slist_init(&retry);
        sys_snode_t *node;
        while ((node = sys_slist_get(&pending)) != NULL) {
            struct atm_ctx *ctx = CONTAINER_OF(node, struct atm_ctx, reap_node);
            if (!atm_ctx_reap(ctx)) {
                sys_slist_append(&retry, node);
            }
        }
        sys_slist_merge_slist(&pending, &retry);
    }
}

K_THREAD_DEFINE(atm_reaper_thread, REAP_STACKSIZE, atm_reaper_task, NULL, NULL, NULL,
                REAP_PRIORITY, 0, 0);

struct k_container *atm_create_signal_socket(uint32_t vpi, uint32_t vci)
{
    int ret;
    struct k_container *container = k_object_alloc(K_OBJ_CONTAINER);
    if (container == NULL) {
        errno = ENOMEM;
        return 0;
    }

    struct atm_ctx *ctx = k_calloc(1, sizeof(struct atm_ctx));
	if (ctx == NULL) {
        k_object_free(container);
		errno = ENOMEM;
		return 0;
	}

    container->obj = ctx;
    container->destroy = atm_ctx_destroy;

    if ((ret = sig_init(&ctx->sig, vpi, vci)) != 0) {
        k_free(ctx);
        k_object_free(container);
        errno = -ret;
        return 0;
    }

    k_mutex_init(&ctx->lock);
    ctx->state = ATM_CTX_LISTENING;

    k_object_init(container);

    return container;
}

struct k_container *z_impl_atmlab_accept(struct k_container *obj)
{
    int ret;
    struct atm_ctx *ctx = (struct atm_ctx*)obj->obj;

    if (ctx->state != ATM_CTX_LISTENING) {
        errno = EINVAL;
        return 0;
    }

    struct k_container *container = k_object_alloc(K_OBJ_CONTAINER);
    if (container == NULL) {
        errno = ENOMEM;
        return 0;
    }

    struct atm_ctx *new_ctx = k_calloc(1, sizeof(struct atm_ctx));
    if (new_ctx == NULL) {
        k_object_free(container);
        errno = ENOMEM;
        return 0;
    }

    container->obj = new_ctx;
    container->destroy = atm_ctx_destroy;

    k_mutex_lock(&ctx->lock, K_FOREVER);

    if ((ret = sig_accept(&ctx->sig, &new_ctx->aal5)) != 0) {
        k_mutex_unlock(&ctx->lock);
        // sig_accept can fail after the circuit was opened; a no-op if it wasn't
        aal5_close_vc(&new_ctx->aal5);
        k_object_free(container);
        // no other thread can reference new_ctx yet (k_object_init not called)
        k_free(new_ctx);
        // A permanently failing signaling channel must not turn the accept loop
        // in userspace into a busy loop (it cannot sleep on its own).
        k_msleep(ACCEPT_RETRY_MS);
        errno = -ret;
        return 0;
    }

    k_mutex_init(&new_ctx->lock);
    new_ctx->state = ATM_CTX_CONNECTED;
    new_ctx->parent = &ctx->sig;
    if (CIRCUIT_LIFETIME_MS != 0) {
        new_ctx->deadline = k_uptime_get() + CIRCUIT_LIFETIME_MS;
    }

    k_spinlock_key_t live_lock_key = k_spin_lock(&live_lock);
    sys_dlist_append(&live_list, &new_ctx->live_node);
    k_spin_unlock(&live_lock, live_lock_key);

    k_mutex_unlock(&ctx->lock);

    k_object_init(container);

    return container;
}

struct k_container *z_vrfy_atmlab_accept(struct k_container *obj)
{
	K_OOPS(K_SYSCALL_OBJ(obj, K_OBJ_CONTAINER));
    syscall_guard_enter();
    struct k_container *ret = z_impl_atmlab_accept(obj);
    syscall_guard_exit();
    return ret;
}
#include <zephyr/syscalls/atmlab_accept_mrsh.c>

ssize_t z_impl_atmlab_read(struct k_container *obj, void *buffer, size_t count)
{
    struct atm_ctx *ctx = (struct atm_ctx*)obj->obj;

    // ctx->aal5 shares storage with ctx->sig, so a non-connection socket must
    // never reach the AAL5 layer here
    if (ctx->state != ATM_CTX_CONNECTED) {
        return -ENOTCONN;
    }

    k_mutex_lock(&ctx->lock, K_FOREVER);

    // whoever reads this socket is its handler, as far as the supervisor cares
    ctx->handler = k_current_get();

    int ret = aal5_rx(&ctx->aal5, buffer, &count, NULL);

    k_mutex_unlock(&ctx->lock);

    if (ret != 0) {
        return ret;
    }
    return count;
}

ssize_t z_vrfy_atmlab_read(struct k_container *obj, void *buffer, size_t count)
{
	K_OOPS(K_SYSCALL_OBJ(obj, K_OBJ_CONTAINER));
	K_OOPS(K_SYSCALL_VERIFY(count <= AAL5_MAX_SDU_SIZE));
	K_OOPS(K_SYSCALL_MEMORY_WRITE(buffer, count + sizeof(struct aal5_trailer)));
    syscall_guard_enter();
    ssize_t ret = z_impl_atmlab_read(obj, buffer, count);
    syscall_guard_exit();
    return ret;

}
#include <zephyr/syscalls/atmlab_read_mrsh.c>

ssize_t z_impl_atmlab_write(struct k_container *obj, const void *buffer, size_t count)
{
    struct atm_ctx *ctx = (struct atm_ctx*)obj->obj;

    // see z_impl_atmlab_read()
    if (ctx->state != ATM_CTX_CONNECTED) {
        return -ENOTCONN;
    }

    k_mutex_lock(&ctx->lock, K_FOREVER);

    int ret = aal5_tx(&ctx->aal5, buffer, count, false, false, 0);

    k_mutex_unlock(&ctx->lock);

    if (ret != 0) {
        return ret;
    }
    return count;
}

ssize_t z_vrfy_atmlab_write(struct k_container *obj, const void *buffer, size_t count)
{
	K_OOPS(K_SYSCALL_OBJ(obj, K_OBJ_CONTAINER));
	K_OOPS(K_SYSCALL_MEMORY_READ(buffer, count));
    syscall_guard_enter();
    ssize_t ret = z_impl_atmlab_write(obj, buffer, count);
    syscall_guard_exit();
    return ret;

}
#include <zephyr/syscalls/atmlab_write_mrsh.c>

int z_impl_atmlab_close(struct k_container *obj)
{
    int ret;
    struct atm_ctx *ctx = (struct atm_ctx*)obj->obj;

    if (ctx->state == ATM_CTX_CONNECTED) {
        // close remote connection only if connected
        k_mutex_lock(&ctx->lock, K_FOREVER);

        if ((ret = sig_release(ctx->parent, &ctx->aal5)) != 0) {
            k_mutex_unlock(&ctx->lock);
            errno = -ret;
            return -1;
        }
        ctx->state = ATM_CTX_UNCONNECTED;

        k_mutex_unlock(&ctx->lock);
    }

    if (ctx->state == ATM_CTX_UNCONNECTED) {
        // clear perms, this will automatically clean up the object if there are no other threads using it
        k_object_access_revoke(obj, _current);
        k_sem_give(&reap_sem);
    } else {
        // closing signaling channel is not supported
        errno = EBADF;
        return -1;
    }

    return 0;
}

int z_vrfy_atmlab_close(struct k_container *obj)
{
	K_OOPS(K_SYSCALL_OBJ(obj, K_OBJ_CONTAINER));
    syscall_guard_enter();
    int ret = z_impl_atmlab_close(obj);
    syscall_guard_exit();
    return ret;
}
#include <zephyr/syscalls/atmlab_close_mrsh.c>
