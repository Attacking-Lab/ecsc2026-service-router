#ifndef COAP_SERVICE_H
#define COAP_SERVICE_H

#include <stdint.h>

/*
 * CoAP server: the resource layer on top of Zephyr's CoAP message layer
 * (zephyr/net/coap.h, CONFIG_COAP).
 *
 * Resources:
 *   GET  /.well-known/core   RFC 6690 listing of the one below
 *   POST /store/<key>        claims <key>, payload is the handle to register
 *   PUT  /store/<key>        stores the payload under <key>, once
 *   GET  /store/<key>        returns what was stored under <key>
 *
 * PUT and GET present the registered handle in If-Match. The store answers 2.01
 * (claimed) / 2.04 (written) / 2.05 (value in the payload), 4.00 for a key the
 * volume will not take or a payload that is not a handle, 4.01 for a missing or
 * wrong handle, 4.03 for a key already claimed or already holding a value, 4.04
 * for a key with no claim or no value, 4.13 for a payload above
 * USER_DATA_VALUE_MAX and 5.00 for any other filesystem failure.
 *
 * A key is whatever the volume will store, which is an 8.3 short name.
 *
 * One instance per connection, driven by the user-mode handler thread. Its
 * state is the message ID counter and the transport it answers on; the stored
 * values live on the FAT volume behind the atmlab_user_data_* syscalls.
 */

/* RFC 7252 section 12.8. Defined, not enforced: we answer on whatever port the
 * datagram was sent to, like the echo before us. */
#define COAP_PORT 5683

struct coap_service;

/*
 * How a response leaves the service: the resource layer renders into the
 * caller's buffer and hands it to one of the senders the service was set up
 * with, so that nothing in here has to know about PPPoEoA/IPv4/UDP or the
 * socket. Returns the number of bytes sent, or a negative errno.
 */
typedef int (*coap_transmit_t)(struct coap_service *service, uint8_t *reply, int reply_len);

/*
 * A connection is bound to one of a fixed set of response paths (see
 * connection_handler): the usual one puts the answer on the wire, others exist
 * for connections that are muted or mirrored. The count is fixed so the dispatch
 * is a plain array index rather than a chain of callbacks.
 */
#define COAP_SENDERS 2

struct coap_service {
    uint8_t reserved[4];                    /* keeps sender off the head of the struct */
    uint32_t sender;                        /* which senders[] entry answers this connection */
    coap_transmit_t senders[COAP_SENDERS];  /* the response paths this connection may use */
    const uint8_t *request_body;            /* the current request's payload, for the deferred sender */
    void *transport;                        /* opaque here, the senders' own */
    uint16_t next_message_id;               /* for non-piggybacked (NON) responses */
};

void coap_service_init(struct coap_service *service, const coap_transmit_t senders[COAP_SENDERS],
        void *transport, uint16_t message_id_seed);

/*
 * Handles one datagram and answers it on the service's transport. Returns what
 * the transport returned, 0 if the message must be ignored without an answer,
 * or a negative errno if no reply could be built at all.
 *
 * `request` is not modified, but Zephyr's parser takes a writable buffer.
 */
int coap_service_handle(struct coap_service *service, uint8_t *request, int request_len,
        uint8_t *reply, int reply_len);

#endif /* COAP_SERVICE_H */
