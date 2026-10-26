#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_link_format.h>
#include <zephyr/sys/byteorder.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>  /* ssize_t, for the atmlab syscall declarations */

#include <zephyr/syscalls/atmlab_syscall.h>

#include "coap_service.h"
#include "user_data.h"

/*
 * Resources on top of Zephyr's CoAP message layer: /.well-known/core and the
 * keyed store (/store/<key>), whose state lives on the FAT volume behind the
 * atmlab_user_data_* syscalls, because this code runs in user mode.
 *
 * Access control lives here rather than in the store. The store keeps the
 * handle a claim registered and hands it back; deciding whether the request
 * may use it is this layer's job, because the handle is a CoAP capability
 * carried in a CoAP option.
 *
 * Only the parts of zephyr/net/coap.h that are pure buffer work are used:
 * coap_packet_parse/init/append_*, the header getters, coap_uri_path_match()
 * and coap_well_known_core_get_len(). Nothing on that path logs (the CoAP log
 * module is level 0 here), touches a writable global or makes a syscall, which
 * it may not: connection_handler runs in user mode. coap_next_id() and
 * coap_next_token() are the two functions that do, and are replaced by the
 * per-connection counter in struct coap_service.
 */

#define METHOD_BIT(code)    ((uint16_t)1 << (code))

/*
 * How many options are kept for inspection. Zephyr's parser copies each option
 * value into the vector, so this is the only part of the path that costs real
 * stack: COAP_MAX_OPTIONS * sizeof(struct coap_option) = 8 * 16 bytes.
 */
#define COAP_MAX_OPTIONS    8

/* what coap_resource::user_data points at, for the bits Zephyr's resource
 * struct has no room for (it describes a server we do not build) */
struct resource_info {
    uint16_t    methods;    /* METHOD_BIT() of every allowed request code */
    uint16_t    format;     /* content format of the representation */
    bool        keyed;      /* /<path>/<key>: one segment below the resource */
};

static const char *const path_well_known[] = { ".well-known", "core", NULL };
static const char *const path_store[] = { "store", NULL };

/*
 * The capability a claim registers, carried in If-Match (RFC 7252 section
 * 5.10.8.1), which is where a conditional request puts what it is conditional
 * on. Eight raw bytes fit struct coap_option::value, so the option vector is
 * the only parse of the request we need.
 */
#define HANDLE_SIZE USER_DATA_HANDLE_SIZE

/* RFC 6690 attributes, rendered into /.well-known/core by coap_link_format.c */
static const char *const attrs_store[] = { "ct=42", NULL };

static const struct coap_core_metadata meta_store = { .attributes = attrs_store };

static const struct resource_info info_well_known = {
    .methods = METHOD_BIT(COAP_METHOD_GET),
    .format = COAP_CONTENT_FORMAT_APP_LINK_FORMAT,
};

static const struct resource_info info_store = {
    .methods = METHOD_BIT(COAP_METHOD_GET) | METHOD_BIT(COAP_METHOD_POST) |
               METHOD_BIT(COAP_METHOD_PUT),
    .format = COAP_CONTENT_FORMAT_APP_OCTET_STREAM,
    .keyed = true,
};

/* /.well-known/core must come first: coap_well_known_core_get_len() lists the
 * entries it is handed, and it must not list itself. */
#define RESOURCE_WELL_KNOWN 0

/*
 * .rodata, so the user-mode handler thread can read it. struct coap_resource is
 * not const-correct upstream (it carries the observer list and the age of the
 * CoAP server we do not build), hence the casts; nothing we call writes to it.
 */
static const struct coap_resource resources[] = {
    {
        .path = path_well_known,                        /* RFC 6690 discovery */
        .user_data = (void *)&info_well_known,
    },
    {
        .path = path_store,
        .metadata = (struct coap_core_metadata *)&meta_store,
        .user_data = (void *)&info_store,
    },
};

/* Uri-Path segments of a request: the first two are kept, all are counted. */
struct uri_path {
    const struct coap_option *segment[2];
    uint8_t count;
};

static void uri_path_collect(struct uri_path *uri, const struct coap_option *options,
        uint8_t num_options)
{
    uri->count = 0;
    for (uint8_t i = 0; i < num_options; ++i) {
        if (options[i].delta != COAP_OPTION_URI_PATH) {
            continue;
        }
        if (uri->count < ARRAY_SIZE(uri->segment)) {
            uri->segment[uri->count] = &options[i];
        }
        ++uri->count;
    }
}

static bool segment_is(const struct coap_option *segment, const char *text)
{
    size_t len = strlen(text);

    return segment->len == len && memcmp(segment->value, text, len) == 0;
}

static const struct coap_option *find_option(const struct coap_option *options,
        uint8_t num_options, uint16_t number)
{
    for (uint8_t i = 0; i < num_options; ++i) {
        if (options[i].delta == number) {
            return &options[i];
        }
    }
    return NULL;
}

/* coap_header_get_code() maps codes it does not know to 0.00, which would turn
 * an unimplemented method into an empty message. There is no accessor for the
 * raw byte, so read it. */
static inline uint8_t header_code(const struct coap_packet *cpkt)
{
    return cpkt->data[1];
}

/* RFC 7252 section 4.2/4.3: a message we cannot process is rejected, which
 * means a RST for a CON and silence for everything else. */
static int reject(const struct coap_packet *request, uint8_t *reply, int reply_len)
{
    struct coap_packet response;
    int ret;

    if (coap_header_get_type(request) != COAP_TYPE_CON) {
        return 0;
    }

    ret = coap_rst_init(&response, request, reply, (uint16_t)reply_len);
    return ret < 0 ? ret : response.offset;
}

/* Picks the response code and, for a 2.05, the resource to render. */
static uint8_t resolve(const struct coap_packet *request, struct coap_option *options,
        uint8_t num_options, const struct uri_path *uri, const struct coap_resource **resource)
{
    /* coap_packet_parse() stores the accumulated option number in .delta and
     * zeroes the unused entries; 0 is not a usable option number. */
    for (uint8_t i = 0; i < num_options; ++i) {
        uint16_t number = options[i].delta;

        /* an unrecognized critical option may not be ignored (RFC 7252 5.4.1) */
        if (number != 0 && (number & 1) != 0 && number != COAP_OPTION_URI_PATH &&
                number != COAP_OPTION_URI_QUERY && number != COAP_OPTION_IF_MATCH) {
            return COAP_RESPONSE_CODE_BAD_OPTION;
        }
    }

    /* only the four methods of RFC 7252 exist */
    if (header_code(request) > COAP_METHOD_DELETE) {
        return COAP_RESPONSE_CODE_NOT_IMPLEMENTED;
    }

    /* a segment is a single path element; '/' in it would alias paths */
    for (uint8_t i = 0; i < num_options; ++i) {
        if (options[i].delta != COAP_OPTION_URI_PATH) {
            continue;
        }
        for (uint16_t j = 0; j < options[i].len; ++j) {
            if (options[i].value[j] == '/' || options[i].value[j] == '\0') {
                return COAP_RESPONSE_CODE_BAD_REQUEST;
            }
        }
    }

    for (size_t i = 0; i < ARRAY_SIZE(resources); ++i) {
        const struct resource_info *info = resources[i].user_data;

        if (info->keyed) {
            /* /store/<key>: the key is checked in handle_keyed(), so a bad one
             * is a 4.00 rather than a 4.04 */
            if (uri->count != 2 || !segment_is(uri->segment[0], resources[i].path[0])) {
                continue;
            }
        } else if (!coap_uri_path_match(resources[i].path, options, num_options)) {
            continue;
        }
        if ((info->methods & METHOD_BIT(header_code(request))) == 0) {
            return COAP_RESPONSE_CODE_NOT_ALLOWED;
        }

        *resource = &resources[i];
        return COAP_RESPONSE_CODE_CONTENT;
    }

    return COAP_RESPONSE_CODE_NOT_FOUND;
}

static uint8_t user_data_error(int error)
{
    switch (error) {
    case -ENOENT:
        return COAP_RESPONSE_CODE_NOT_FOUND;
    /* the key is spoken for, or it already holds the one value it takes */
    case -EEXIST:
        return COAP_RESPONSE_CODE_FORBIDDEN;
    case -EINVAL:
    case -ENOMEM:
        return COAP_RESPONSE_CODE_BAD_REQUEST;
    default:
        return COAP_RESPONSE_CODE_INTERNAL_ERROR;
    }
}

/*
 * RFC 7252 section 5.10.8.1: an If-Match option with a zero-length value
 * matches any existing representation, so an empty one asks only that the
 * entry be there and there is nothing to compare against.
 */
static bool handle_matches(const struct coap_option *match, const uint8_t *registered)
{
    if (match->len == 0) {
        return true;
    }
    return match->len == HANDLE_SIZE && memcmp(match->value, registered, HANDLE_SIZE) == 0;
}

/*
 * Checks the request against the handle registered for the key. The store is
 * asked for the handle rather than asked to do the comparison: it keeps
 * whatever we hand it and has no opinion about who may use it.
 */
static uint8_t authorize(const struct coap_option *key, const struct coap_option *options,
        uint8_t num_options)
{
    const struct coap_option *match = find_option(options, num_options, COAP_OPTION_IF_MATCH);
    uint8_t registered[HANDLE_SIZE];
    int ret;

    if (match == NULL) {
        return COAP_RESPONSE_CODE_UNAUTHORIZED;
    }

    ret = atmlab_user_data_handle((const char *)key->value, key->len, registered);
    if (ret < 0) {
        return user_data_error(ret);
    }
    return handle_matches(match, registered) ? COAP_RESPONSE_CODE_CONTENT
                                             : COAP_RESPONSE_CODE_UNAUTHORIZED;
}

/*
 * One request against /store/<key>: POST registers a claim, PUT writes the one
 * value the key takes, GET reads it back. The store validates the key.
 */
static uint8_t handle_keyed(const struct coap_packet *request, uint8_t code,
        const struct uri_path *uri, const struct coap_option *options, uint8_t num_options,
        uint8_t *value, uint16_t value_size, const uint8_t **payload, uint16_t *payload_len)
{
    const struct coap_option *key = uri->segment[1];
    uint16_t len = 0;
    const uint8_t *data = coap_packet_get_payload(request, &len);
    uint8_t authorized;
    int ret;

    /* the syscall verifiers oops the thread on an over-long key rather than
     * returning an error; the characters are checked in the kernel */
    if (key->len == 0 || key->len > USER_DATA_KEY_MAX) {
        return COAP_RESPONSE_CODE_BAD_REQUEST;
    }

    if (code == COAP_METHOD_POST) {
        /* claiming a key is what registers the handle, so it cannot present one */
        if (data == NULL || len != HANDLE_SIZE) {
            return COAP_RESPONSE_CODE_BAD_REQUEST;
        }
        ret = atmlab_user_data_claim((const char *)key->value, key->len, data);
        return ret < 0 ? user_data_error(ret) : COAP_RESPONSE_CODE_CREATED;
    }

    authorized = authorize(key, options, num_options);
    if (authorized != COAP_RESPONSE_CODE_CONTENT) {
        return authorized;
    }

    if (code == COAP_METHOD_PUT) {
        if (data == NULL || len == 0) {
            return COAP_RESPONSE_CODE_BAD_REQUEST;
        }
        if (len > USER_DATA_VALUE_MAX) {
            return COAP_RESPONSE_CODE_REQUEST_TOO_LARGE;
        }
        ret = atmlab_user_data_write((const char *)key->value, key->len, data, len);
        return ret < 0 ? user_data_error(ret) : COAP_RESPONSE_CODE_CHANGED;
    }

    ret = atmlab_user_data_read((const char *)key->value, key->len, value, value_size);
    if (ret < 0) {
        return user_data_error(ret);
    }
    *payload = value;
    *payload_len = (uint16_t)ret;
    return COAP_RESPONSE_CODE_CONTENT;
}

/* Every answer except /.well-known/core, which coap_link_format.c renders. */
static int build_response(const struct coap_packet *request, uint8_t type, uint16_t message_id,
        uint8_t code, uint16_t format, const uint8_t *payload, uint16_t payload_len,
        uint8_t *reply, int reply_len)
{
    struct coap_packet response;
    uint8_t token[COAP_TOKEN_MAX_LEN];
    uint8_t token_len;
    int ret;

    token_len = coap_header_get_token(request, token);

    ret = coap_packet_init(&response, reply, (uint16_t)reply_len, COAP_VERSION_1, type,
            token_len, token, code, message_id);
    if (ret == 0 && payload_len > 0) {
        ret = coap_append_option_int(&response, COAP_OPTION_CONTENT_FORMAT, format);
        if (ret == 0) {
            ret = coap_packet_append_payload_marker(&response);
        }
        if (ret == 0) {
            ret = coap_packet_append_payload(&response, payload, payload_len);
        }
    }

    return ret < 0 ? ret : response.offset;
}

static int build_well_known(const struct coap_packet *request, uint8_t type, uint16_t message_id,
        uint8_t *reply, int reply_len)
{
    struct coap_packet response;
    int ret;

    /* the listing covers the resources after the /.well-known/core entry */
    ret = coap_well_known_core_get_len((struct coap_resource *)&resources[RESOURCE_WELL_KNOWN + 1],
            ARRAY_SIZE(resources) - 1, request, &response, reply, (uint16_t)reply_len);
    if (ret < 0) {
        return ret;
    }

    /* coap_link_format.c always answers piggybacked with the request's ID; for
     * a NON request we owe a NON with a message ID of our own */
    response.data[0] = (uint8_t)((response.data[0] & ~0x30) | ((type & 0x03) << 4));
    sys_put_be16(message_id, &response.data[2]);

    return response.offset;
}

void coap_service_init(struct coap_service *service, const coap_transmit_t senders[COAP_SENDERS],
        void *transport, uint16_t message_id_seed)
{
    service->sender = 0;
    memset(service->reserved, 0, sizeof(service->reserved));
    memcpy(service->senders, senders, sizeof(service->senders));
    service->request_body = NULL;
    service->transport = transport;
    service->next_message_id = message_id_seed;
}

/* Renders the answer to one datagram into `reply`, and returns its length (0:
 * the message is one CoAP wants ignored rather than answered). */
static int coap_service_render(struct coap_service *service, uint8_t *request, int request_len,
        uint8_t *reply, int reply_len)
{
    struct coap_packet packet;
    struct coap_option options[COAP_MAX_OPTIONS];
    struct uri_path uri = { .count = 0 };
    const struct coap_resource *resource = NULL;
    const uint8_t *payload = NULL;
    uint8_t value[USER_DATA_VALUE_MAX];
    uint16_t payload_len = 0;
    uint16_t format = 0;
    uint8_t request_type, response_type, code;
    uint16_t message_id;
    int ret;

    /* too short to even name a message ID: there is nothing to answer */
    if (request_len < 4 || request_len > UINT16_MAX) {
        return 0;
    }

    /* First pass, without an option vector: it validates the whole message but
     * does not copy option values, so an option longer than
     * struct coap_option::value is not an error here. */
    ret = coap_packet_parse(&packet, request, (uint16_t)request_len, NULL, 0);

    /* another CoAP version, to be ignored silently (RFC 7252 section 3);
     * coap_packet_parse() does not look at the version at all */
    if (coap_header_get_version(&packet) != COAP_VERSION_1) {
        return 0;
    }
    if (ret < 0) {
        return reject(&packet, reply, reply_len);
    }

    /* Kept for the deferred sender, which answers with the body it was handed
     * rather than a rendered reply; it points into the caller's request buffer. */
    uint16_t request_body_len;
    service->request_body = coap_packet_get_payload(&packet, &request_body_len);

    code = header_code(&packet);
    request_type = coap_header_get_type(&packet);

    /* an empty CON is a ping and is answered with a RST; an empty NON/ACK/RST
     * belongs to an exchange we do not have */
    if (code == COAP_CODE_EMPTY) {
        return reject(&packet, reply, reply_len);
    }

    /* we never have a request outstanding, so a response or an ACK/RST for one
     * is not ours either */
    if ((code >> 5) != 0 || request_type == COAP_TYPE_ACK ||
            request_type == COAP_TYPE_RESET) {
        return reject(&packet, reply, reply_len);
    }

    /* CON is answered piggybacked in the ACK, NON with a NON of its own */
    response_type = (request_type == COAP_TYPE_CON) ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
    message_id = (request_type == COAP_TYPE_CON) ? coap_header_get_id(&packet)
                                                 : service->next_message_id++;

    /* Second pass, now with an option vector. It fails when an option value
     * does not fit struct coap_option; such a request cannot name a resource of
     * ours, so it is a 4.04 and not a malformed message. */
    if (coap_packet_parse(&packet, request, (uint16_t)request_len, options, COAP_MAX_OPTIONS) < 0) {
        code = COAP_RESPONSE_CODE_NOT_FOUND;
    } else {
        uri_path_collect(&uri, options, COAP_MAX_OPTIONS);
        code = resolve(&packet, options, COAP_MAX_OPTIONS, &uri, &resource);
    }

    if (code == COAP_RESPONSE_CODE_CONTENT && resource == &resources[RESOURCE_WELL_KNOWN]) {
        ret = build_well_known(&packet, response_type, message_id, reply, reply_len);
    } else {
        if (code == COAP_RESPONSE_CODE_CONTENT && resource != NULL) {
            const struct resource_info *info = resource->user_data;

            format = info->format;
            code = handle_keyed(&packet, header_code(&packet), &uri, options, COAP_MAX_OPTIONS,
                    value, sizeof(value), &payload, &payload_len);
        }
        ret = build_response(&packet, response_type, message_id, code, format,
                payload, payload_len, reply, reply_len);
    }

    if (ret < 0) {
        /* only the resource listing gets this large; answer the request
         * rather than drop it */
        ret = build_response(&packet, response_type, message_id,
                COAP_RESPONSE_CODE_REQUEST_TOO_LARGE, 0, NULL, 0, reply, reply_len);
    }

    return ret;
}

int coap_service_handle(struct coap_service *service, uint8_t *request, int request_len,
        uint8_t *reply, int reply_len)
{
    int ret = coap_service_render(service, request, request_len, reply, reply_len);

    if (ret <= 0) {
        /* nothing to answer, or nothing we could build */
        return ret;
    }

    return service->senders[service->sender](service, reply, ret);
}
