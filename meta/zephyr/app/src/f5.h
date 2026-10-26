#ifndef F5_H_
#define F5_H_

#include <stdint.h>

#include "atm.h"

#define OAM_PAYLOAD_SIZE (ATM_SDU_SIZE - 1 /* header */ - 2 /* trailer with EDC */)
_Static_assert(OAM_PAYLOAD_SIZE == 45, "OAM cell payload size ('function specific field') should be 45 bytes, per I.610");


/*
 * F5 flag store internals:
 *  - PUT(data)      => (id, key)                             stores id -> (key, ct = enc(data, key))
 *  - GET(id, nonce) => (ct, mac(dec(ct, key) || nonce, key))
 *
 * Bugs:
 *  - A buffer overflow in retrieval allows leaking keys
 *  - The key generation is weak.
 */
enum f5_function {
    F5_OP_PUT = 0,
    F5_OP_GET = 1,
    F5_OP_RESPONSE_BIT = 8,
};

typedef uint8_t f5_id_t[4];
typedef uint8_t f5_data_t[38]; /* exactly the length of a flag, how convenient */
typedef uint8_t f5_mac_t[7]; /* must fit into a cell with the data */
typedef uint8_t f5_key_t[16];

struct f5_put_request {
    f5_data_t data;
    char      reserved[OAM_PAYLOAD_SIZE - sizeof(f5_data_t)];
};

struct f5_put_response {
    f5_id_t  id;
    f5_key_t key;
    char     reserved[OAM_PAYLOAD_SIZE - sizeof(f5_id_t) - sizeof(f5_key_t)];
};

struct f5_get_request {
    f5_id_t    id;
    uint8_t    nonce_length;
    uint8_t    nonce[OAM_PAYLOAD_SIZE - sizeof(f5_id_t) - sizeof(uint8_t)];
};

struct f5_get_response {
    f5_data_t  ct;
    f5_mac_t   mac;
};

_Static_assert(sizeof(struct f5_put_request)  == OAM_PAYLOAD_SIZE, "put request too large for OAM cell");
_Static_assert(sizeof(struct f5_put_response) == OAM_PAYLOAD_SIZE, "put response too large for OAM cell");
_Static_assert(sizeof(struct f5_get_request)  == OAM_PAYLOAD_SIZE, "get request too large for OAM cell");
_Static_assert(sizeof(struct f5_get_response) == OAM_PAYLOAD_SIZE, "get response too large for OAM cell");


/* Storage management */

#define F5_MAX_GENERATION_ID     0x7fff
#define F5_INVALID_GENERATION_ID (F5_MAX_GENERATION_ID + 1)
#define F5_GEN_ID(gen)           ((gen) & F5_MAX_GENERATION_ID)
#define F5_GEN_FILEID(gen)       (F5_GEN_ID(gen) & (CONFIG_OAM_LIVE_GENERATIONS - 1))
#define F5_GEN_SLOTID(slot)      ((slot) & (CONFIG_OAM_SLOTS_PER_GENERATION - 1))

_Static_assert((CONFIG_OAM_SLOTS_PER_GENERATION & (CONFIG_OAM_SLOTS_PER_GENERATION - 1)) == 0, "CONFIG_OAM_SLOTS_PER_GENERATION must be a power of two");
_Static_assert(CONFIG_OAM_SLOTS_PER_GENERATION <= ((uint64_t) 1u << (sizeof(f5_id_t) * 8 - 16)), "Too many slots for f5_id_t");
_Static_assert((CONFIG_OAM_LIVE_GENERATIONS & (CONFIG_OAM_LIVE_GENERATIONS - 1)) == 0, "CONFIG_OAM_LIVE_GENERATIONS must be a power of two");
_Static_assert(CONFIG_OAM_LIVE_GENERATIONS <= F5_MAX_GENERATION_ID + 1, "Too many live generations");

typedef enum {
    F5CS_NULL,
    F5CS_AES128CTR_CMAC,
    F5CS_COUNT,
} f5_suite_t;

struct f5_record {
    uint16_t suite;
    uint8_t  payload[sizeof(f5_key_t) + sizeof(f5_data_t)];
};

_Static_assert(F5CS_COUNT <= (1ul << (sizeof(((struct f5_record *) NULL)->suite) * 8)), "f5_record::suite is too small");
_Static_assert(sizeof(struct f5_record) <= CONFIG_OAM_RECORD_SIZE, "Configured record size is too small");

void f5_rx(struct atm_vc *vc, uint8_t sdu[static ATM_SDU_SIZE], bool loss_priority, enum atm_pti pti);

#endif 
