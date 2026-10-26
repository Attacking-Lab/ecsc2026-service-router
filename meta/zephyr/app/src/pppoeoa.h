#ifndef PPPOEOA_H
#define PPPOEOA_H

#include <stdint.h>
#include <sys/types.h>

#define ETH_ALEN            6

/* what pppoeoa_build() puts in front of the payload */
#define PPPOEOA_HDR_LEN     32

int pppoeoa_parse(uint8_t *buffer, ssize_t len, uint8_t **smac, uint8_t **dmac, uint16_t *session_id, uint8_t **payload);
int pppoeoa_build(uint8_t *buffer, ssize_t len, uint8_t *smac, uint8_t *dmac, uint16_t session_id, uint8_t *payload, ssize_t payload_len);

#endif /* PPPOEOA_H */
