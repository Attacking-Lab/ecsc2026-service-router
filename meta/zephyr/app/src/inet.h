#ifndef INET_H
#define INET_H

#include <stdint.h>

#define IPV4_ALEN           4

/* what ipv4_build() puts in front of the payload */
#define IPV4_UDP_HDR_LEN    28

int ipv4_parse(uint8_t *buffer, int len, uint8_t **saddr, uint8_t **daddr, uint16_t *sport, uint16_t *dport, uint8_t **payload);
int ipv4_build(uint8_t *buffer, int len, uint8_t *saddr, uint8_t *daddr, uint16_t sport, uint16_t dport, uint8_t *payload, int payload_len);

#endif /* INET_H */
