#include <zephyr/kernel.h>

#include "inet.h"

static inline uint16_t be16_get(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)((b[0] << 8) | b[1]);
}

static inline void be16_put(void *p, uint16_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)(v & 0xff);
}

/*
 * IPv4
 */

#define IPV4_VERSION_IHL        0x45
#define IPV4_VERSION            4
#define IPV4_IHL_NO_OPTIONS     5           /* header length in 32-bit words */
#define IPV4_HDR_LEN            20          /* IPV4_IHL_NO_OPTIONS * 4 */

#define IPV4_FLAG_RESERVED  0x8000  /* must be 0 */
#define IPV4_FLAG_DF        0x4000  /* don't fragment */
#define IPV4_FLAG_MF        0x2000  /* more fragments */
#define IPV4_FRAG_OFF_MASK  0x1fff

#define IPV4_PROTO_UDP      17

struct ipv4_hdr {
    uint8_t  ver_ihl;          /* IPV4_VER_IHL(4, 5) when there are no options */
    uint8_t  dscp_ecn;         /* 6-bit DSCP, 2-bit ECN */
    uint8_t  total_length[2];  /* be16, whole datagram: header + payload */
    uint8_t  identification[2];/* be16, for fragment reassembly */
    uint8_t  flags_frag_off[2];/* be16, see IPV4_FLAG_* / IPV4_FRAG_OFF_MASK */
    uint8_t  ttl;
    uint8_t  protocol;         /* IPV4_PROTO_* */
    uint8_t  checksum[2];      /* be16, header-only, ones' complement */
    uint8_t  src_addr[IPV4_ALEN];
    uint8_t  dst_addr[IPV4_ALEN];
} __packed;

/*
 * UDP
 */
struct udp_hdr {
    uint8_t  src_port[2];   /* be16 */
    uint8_t  dst_port[2];   /* be16 */
    uint8_t  length[2];     /* be16, UDP header + UDP payload (min 8) */
    uint8_t  checksum[2];   /* be16. 0 means "not computed" (IPv4 only) */
    uint8_t  payload[];
} __packed;

/*
 * combined header
 */
struct ipv4_udp {
    struct ipv4_hdr ipv4;
    struct udp_hdr  udp;
} __packed;

BUILD_ASSERT(sizeof(struct ipv4_udp) == IPV4_UDP_HDR_LEN);

static inline uint16_t inet_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;

    while (len > 1) {
        sum += be16_get(data);
        data += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += (uint32_t)data[0] << 8;    /* odd trailing byte, zero-padded */
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

int ipv4_parse(uint8_t *buffer, int len, uint8_t **saddr, uint8_t **daddr, uint16_t *sport, uint16_t *dport, uint8_t **payload)
{
    if (len < sizeof(struct ipv4_udp)) {
        return -EBADMSG;
    }

    struct ipv4_udp *frame = (struct ipv4_udp*)buffer;
    if(
        frame->ipv4.ver_ihl != IPV4_VERSION_IHL ||
        // ignore dscp and ecn
        // ignore identification
        // drop fragmented frames
        (be16_get(frame->ipv4.flags_frag_off) & (IPV4_FLAG_RESERVED | IPV4_FLAG_MF | IPV4_FRAG_OFF_MASK)) != 0 ||
        // ignore ttl
        frame->ipv4.protocol != IPV4_PROTO_UDP ||
        inet_checksum((uint8_t*)&frame->ipv4, IPV4_HDR_LEN) != 0
    ) {
        return -EBADMSG;
    }

    int ip_length = be16_get(frame->ipv4.total_length);
    if (ip_length != len) {
        return -EBADMSG;
    }
    int udp_length = be16_get(frame->udp.length);
    if (udp_length != len - sizeof(struct ipv4_hdr)) {
        return -EBADMSG;
    }

    *saddr = frame->ipv4.src_addr;
    *daddr = frame->ipv4.dst_addr;
    *sport = be16_get(frame->udp.src_port);
    *dport = be16_get(frame->udp.dst_port);
    *payload = frame->udp.payload;
    return udp_length - sizeof(struct udp_hdr);
}

int ipv4_build(uint8_t *buffer, int len, uint8_t *saddr, uint8_t *daddr, uint16_t sport, uint16_t dport, uint8_t *payload, int payload_len)
{
    if (len < payload_len + sizeof(struct ipv4_udp)) {
        return -ENOBUFS;
    }

    memset(buffer, 0, len);
    struct ipv4_udp *frame = (struct ipv4_udp*)buffer;

    frame->ipv4.ver_ihl = IPV4_VERSION_IHL;
    be16_put(frame->ipv4.total_length, payload_len + sizeof(struct ipv4_udp));
    be16_put(frame->ipv4.flags_frag_off, IPV4_FLAG_DF);
    frame->ipv4.ttl = 1;
    frame->ipv4.protocol = IPV4_PROTO_UDP;
    memcpy(frame->ipv4.src_addr, saddr, IPV4_ALEN);
    memcpy(frame->ipv4.dst_addr, daddr, IPV4_ALEN);
    be16_put(frame->ipv4.checksum, 0);
    be16_put(frame->ipv4.checksum, inet_checksum((uint8_t*)&frame->ipv4, IPV4_HDR_LEN));

    be16_put(frame->udp.src_port, sport);
    be16_put(frame->udp.dst_port, dport);
    be16_put(frame->udp.length, payload_len + sizeof(struct udp_hdr));
    memcpy(frame->udp.payload, payload, payload_len);

    return payload_len + sizeof(struct ipv4_udp);
}
