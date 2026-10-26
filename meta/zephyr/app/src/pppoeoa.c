#include <zephyr/kernel.h>

#include "pppoeoa.h"

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
 * RFC 2684 bridged encapsulation
 */

#define LLC_DSAP_SNAP       0xAA
#define LLC_SSAP_SNAP       0xAA
#define LLC_CTRL_UI         0x03    /* unnumbered information */

#define SNAP_OUI_8021       { 0x00, 0x80, 0xC2 }   /* IEEE 802.1 bridging */

#define BRIDGED_PID_ETH_FCS     0x0001  /* Ethernet/802.3, LAN FCS preserved */
#define BRIDGED_PID_ETH_NOFCS   0x0007  /* Ethernet/802.3, FCS stripped  <-- usual */

/* LLC/SNAP flavour: 10 bytes ahead of the MAC header. */
struct rfc2684_bridged_llc {
    uint8_t  dsap;          /* 0xAA */
    uint8_t  ssap;          /* 0xAA */
    uint8_t  ctrl;          /* 0x03 */
    uint8_t  oui[3];        /* 00 80 C2 */
    uint8_t  pid[2];        /* 0x0007 (be16) */
    uint8_t  pad[2];        /* 00 00 -- aligns dst MAC to 4-byte boundary */
} __packed;

/*
 * Ethernet
 */

#define ETHERTYPE_PPPOE_SESS    0x8864

struct eth_hdr {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint8_t  ethertype[2];  /* be16 */
} __packed;

/*
 * PPPoE (RFC 2516)
 */

#define PPPOE_VER           0x1
#define PPPOE_TYPE          0x1
#define PPPOE_VER_TYPE      0x11    // default

// only session supported
#define PPPOE_CODE_SESSION  0x00

struct pppoe_hdr {
    uint8_t  ver_type;      /* PPPOE_VER_TYPE */
    uint8_t  code;          /* PPPOE_CODE_* */
    uint8_t  session_id[2]; /* be16 */
    uint8_t  length[2];     /* be16, payload only -- excludes these 6 bytes */
} __packed;

/*
 * PPP
 */

struct ppp_hdr {
    uint8_t  protocol[2];   /* be16, PPP_PROTO_* */
    uint8_t  payload[];
} __packed;

#define PPP_PROTO_IPV4      0x0021
#define PPP_PROTO_IPV6      0x0057

/*
 * Whole-stack view
 */

struct pppoeoa_llc_frame {
    struct rfc2684_bridged_llc  llc;
    struct eth_hdr              eth;
    struct pppoe_hdr            pppoe;
    struct ppp_hdr              ppp;
} __packed;

BUILD_ASSERT(sizeof(struct pppoeoa_llc_frame) == PPPOEOA_HDR_LEN);


int pppoeoa_parse(uint8_t *buffer, ssize_t len, uint8_t **smac, uint8_t **dmac, uint16_t *session_id, uint8_t **payload)
{
    static const uint8_t oui[3] = SNAP_OUI_8021;

    if (len < sizeof(struct pppoeoa_llc_frame)) {
        return -EBADMSG;
    }

    struct pppoeoa_llc_frame *frame = (struct pppoeoa_llc_frame*)buffer;
    if (
        frame->llc.dsap != LLC_DSAP_SNAP ||
        frame->llc.ssap != LLC_SSAP_SNAP ||
        frame->llc.ctrl != LLC_CTRL_UI ||
        memcmp(frame->llc.oui, oui, sizeof(oui)) != 0 ||
        be16_get(frame->llc.pid) != BRIDGED_PID_ETH_NOFCS ||
        be16_get(frame->eth.ethertype) != ETHERTYPE_PPPOE_SESS ||
        frame->pppoe.ver_type != PPPOE_VER_TYPE ||
        frame->pppoe.code != PPPOE_CODE_SESSION ||
        be16_get(frame->ppp.protocol) != PPP_PROTO_IPV4
    ) {
        return -EBADMSG;
    }

    int length = be16_get(frame->pppoe.length);
    if (length < sizeof(struct ppp_hdr) || length > len - offsetof(struct pppoeoa_llc_frame, ppp)) {
        return -EBADMSG;
    }

    *smac = frame->eth.src;
    *dmac = frame->eth.dst;
    *session_id = be16_get(frame->pppoe.session_id);
    *payload = frame->ppp.payload;
    return length - sizeof(struct ppp_hdr);
}

int pppoeoa_build(uint8_t *buffer, ssize_t len, uint8_t *smac, uint8_t *dmac, uint16_t session_id, uint8_t *payload, ssize_t payload_len)
{
    static const uint8_t oui[3] = SNAP_OUI_8021;

    if (len < payload_len + sizeof(struct pppoeoa_llc_frame)) {
        return -ENOBUFS;
    }

    memset(buffer, 0, len);
    struct pppoeoa_llc_frame *frame = (struct pppoeoa_llc_frame*)buffer;

    frame->llc.dsap = LLC_DSAP_SNAP;
    frame->llc.ssap = LLC_SSAP_SNAP;
    frame->llc.ctrl = LLC_CTRL_UI;
    memcpy(frame->llc.oui, oui, sizeof(oui));
    be16_put(frame->llc.pid, BRIDGED_PID_ETH_NOFCS);

    memcpy(frame->eth.dst, dmac, ETH_ALEN);
    memcpy(frame->eth.src, smac, ETH_ALEN);
    be16_put(frame->eth.ethertype, ETHERTYPE_PPPOE_SESS);

    frame->pppoe.ver_type = PPPOE_VER_TYPE;
    frame->pppoe.code = PPPOE_CODE_SESSION;
    be16_put(frame->pppoe.session_id, session_id);
    be16_put(frame->pppoe.length, payload_len + sizeof(struct ppp_hdr));

    be16_put(frame->ppp.protocol, PPP_PROTO_IPV4);
    memcpy(frame->ppp.payload, payload, payload_len);
    return payload_len + sizeof(struct pppoeoa_llc_frame);
}
