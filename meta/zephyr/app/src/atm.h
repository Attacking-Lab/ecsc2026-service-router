#ifndef ATM_H_
#define ATM_H_

#include <zephyr/kernel.h>

#include <zephyr/sys/slist.h>

#define ATM_CELL_SIZE 53
#define ATM_QUEUE_SIZE 100

/*
 * The UNI cell header carries 8 bits of VPI and 16 bits of VCI.
 * VCI 0..31 are reserved (0..15 by the ITU-T, 16..31 by the ATM Forum)
 * and are never used for a call.
 */
#define ATM_MAX_VPI 0xffU
#define ATM_MAX_VCI 0xffffU
#define ATM_MIN_CALL_VCI 32U

struct atm_cell_buffer;
struct atm_vc;
enum atm_pti;

/*
 * Callback that is called for every data cell that is received on the circuit
 *
 * Ref: I.361 3.1 ATM-DATA indication
 */
typedef void(atm_data_cb)(struct atm_vc* vc, uint8_t* sdu, bool loss_priority, bool congestion_indication, uint32_t auu);

/*
 * Callback that is called for every mgmt cell that is received on the circuit
 *
 * This is for use with F5
 */
// TODO: where to set this?
typedef void(atm_mgmt_cb)(struct atm_vc* vc, uint8_t* sdu, bool loss_priority, enum atm_pti pti);

/*
 * Teardown state of a virtual circuit, protected by the VC list lock.
 * A VC is in the list exactly while it is ATM_VC_OPEN.
 */
enum atm_vc_state {
    ATM_VC_CLOSED = 0,  /* never opened or fully torn down: may be freed */
    ATM_VC_OPEN,        /* in the VC list */
    ATM_VC_CLOSING,     /* unlinked, teardown in progress: must not be freed */
};

/*
 * Virtual Circuit struct
 */
struct atm_vc {
	sys_snode_t _node;
    uint32_t vpi : 12;
    uint32_t vci : 16;
    bool is_svc;
    atm_mgmt_cb *mgmt_cb;
    atm_data_cb *data_cb;
    struct k_mutex lock;
    uint8_t _state; /* enum atm_vc_state */
};

/*
 * Payload type identifier for an ATM cell
 */
enum atm_pti {
    PtiUserDataCell0 = 0b000,
    PtiUserDataCell1 = 0b001,
    PtiUserDataCellCongested0 = 0b010,
    PtiUserDataCellCongested1 = 0b011,
    PtiSegmentOamF5Cell = 0b100,
    PtiEndToEndOamF5Cell = 0b101,
    PtiResourceManagementCell = 0b110,
    PtiReserved = 0b111,
} __packed;

/*
 * ATM header utilities
 */

#define ATM_HEADER_SIZE 5

__always_inline static uint8_t atm_hdr_get_gfc(const uint8_t *cell)
{
    return cell[0] >> 4;
}
__always_inline static void atm_hdr_set_gfc(uint8_t *cell, uint8_t gfc)
{
    cell[0] = (cell[0] & 0xf) | (gfc << 4);
}

__always_inline static uint8_t atm_hdr_get_vpi(const uint8_t *cell)
{
    return (cell[0] << 4) | (cell[1] >> 4);
}

__always_inline static void atm_hdr_set_vpi(uint8_t *cell, uint8_t vpi)
{
    cell[0] = (cell[0] & 0xf0) | (vpi >> 4);
    cell[1] = (cell[1] & 0x0f) | (vpi << 4);
}

__always_inline static uint16_t atm_hdr_get_vci(const uint8_t *cell)
{
    return (((uint16_t) (cell[1] & 0xf)) << 12) |
           (((uint16_t) cell[2]) << 4) |
           (((uint16_t) cell[3]) >> 4);
}

__always_inline static void atm_hdr_set_vci(uint8_t *cell, uint16_t vci)
{
    cell[1] = (cell[1] & 0xf0) | (vci >> 12);
    cell[2] = vci >> 4;
    cell[3] = (cell[3] & 0x0f) | (vci << 4);
}

__always_inline static uint8_t atm_hdr_get_pti(const uint8_t *cell)
{
    return (cell[3] >> 1) & 7;
}

__always_inline static void atm_hdr_set_pti(uint8_t *cell, uint8_t pti)
{
    cell[3] = (cell[3] & 0xf1) | ((pti & 7) << 1);
}

__always_inline static bool atm_hdr_get_clp(const uint8_t *cell)
{
    return cell[3] & 1;
}

__always_inline static void atm_hdr_set_clp(uint8_t *cell, bool clp)
{
    cell[3] = (cell[3] & 0xfe) | (clp ? 1 : 0);
}

__always_inline static uint8_t atm_hdr_get_hec(const uint8_t *cell)
{
    return cell[4];
}

__always_inline static void atm_hdr_set_hec(uint8_t *cell, uint8_t hec)
{
    cell[4] = hec;
}

uint8_t atm_hec_crc(const uint8_t *data, size_t len);


/*
 * Buffer for an ATM cell
 *
 * contains a reserved field used by the fifo communicating with the netdev layer
 */
struct atm_cell_buffer {
    void *fifo_reserved;
    uint8_t buffer[ATM_CELL_SIZE];
};

#define ATM_CELL_TO_CELL_BUFFER(raw_buffer) \
    CONTAINER_OF((uint8_t *) raw_buffer, struct atm_cell_buffer, buffer[0])
#define ATM_SDU_SIZE (ATM_CELL_SIZE - ATM_HEADER_SIZE)

/* Allocate an ATM cell. Returns NULL if the cell heap is exhausted. */
struct atm_cell_buffer *atm_cell_buffer_alloc(void);

/* Free an ATM cell */
void atm_cell_buffer_free(struct atm_cell_buffer *buffer);

/*
 * Opens a permanent virtual circuit with the given vpi and vci
 * vc must be allocated by the caller
 * If the vpi/vci combination is already used return -EADDRINUSE
 *
 * For our setup we can ignore the fact that a virtual circuit would normally
 * be running on top of a virtual path
 */
int atm_open_pvc(struct atm_vc *vc, uint32_t vpi, uint32_t vci);

/*
 * Claim the teardown of the given virtual circuit: unlink it and wait for a
 * running RX callback to finish. Exactly one caller succeeds; all others get
 * -EBADR without the VC being dereferenced, so vc may be a stale pointer from
 * atm_find_vc(). The caller must finish with atm_close_vc_finish(); the memory
 * must not be freed before that.
 * Returns -EINVAL if vc is NULL, -EBADR if the VC is not (or no longer) open.
 */
int atm_close_vc(struct atm_vc *vc);

/*
 * End a teardown claimed by atm_close_vc(). Last access to the VC.
 */
void atm_close_vc_finish(struct atm_vc *vc);

/* True if the VC was never opened or its teardown has finished, i.e. it may be freed */
bool atm_vc_is_closed(const struct atm_vc *vc);

/*
 * Sets the callback that is called for every cell that is received by this circuit
 */
int atm_set_data_cb(struct atm_vc *vc, atm_data_cb cb);

/*
 * Get the atm_vc struct belonging to a given VPI VCI combination
 *
 * Returns NULL if the VPI VCI combination is not used
 *
 * The result is not pinned: the circuit may be closed and freed at any time,
 * so only pass it to atm_close_vc()/aal5_close_vc(), which validate it first.
 */
struct atm_vc *atm_find_vc(uint32_t vpi, uint32_t vci);

/*
 * Send a ATM-SDU over the given virtual circuit
 * sdu must point to a byte array of exactly 48 bytes
 *
 * If an ATM network device does not exist, this returns -ENODEV.
 * If the device is not ready yet, this returns -ENXIO.
 * If the system is out of memory this returns -ENOMEM, and if the transmit
 * backlog is full it returns -ENOBUFS.
 *
 * This is for use with F5 to set the pti directly
 */
int atm_tx(struct atm_vc *vc, const uint8_t *sdu, bool loss_priority, enum atm_pti pti);

/*
 * Send a ATM-SDU over the circuit identified by vpi/vci, for a sender that
 * answers on another thread after atm_rx_task() released the VC lock.
 *
 * vc names the circuit the request arrived on. Like in atm_close_vc() it is
 * only compared against the VC list, never dereferenced, so it may be stale.
 *
 * Returns -ENOTCONN if that circuit is no longer open, otherwise as atm_tx().
 */
int atm_tx_circuit(const struct atm_vc *vc, uint32_t vpi, uint32_t vci, const uint8_t *sdu, bool loss_priority, enum atm_pti pti);

/*
 * Send a ATM-SDU over the given virtual circuit
 * sdu must point to a byte array of exactly 48 bytes
 *
 * If an ATM network device does not exist, this returns -ENODEV.
 * If the device is not ready yet, this returns -ENXIO.
 * If the system is out of memory this returns -ENOMEM, and if the transmit
 * backlog is full it returns -ENOBUFS.
 *
 * Ref: I.361 3.1 ATM-DATA request
 */
int atm_tx_data(struct atm_vc *vc, const uint8_t *sdu, bool loss_priority, bool congestion_indication, uint32_t auu);

#endif
