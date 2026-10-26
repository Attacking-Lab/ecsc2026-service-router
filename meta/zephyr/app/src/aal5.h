#ifndef AAL5_H_
#define AAL5_H_

#include <zephyr/sys/atomic.h>

#include "atm.h"

#define AAL5_MAX_SDU_SIZE 2048
#define AAL5_RX_QUEUE_CELLS 128

struct aal5_trailer {
    uint8_t uu;     // User-to-User indication
    uint8_t cpi;    // Common Part Indicator (reserved)
    uint8_t length[2];
    uint8_t crc[4];
} __packed;

struct aal5_vc;

struct aal5_vc {
    struct atm_vc atm;
    bool closing;
    bool rx_dropping;
    struct k_fifo rx_q;
    /* number of cells currently in rx_q; written by both producer and reader */
    atomic_t rx_q_cells;
    /*
     * End-of-stream marker: aal5_close_vc() queues it, aal5_rx() recognises
     * it by address and returns -ENOTCONN. Unlike k_fifo_cancel_wait() it also
     * catches readers that are not pending yet.
     */
    void *rx_eof;
};

/*
 * Wrapper around atm_open_vc for a PVC that uses AAL5
 * vc must be allocated by the caller
 * If the vpi/vci combination is already used return -EADDRINUSE
 */
int aal5_open_pvc(struct aal5_vc *vc, uint32_t vpi, uint32_t vci);

/*
 * Close the given virtual circuit
 * The allocated memory must be deallocated by the caller
 *
 * Only one caller tears a circuit down (see atm_close_vc()); the others get
 * -EBADR without touching the VC, so a stale pointer from aal5_find_vc() is safe.
 * Returns -EINVAL if vc is NULL, -EBADR if the circuit is not open (any more).
 */
int aal5_close_vc(struct aal5_vc *vc);

/*
 * Get the aal5_vc struct belonging to a given VPI VCI combination
 *
 * Returns NULL if the VPI VCI combination is not used
 * The result is not pinned (see atm_find_vc()); only pass it to aal5_close_vc().
 */
struct aal5_vc *aal5_find_vc(uint32_t vpi, uint32_t vci);

/*
 * Receive an AAL5 encoded SDU via the VC into the given buffer
 * buf_len is the length of the buffer on entry and is returned as the actually received size
 * uu is returned as the uu of the SDU
 *
 * buf_len needs to be (N * ATM_SDU_SIZE) - 8
 *
 * If the conection is closed returns -ENOTCONN
 * If the arguments are invalid returns -EINVAL
 * If the buffer is to small for the received SDU returns -ENOBUFS
 */
int aal5_rx(struct aal5_vc *vc, uint8_t *buf, size_t *buf_len, uint8_t *uu);

/*
 * Send an AAL5 encoded SDU via a VC to the receiving side
 * sdu_len must be less than 2^16
 *
 * If the conection is closed returns -ENOTCONN
 * If an ATM network device does not exist, this returns -ENODEV.
 * If the device is not ready yet, this returns -ENXIO.
 * If the system is out of memory this function will block until memory is available again
 *
 * Ref: I.363.5 7.2.1 CPCS-UNITDATA invoke
 */
int aal5_tx(struct aal5_vc *vc, const uint8_t *sdu, size_t sdu_len, bool loss_priority, bool congestion_indication, uint8_t uu);

#endif
