/*
 * Implementation of ATM Adaption Layer Type 5 as specified in I.363.5
 *
 * Streaming mode (7.ii) is not implemented.
 * Corrupted data delivery (Annex E) is not implemented.
 */

#include <string.h>
#include <zephyr/kernel.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/crc.h>
#include <zephyr/sys/util.h>

#include "aal5.h"
#include "atm.h"
#include "crc.h"

LOG_MODULE_REGISTER(aal5_layer, CONFIG_ATM_LOG_LEVEL);

struct atm_sdu_entry {
    void *fifo_reserverd;
    uint32_t auu;
    uint8_t data[ATM_SDU_SIZE];
};

__always_inline static uint16_t aal5_trailer_get_len(const struct aal5_trailer* trailer)
{
    return trailer->length[0] << 8 | trailer->length[1];
}

__always_inline static void aal5_trailer_set_len(struct aal5_trailer* trailer, uint16_t length)
{
    trailer->length[0] = (uint8_t)(length >> 8);
    trailer->length[1] = (uint8_t)length;
}

__always_inline static uint32_t aal5_trailer_get_crc(const struct aal5_trailer* trailer)
{
    return trailer->crc[0] << 24 | trailer->crc[1] << 16 | trailer->crc[2] << 8 | trailer->crc[3];
}

__always_inline static void aal5_trailer_set_crc(struct aal5_trailer* trailer, uint32_t crc)
{
    trailer->crc[0] = (uint8_t)(crc >> 24);
    trailer->crc[1] = (uint8_t)(crc >> 16);
    trailer->crc[2] = (uint8_t)(crc >> 8);
    trailer->crc[3] = (uint8_t)crc;
}

static void aal5_cb(struct atm_vc* atm_vc, uint8_t* atm_sdu, bool loss_priority, bool congestion_indication, uint32_t auu)
{
    struct aal5_vc *vc = CONTAINER_OF(atm_vc, struct aal5_vc, atm);

    if (atomic_get(&vc->rx_q_cells) >= AAL5_RX_QUEUE_CELLS) {
        // Reader is not reading, drop the cell
        LOG_DBG("rx queue full, dropping cell");
        return;
    }

    struct atm_sdu_entry *sdu = k_malloc(sizeof(struct atm_sdu_entry));
    if (sdu == NULL) {
        LOG_ERR("out of memory, dropping cell");
        return;
    }
    sdu->auu = auu;
    memcpy(sdu->data, atm_sdu, ATM_SDU_SIZE);

    atomic_inc(&vc->rx_q_cells);
    k_fifo_put(&vc->rx_q, sdu);
}

int aal5_rx(struct aal5_vc *vc, uint8_t *buf, size_t *buf_len, uint8_t *uu)
{
    int rx_size = 0;
    uint32_t crc = CRC_INITIAL_VALUE;

    if (
            vc == NULL
            || buf == NULL
            || buf_len == NULL
            || (*buf_len + sizeof(struct aal5_trailer)) % ATM_SDU_SIZE != 0 ) {
        return -EINVAL;
    }

    if (vc->closing) {
        return -ENOTCONN;
    }

    while (true) {
        struct atm_sdu_entry *sdu = k_fifo_get(&vc->rx_q, K_FOREVER);
        if (sdu == NULL) {
            // can only happen if signaled from close
            // means connection is closed
            return -ENOTCONN;
        }
        if ((void *)sdu == (void *)&vc->rx_eof) {
            // end-of-stream marker from aal5_close_vc(); put it back for the
            // next reader, it is part of the VC and must not be freed
            k_fifo_put(&vc->rx_q, &vc->rx_eof);
            return -ENOTCONN;
        }
        atomic_dec(&vc->rx_q_cells);

        if (vc->rx_dropping) {
            // rx error from previous cell
            // drop until next AAL5 SDU
            if (sdu->auu == 1) {
                vc->rx_dropping = false;
            }
        } else if (sdu->auu == 1) {
            // last frame
            struct aal5_trailer *trailer = (struct aal5_trailer*)((uintptr_t)sdu->data + ATM_SDU_SIZE - sizeof(struct aal5_trailer));
            bool discard = false;

            // can be negative if there is already padding in the previous cell
            int sdu_remaining_bytes = (int)aal5_trailer_get_len(trailer) - rx_size;
            if (
                    aal5_trailer_get_len(trailer) == 0                                          // explicit drop requested
                    || sdu_remaining_bytes < -(int)(sizeof(struct aal5_trailer) - 1)            // too much data already present
#ifdef FIX_AAL5_BUG
                    || sdu_remaining_bytes > (int)(ATM_SDU_SIZE - sizeof(struct aal5_trailer))  // too little data
                    || aal5_trailer_get_len(trailer) > *buf_len                                 // too much data for buffer
#else
                    || sdu_remaining_bytes > ATM_SDU_SIZE                                       // too little data
#endif
                    || trailer->cpi != 0                                                        // invalid cpi
                    ) {
                LOG_DBG("Dropping invalid AAL5 SDU");
                discard = true;
            }

            if (!discard) {
                // update crc
                crc = update_crc(crc, sdu->data, ATM_SDU_SIZE - 4);
                crc = CRC_FINISH(crc);

                if (aal5_trailer_get_crc(trailer) != crc) {
                    LOG_DBG("Invalid CRC: calculated: %x expected: %x", crc, aal5_trailer_get_crc(trailer));
                    discard = true;
                }
            }

            if (discard) {
                // stop processing invalid SDU
                vc->rx_dropping = true;
                rx_size = 0;
                k_free(sdu);
                continue;
            }
            if (sdu_remaining_bytes > 0) {
                memcpy(buf + rx_size, sdu->data, sdu_remaining_bytes);
            }
            // rx_size needs to be adjusted even if sdu_remaining_bytes is < 0
            // because this indicates padding in the previous cell that needs to be truncated
            rx_size += sdu_remaining_bytes;
            *buf_len = rx_size;
            if (uu != NULL) {
                *uu = trailer->uu;
            }
            k_free(sdu);
            return 0;
        } else {
            // continous frame
            if (rx_size + ATM_SDU_SIZE > *buf_len - 1) {
                // either this or the next ATM SDU would overflow the buffer
                // drop packets in the following call
                vc->rx_dropping = true;
                // and notify the caller
                k_free(sdu);
                return -ENOBUFS;
            }
            // update crc
            crc = update_crc(crc, sdu->data, ATM_SDU_SIZE);

            // copy to reassembly buffer
            memcpy(buf + rx_size, sdu->data, ATM_SDU_SIZE);
            rx_size += ATM_SDU_SIZE;
        }
        k_free(sdu);
    }

}

int aal5_tx(struct aal5_vc *vc, const uint8_t *sdu, size_t sdu_len, bool loss_priority, bool congestion_indication, uint8_t uu)
{
    if (vc->closing) {
        return -ENOTCONN;
    }

    if (sdu_len > UINT16_MAX) {
        return -EINVAL;
    }

    uint32_t crc = CRC_INITIAL_VALUE;
    crc = update_crc(crc, sdu, sdu_len);
    size_t sdu_remaining_bytes = sdu_len;
    size_t left;
    while (true) {
        size_t data_len = min(sdu_remaining_bytes, ATM_SDU_SIZE);
        left = ATM_SDU_SIZE - data_len;

        if (left == 0) {
            // full cell, send it out
            int ret = atm_tx_data(&vc->atm, sdu, loss_priority, congestion_indication, 0);
            if (ret != 0) {
                return ret;
            }
        } else if (left < sizeof(struct aal5_trailer)) {
            // not enough space for trailer, but need to add padding
            uint8_t cell[ATM_SDU_SIZE];
            memcpy(cell, sdu, sdu_remaining_bytes);
            memset(cell + sdu_remaining_bytes, 0, left);
            // need to include padding in the CRC
            crc = update_crc(crc, cell + sdu_remaining_bytes, left);
            int ret = atm_tx_data(&vc->atm, cell, loss_priority, congestion_indication, 0);
            if (ret != 0) {
                return ret;
            }
        } else {
            // enough space for the trailer, this is the last cell
            uint8_t cell[ATM_SDU_SIZE];
            memcpy(cell, sdu, sdu_remaining_bytes);
            memset(cell + sdu_remaining_bytes, 0, left - sizeof(struct aal5_trailer));
            struct aal5_trailer *trailer = (struct aal5_trailer*)((uintptr_t)cell + ATM_SDU_SIZE - sizeof(struct aal5_trailer));
            trailer->uu = uu;
            trailer->cpi = 0;
            aal5_trailer_set_len(trailer, sdu_len);

            // CRC includes padding and trailer, except for the CRC field
            crc = update_crc(crc, cell + sdu_remaining_bytes, left - 4);
            aal5_trailer_set_crc(trailer, CRC_FINISH(crc));

            // set auu to 1 to indicate last cell
            int ret = atm_tx_data(&vc->atm, cell, loss_priority, congestion_indication, 1);
            if (ret != 0) {
                return ret;
            }
            break;
        }
        sdu_remaining_bytes -= data_len;
        sdu += data_len;
    }
    return 0;
}

struct aal5_vc *aal5_find_vc(uint32_t vpi, uint32_t vci)
{
    struct atm_vc *atm_vc = atm_find_vc(vpi, vci);
    if (atm_vc == NULL) {
        return NULL;
    }
    struct aal5_vc *vc = CONTAINER_OF(atm_vc, struct aal5_vc, atm);
    return vc;
}

int aal5_open_pvc(struct aal5_vc *vc, uint32_t vpi, uint32_t vci)
{
    int ret;
    if ((ret = atm_set_data_cb(&vc->atm, aal5_cb)) != 0) {
        return ret;
    }
    vc->closing = false;
    vc->rx_dropping = false;
    atomic_clear(&vc->rx_q_cells);
    k_fifo_init(&vc->rx_q);
    return atm_open_pvc(&vc->atm, vpi, vci);
}

int aal5_close_vc(struct aal5_vc *vc)
{
    if (vc == NULL) {
        return -EINVAL;
    }

    // vc may be stale (see aal5_find_vc), so claim the teardown before touching
    // any field; on -EBADR another closer owns it and we must not touch it
    int ret;
    if ((ret = atm_close_vc(&vc->atm)) != 0) {
        return ret;
    }

    // we own the teardown: the RX callback is done and nothing can put into
    // rx_q any more; the memory stays valid until atm_close_vc_finish()
    vc->closing = true;

    // clear any remaining entries in the queue
    struct atm_sdu_entry *sdu;
    while ((sdu = k_fifo_get(&vc->rx_q, K_NO_WAIT)) != NULL) {
        k_free(sdu);
    }
    atomic_clear(&vc->rx_q_cells);

    // wake a waiting reader and fail every later one (must come after the drain)
    k_fifo_put(&vc->rx_q, &vc->rx_eof);

    // last access to the VC
    atm_close_vc_finish(&vc->atm);
    return 0;
}
