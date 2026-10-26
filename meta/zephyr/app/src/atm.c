#include <zephyr/kernel.h>

#include <zephyr/logging/log.h>
#include <zephyr/spinlock.h>
#include <zephyr/sys/slist.h>

#include "f5.h"
#include "netdev.h"

LOG_MODULE_REGISTER(atm_layer, CONFIG_ATM_LOG_LEVEL);

// Important: The lock protects the list, the cache and every vc->_state
static struct k_spinlock vcs_lock;
static sys_slist_t vcs = SYS_SLIST_STATIC_INIT(&vcs);
static struct atm_vc *vc_cache = NULL;

static struct atm_vc *_atm_find_vc(uint32_t vpi, uint32_t vci, struct atm_vc **prev)
{
    if (prev != NULL) {
        *prev = NULL;
    }

    struct atm_vc *current;
    bool found = false;
    SYS_SLIST_FOR_EACH_CONTAINER(&vcs, current, _node) {
        if (current->vpi == vpi && current->vci == vci) {
            found = true;
            break;
        }
        if (prev != NULL) {
            *prev = current;
        }
    }

    return found ? current : NULL;
}

// Look a VC up by identity. vc is only compared, never dereferenced, so a
// stale pointer is safe here. Call with vcs_lock held.
static struct atm_vc *_atm_find_vc_ptr(const struct atm_vc *vc, struct atm_vc **prev)
{
    if (prev != NULL) {
        *prev = NULL;
    }

    struct atm_vc *current;
    SYS_SLIST_FOR_EACH_CONTAINER(&vcs, current, _node) {
        if (current == vc) {
            return current;
        }
        if (prev != NULL) {
            *prev = current;
        }
    }

    return NULL;
}

struct atm_vc *atm_find_vc(uint32_t vpi, uint32_t vci)
{
    k_spinlock_key_t vcs_lock_key = k_spin_lock(&vcs_lock);
    struct atm_vc *ret = _atm_find_vc(vpi, vci, NULL);
    k_spin_unlock(&vcs_lock, vcs_lock_key);
    return ret;
}

int atm_open_pvc(struct atm_vc *vc, uint32_t vpi, uint32_t vci)
{
    if (vc == NULL) {
        LOG_WRN("vc is NULL");
        return -EINVAL;
    }

    if (vpi > ATM_MAX_VPI || vci > ATM_MAX_VCI) {
        LOG_WRN("%u.%u is not a valid circuit", vpi, vci);
        return -EINVAL;
    }

    k_spinlock_key_t vcs_lock_key = k_spin_lock(&vcs_lock);
    if (_atm_find_vc(vpi, vci, NULL) != NULL) {
        k_spin_unlock(&vcs_lock, vcs_lock_key);
        LOG_WRN("circuit %u.%u is already in use", vpi, vci);
        return -EADDRINUSE;
    }

    vc->_node.next = 0;
    vc->vpi = vpi;
    vc->vci = vci;
    vc->is_svc = false;
    vc->mgmt_cb = f5_rx;
    k_mutex_init(&vc->lock);

    vc->_state = ATM_VC_OPEN;
    sys_slist_append(&vcs, &vc->_node);
    k_spin_unlock(&vcs_lock, vcs_lock_key);
    return 0;
}

int atm_close_vc(struct atm_vc *vc)
{
    if (vc == NULL) {
        LOG_WRN("vc is NULL");
        return -EINVAL;
    }

    // vc may be stale (callers get it from atm_find_vc without holding a
    // reference), so match by address and do not touch *vc until it is found.
    k_spinlock_key_t vcs_lock_key = k_spin_lock(&vcs_lock);
    struct atm_vc *prev;
    struct atm_vc *element = _atm_find_vc_ptr(vc, &prev);
    if (element == NULL) {
        k_spin_unlock(&vcs_lock, vcs_lock_key);
        // never opened, or another closer got here first
        LOG_DBG("vc was not in list");
        return -EBADR;
    }

    // Unlinking is the teardown claim: only one caller gets past this point.
    // if prev is NULL this will remove the the first element in the list
    sys_slist_remove(&vcs, prev != NULL ? &prev->_node : NULL, &element->_node);
    element->_state = ATM_VC_CLOSING;
    // the cache must never outlive the list entry
    vc_cache = NULL;
    k_spin_unlock(&vcs_lock, vcs_lock_key);

    // VC might still be in use by the RX path, wait before returning
    // this assures that all callbacks invokations are finished after this function returns
    k_mutex_lock(&vc->lock, K_FOREVER);
    k_mutex_unlock(&vc->lock);
    return 0;
}

void atm_close_vc_finish(struct atm_vc *vc)
{
    if (vc == NULL) {
        return;
    }

    // last access to the VC: after this the owner may free it
    k_spinlock_key_t vcs_lock_key = k_spin_lock(&vcs_lock);
    vc->_state = ATM_VC_CLOSED;
    k_spin_unlock(&vcs_lock, vcs_lock_key);
}

bool atm_vc_is_closed(const struct atm_vc *vc)
{
    k_spinlock_key_t vcs_lock_key = k_spin_lock(&vcs_lock);
    bool ret = vc == NULL || vc->_state == ATM_VC_CLOSED;
    k_spin_unlock(&vcs_lock, vcs_lock_key);
    return ret;
}

int atm_set_data_cb(struct atm_vc *vc, atm_data_cb cb)
{
    if (vc == NULL) {
        LOG_WRN("vc is NULL");
        return -EINVAL;
    }

    vc->data_cb = cb;
    return 0;
}

uint8_t atm_hec_crc(const uint8_t *data, size_t len)
{
    uint8_t crc = 0x00;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x80) ? (crc << 1) ^ 0x07 : (crc << 1);
    }
    return crc ^ 0x55;
}

static int _atm_tx(uint32_t vpi, uint32_t vci, const uint8_t *sdu, bool loss_priority, enum atm_pti pti)
{
    struct atm_cell_buffer *buf = atm_cell_buffer_alloc();
    if (buf == NULL) {
        LOG_ERR_RATELIMIT("out of cell buffers, dropping transmit cell");
        return -ENOMEM;
    }
    atm_hdr_set_vpi(buf->buffer, vpi);
    atm_hdr_set_vci(buf->buffer, vci);
    atm_hdr_set_pti(buf->buffer, pti);
    atm_hdr_set_gfc(buf->buffer, 0);
    atm_hdr_set_clp(buf->buffer, loss_priority ? 1 : 0);
    atm_hdr_set_hec(buf->buffer, atm_hec_crc(buf->buffer, 4));

    memcpy(buf->buffer + ATM_HEADER_SIZE, sdu, ATM_SDU_SIZE);

    // the netdev only takes ownership of the buffer once it is queued
    int ret = atm_netdev_tx(buf);
    if (ret != 0) {
        atm_cell_buffer_free(buf);
    }
    return ret;
}

int atm_tx(struct atm_vc *vc, const uint8_t *sdu, bool loss_priority, enum atm_pti pti)
{
    if (vc == NULL) {
        LOG_WRN("vc is NULL");
        return -EINVAL;
    }

    return _atm_tx(vc->vpi, vc->vci, sdu, loss_priority, pti);
}

int atm_tx_circuit(const struct atm_vc *vc, uint32_t vpi, uint32_t vci, const uint8_t *sdu, bool loss_priority, enum atm_pti pti)
{
    /*
     * The VC may have been closed and freed since the request arrived, so never
     * dereference it: _atm_find_vc_ptr() only compares addresses. Matching the
     * identity too means a different call that took over the same VPI/VCI does
     * not get the answer.
     */
    k_spinlock_key_t vcs_lock_key = k_spin_lock(&vcs_lock);
    struct atm_vc *element = _atm_find_vc_ptr(vc, NULL);
    bool open = element != NULL && element->vpi == vpi && element->vci == vci;
    k_spin_unlock(&vcs_lock, vcs_lock_key);

    if (!open) {
        LOG_DBG("dropping a deferred cell for the closed circuit %u.%u", vpi, vci);
        return -ENOTCONN;
    }

    return _atm_tx(vpi, vci, sdu, loss_priority, pti);
}

int atm_tx_data(struct atm_vc *vc, const uint8_t *sdu, bool loss_priority, bool congestion_indication, uint32_t auu)
{
    enum atm_pti pti = 0;
    if (auu == 0 && !congestion_indication) {
        pti = PtiUserDataCell0;
    } else if (auu == 1 && !congestion_indication) {
        pti = PtiUserDataCell1;
    } else if (auu == 0 && congestion_indication) {
        pti = PtiUserDataCellCongested0;
    } else if (auu == 1 && congestion_indication) {
        pti = PtiUserDataCellCongested1;
    }

    return atm_tx(vc, sdu, loss_priority, pti);
}

static int atm_rx_task(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    while (true) {
        struct atm_cell_buffer *buffer;
        int ret = atm_netdev_rx(&buffer, K_FOREVER);
        if (ret != 0) {
            LOG_ERR("atm rx failed with: %d", ret);
            return ret;
        }

        // do basic checks before getting the VC
        uint8_t pti = atm_hdr_get_pti(buffer->buffer);
        bool clp = atm_hdr_get_clp(buffer->buffer);

        if (pti == PtiReserved) {
            LOG_WRN("dropping cell with reserved pti");
            atm_cell_buffer_free(buffer);
            continue;
        }

        // find the matching VC
        struct atm_vc *vc;
        uint8_t vpi = atm_hdr_get_vpi(buffer->buffer);
        uint16_t vci = atm_hdr_get_vci(buffer->buffer);
        k_spinlock_key_t vcs_lock_key = k_spin_lock(&vcs_lock);
        if (vc_cache != NULL && vc_cache->vpi == vpi && vc_cache->vci == vci) {
            // assumption is that multiple packets to the same vc will arrive in batches
            // thus cache the last used vc instead of traversing the list every time
            vc = vc_cache;
        } else {
            vc = _atm_find_vc(vpi, vci, NULL);
            if (vc == NULL) {
                LOG_INF("Dropping packet to unregistered vpi: %d vci: %d", vpi, vci);
                k_spin_unlock(&vcs_lock, vcs_lock_key);
                atm_cell_buffer_free(buffer);
                continue;
            }
            vc_cache = vc;
        }
        // lock the VC before unlocking the list lock
        if ((ret = k_mutex_lock(&vc->lock, K_NO_WAIT)) != 0) {
            // RX and close are the only paths taking the VC lock
            // RX is single threaded and close removes the VC from the list before locking the VC
            // thus this branch can never be reached
            LOG_ERR("VC already locked on RX path: %d", ret);
            k_panic();
        }
        k_spin_unlock(&vcs_lock, vcs_lock_key);

        // process packet
        if (pti == PtiSegmentOamF5Cell || pti == PtiEndToEndOamF5Cell || pti == PtiResourceManagementCell) {
            if (vc->mgmt_cb) {
                vc->mgmt_cb(vc, buffer->buffer + ATM_HEADER_SIZE, clp, pti);
            } else {
                LOG_WRN("vc has no mgmt cb, vpi: %d vci: %d", vc->vpi, vc->vci);
            }
        } else {
            uint32_t congestion_indication, auu;
            switch (pti) {
                case PtiUserDataCell0:
                    congestion_indication = 0;
                    auu = 0;
                    break;
                case PtiUserDataCell1:
                    congestion_indication = 0;
                    auu = 1;
                    break;
                case PtiUserDataCellCongested0:
                    congestion_indication = 1;
                    auu = 0;
                    break;
                case PtiUserDataCellCongested1:
                    congestion_indication = 1;
                    auu = 1;
                    break;
                default:
                    k_panic();
            }
            if (vc->data_cb) {
                vc->data_cb(vc, buffer->buffer + ATM_HEADER_SIZE, clp, congestion_indication, auu);
            } else {
                LOG_WRN("vc has no data cb, vpi: %d vci: %d", vc->vpi, vc->vci);
            }
        }

        if ((ret = k_mutex_unlock(&vc->lock)) != 0) {
            LOG_ERR("atm_rx release failed: %d", ret);
            k_panic();
        }
        atm_cell_buffer_free(buffer);
    }
    return 0;
}

K_THREAD_DEFINE(atm_rx_thread, 2048, atm_rx_task, NULL, NULL, NULL, 0, 0, 0);
