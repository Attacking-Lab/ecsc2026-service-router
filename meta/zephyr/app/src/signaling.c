/*
 * Implementation of signaling after ATKLAB Q.1337
 *
 * Only incoming connections are supported
 */
#include <zephyr/kernel.h>

#include <stdlib.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>

#include "aal5.h"
#include "addresses.h"
#include "atm.h"
#include "zephyr/spinlock.h"
#include "signaling.h"

LOG_MODULE_REGISTER(signaling_layer, CONFIG_ATM_LOG_LEVEL);

#define RETRANSMIT_MS 2000
#define RETRANSMIT_MAX 5

/*! \enum SignalingType
 *
 *  Type of signaling message
 */
enum sig_msg_type {
    ESTABLISH,
    ESTABLISHED,
    RELEASE,
    RELEASED,
    E_GENERIC = 10,
    E_INVALID_ADDRESS,
    E_UNREACHABLE,
    E_REJECTED_CIRCUIT,
    E_NOT_PERMITTED,
    E_QUOTA_EXCEEDED,
    E_CONGESTED,
};

/*
 * Structs for the signaling messages
 */
struct sig_msg_base {
    uint32_t type;
    uint32_t ID;
} __packed;

struct sig_msg_establish {
    struct E191_address address;
    uint32_t vpi;
    uint32_t vci;
} __packed;

struct sig_msg_release {
    uint32_t vpi;
    uint32_t vci;
} __packed;

struct sig_msg {
    struct sig_msg_base base;
    union {
        struct sig_msg_establish establish;
        struct sig_msg_release release;
    };
} __packed;

/*
 * Struct to store the pending release of a circuit
 *
 * Plain list node, no embedded kernel object, so the retransmit handler can free it.
 */
struct release_pending {
    struct release_pending *next;
    uint32_t retransmit_count;
    struct sig_msg msg;
};

static struct k_spinlock release_lock;

static void handle_release(struct k_work *work);

int sig_init(struct sig_state *state, uint32_t vpi, uint32_t vci)
{
    state->release_list = NULL;
    k_work_init_delayable(&state->retransmit_work, handle_release);
    return aal5_open_pvc(&state->vc, vpi, vci);
}

int sig_accept(struct sig_state* state, struct aal5_vc *new_vc)
{
    while (true) {
        // NB: Avoid the AAL5 RX bug (FIX_AAL5_BUG) here, just in case.
        // It should not be triggerable through here regardless.
        uint8_t sdu[ATM_SDU_SIZE];
        size_t sdu_len = ATM_SDU_SIZE - 8;
        int rx_ret = aal5_rx(&state->vc, sdu, &sdu_len, NULL);
        if (rx_ret == -ENOTCONN) {
            // The signaling circuit is gone, so there is nothing left to accept
            // on. Retrying would only spin: aal5_rx() fails immediately from now on.
            LOG_ERR("Signaling channel is closed");
            return rx_ret;
        }
        if (rx_ret != 0) {
            // Nothing was received, sdu and sdu_len still hold the previous
            // message. Wait for the next SDU instead of parsing that again.
            LOG_WRN("Failed to receive a signaling msg: %d", rx_ret);
            continue;
        }

        if (sdu_len < sizeof(struct sig_msg_base)) {
            LOG_WRN("Received too short msg");
            continue;
        }

        struct sig_msg *msg = (struct sig_msg*)sdu;
        // All message fields are big-endian on the wire; IDs are opaque and only ever
        // echoed back verbatim, so they need no conversion.
        uint32_t type = sys_be32_to_cpu(msg->base.type);
        struct sig_msg response = { 0 };
        size_t response_len = 0;
        switch (type) {
            case ESTABLISH:
                if (sdu_len != sizeof(struct sig_msg_base) + sizeof(struct sig_msg_establish)) {
                    LOG_WRN("Received establish msg with wrong length");
                    break;
                }
                uint32_t establish_vpi = sys_be32_to_cpu(msg->establish.vpi);
                uint32_t establish_vci = sys_be32_to_cpu(msg->establish.vci);
                if (establish_vpi > ATM_MAX_VPI || establish_vci > ATM_MAX_VCI
                        || establish_vci < ATM_MIN_CALL_VCI) {
                    LOG_WRN("Refusing to establish unusable circuit %u.%u", establish_vpi, establish_vci);
                    response.base.type = sys_cpu_to_be32(E_REJECTED_CIRCUIT);
                    response.base.ID = msg->base.ID;
                    response_len = sizeof(struct sig_msg_base);
                    break;
                }
                if (aal5_open_pvc(new_vc, establish_vpi, establish_vci) != 0) {
                    response.base.type = sys_cpu_to_be32(E_REJECTED_CIRCUIT);
                    response.base.ID = msg->base.ID;
                    response_len = sizeof(struct sig_msg_base);
                } else {
                    response.base.type = sys_cpu_to_be32(ESTABLISHED);
                    response.base.ID = msg->base.ID;
                    response_len = sizeof(struct sig_msg_base);
                }
                break;
            case ESTABLISHED:
                LOG_WRN("Received unexpected established msg");
                break;
            case RELEASE:
                if (sdu_len != sizeof(struct sig_msg_base) + sizeof(struct sig_msg_release)) {
                    LOG_WRN("Received release msg with wrong length");
                    break;
                }
                uint32_t release_vpi = sys_be32_to_cpu(msg->release.vpi);
                uint32_t release_vci = sys_be32_to_cpu(msg->release.vci);
                struct aal5_vc *close_vc = aal5_find_vc(release_vpi, release_vci);
                // Only circuits that signaling set up may be torn down by it.
                if (release_vci < ATM_MIN_CALL_VCI || close_vc == &state->vc) {
                    LOG_WRN("Refusing to release reserved circuit %u.%u", release_vpi, release_vci);
                    response.base.type = sys_cpu_to_be32(E_NOT_PERMITTED);
                    response.base.ID = msg->base.ID;
                    response_len = sizeof(struct sig_msg_base);
                    break;
                }
                aal5_close_vc(close_vc);
                response.base.type = sys_cpu_to_be32(RELEASED);
                response.base.ID = msg->base.ID;
                response_len = sizeof(struct sig_msg_base);
                break;
            case RELEASED:
                if (sdu_len != sizeof(struct sig_msg_base)) {
                    LOG_WRN("Received released msg with wrong length");
                    break;
                }
                k_spinlock_key_t release_lock_key = k_spin_lock(&release_lock);
                struct release_pending *pending;
                for (pending = state->release_list; pending != NULL; pending = pending->next) {
                    if (pending->msg.base.ID == msg->base.ID) {
                        break;
                    }
                }
                if (pending == NULL) {
                    LOG_WRN("Received released msg for a circuit that is not pending release");
                } else {
                    // indicate that no retransmission is required
                    pending->retransmit_count = 0;
                }
                k_spin_unlock(&release_lock, release_lock_key);
                break;
            case E_GENERIC:
            case E_INVALID_ADDRESS:
            case E_UNREACHABLE:
            case E_REJECTED_CIRCUIT:
            case E_NOT_PERMITTED:
                LOG_WRN("Received unexpected error msg: %d", type);
                break;
            default:
                LOG_WRN("Received unexpected msg type: %d", type);
                break;
        }

        if (response_len != 0) {
            int ret;
            if ((ret = aal5_tx(&state->vc, (void*)&response, response_len, 0, 0, 0)) != 0) {
                return ret;
            }
        }

        if (response.base.type == sys_cpu_to_be32(ESTABLISHED)) {
            return 0;
        }
    }
}

/*
 * Periodic retransmit tick for one signaling channel.
 *
 * This is the only place that unlinks and frees release_pending entries;
 * sig_release() only prepends and sig_accept() only clears retransmit_count.
 */
static void handle_release(struct k_work *work)
{
    struct k_work_delayable *dwork = k_work_delayable_from_work(work);
    struct sig_state *state = CONTAINER_OF(dwork, struct sig_state, retransmit_work);

    // reap acknowledged/exhausted entries, age the rest
    k_spinlock_key_t release_lock_key = k_spin_lock(&release_lock);
    struct release_pending *dead = NULL;
    struct release_pending **link = &state->release_list;
    while (*link != NULL) {
        struct release_pending *pending = *link;
        if (pending->retransmit_count == 0) {
            *link = pending->next;
            pending->next = dead;
            dead = pending;
        } else {
            pending->retransmit_count--;
            link = &pending->next;
        }
    }
    struct release_pending *head = state->release_list;
    k_spin_unlock(&release_lock, release_lock_key);

    while (dead != NULL) {
        struct release_pending *next = dead->next;
        k_free(dead);
        dead = next;
    }

    // retransmit outside the lock (aal5_tx can block); walking unlocked is safe
    // because nothing else removes entries and new ones are prepended before head
    size_t msg_len = sizeof(struct sig_msg_base) + sizeof(struct sig_msg_release);
    for (struct release_pending *pending = head; pending != NULL; pending = pending->next) {
        aal5_tx(&state->vc, (void*)&pending->msg, msg_len, 0, 0, 0);
    }

    release_lock_key = k_spin_lock(&release_lock);
    bool more = state->release_list != NULL;
    k_spin_unlock(&release_lock, release_lock_key);
    if (more) {
        k_work_schedule(&state->retransmit_work, K_MSEC(RETRANSMIT_MS));
    }
}

int sig_release(struct sig_state *state, struct aal5_vc *vc)
{
    // first close the VC
    int ret = aal5_close_vc(vc);

    if (ret == -ENOTCONN || ret == -EBADR || ret == -EINVAL) {
        // the circuit is already gone (e.g. released by the remote concurrently)
        return 0;
    }
    // in all other cases signal the release to the remote system
    // (the caller owns vc, so it is still valid after the close)
    uint32_t vpi = vc->atm.vpi;
    uint32_t vci = vc->atm.vci;

    struct release_pending *pending = k_malloc(sizeof(struct release_pending));
    if (pending == NULL) {
        LOG_ERR("Out of memory for pending release");
        return -ENOMEM;
    }
    // Wire fields are big-endian; the (random) ID is opaque and matched byte-for-byte
    pending->msg.base.type = sys_cpu_to_be32(RELEASE);
    pending->msg.base.ID = rand();
    pending->msg.release.vpi = sys_cpu_to_be32(vpi);
    pending->msg.release.vci = sys_cpu_to_be32(vci);
    pending->retransmit_count = RETRANSMIT_MAX;

    // link before transmitting: RELEASED may arrive before aal5_tx returns
    k_spinlock_key_t release_lock_key = k_spin_lock(&release_lock);
    pending->next = state->release_list;
    state->release_list = pending;
    k_spin_unlock(&release_lock, release_lock_key);

    // send initial release message
    size_t msg_len = sizeof(struct sig_msg_base) + sizeof(struct sig_msg_release);
    ret = aal5_tx(&state->vc, (void*)&pending->msg, msg_len, 0, 0, 0);
    if (ret != 0) {
        // let the handler free it, it may already be walking the list
        release_lock_key = k_spin_lock(&release_lock);
        pending->retransmit_count = 0;
        k_spin_unlock(&release_lock, release_lock_key);
    }

    // no-op if the tick is already scheduled
    k_work_schedule(&state->retransmit_work, K_MSEC(RETRANSMIT_MS));
    return ret;
}
