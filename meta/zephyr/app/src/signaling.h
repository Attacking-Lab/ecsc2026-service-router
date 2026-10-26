#ifndef SIGNALING_H_
#define SIGNALING_H_

#include <zephyr/kernel.h>

#include "aal5.h"

/*
 * Called every time an establish msg is received on the signaling channel
 *
 * If the return value is 0 the connection is accepted
 * If the return value is non 0 the connection is rejected
 */
typedef int(sig_establish_cb)(uint32_t vpi, uint32_t vci, void* user_data);

/*
 * Called every time a release msg is received on the signaling channel
 */
typedef void(sig_release_cb)(uint32_t vpi, uint32_t vci, void* user_data);

struct release_pending;

/*
 * Struct to hold data for the signaling system
 */
struct sig_state {
    struct aal5_vc vc;
    struct release_pending *release_list;
    /* one retransmit tick per channel; a work item must not live in the
     * release_pending entries, which are freed by its handler */
    struct k_work_delayable retransmit_work;
};

/*
 * Initialize the signaling protocol on the given VPI/VCI channel
 * state must be allocated by the caller
 * If the vpi/vci combination is already used return -EADDRINUSE
 */
int sig_init(struct sig_state *state, uint32_t vpi, uint32_t vci);

/*
 * Handle processing of incomming messages and return once a new VC is opened
 *
 * Returns 0 if a new VC was opened or an error code if transmission failed
 */
int sig_accept(struct sig_state* state, struct aal5_vc *new_vc);

/*
 * Closes the VC and handles sending and retransmission of the release message
 *
 * Return 0 on success and an error code if closing or transmission failed
 */
int sig_release(struct sig_state *state, struct aal5_vc *vc);

#endif
