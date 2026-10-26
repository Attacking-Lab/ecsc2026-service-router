#ifndef USERSPACE_H
#define USERSPACE_H

#include <zephyr/kernel.h>

#include <zephyr/app_memory/mem_domain.h>

// bounded: thread indexes are scarce (CONFIG_MAX_THREAD_BYTES) and running out
// of them wedges the service for good
#define MAX_HANDLERS 251

// Each handler's memory domain costs an Xtensa ASID. ptables.c starts handing
// them out at 3 and 255 is the shared one, so the last domain may take 254 --
// 251 domains. Its own __ASSERT is off by one (it checks before incrementing,
// so it would let a domain take the shared ASID) and CONFIG_ASSERT=n compiles
// it out anyway. Overflowing wraps asid_count, which is a uint8_t, and two
// domains end up sharing an ASID, so catch it here instead.
BUILD_ASSERT(MAX_HANDLERS + 3 < 255 /* XTENSA_MMU_SHARED_ASID */,
        "MAX_HANDLERS exceeds the Xtensa ASID budget");

// One L1 page table per domain, plus the kernel's at index 0
BUILD_ASSERT(CONFIG_XTENSA_MMU_NUM_L1_TABLES >= MAX_HANDLERS + 1,
        "not enough L1 page tables for one memory domain per handler");

// One memory domain per handler slot, so a handler can reach its own stack but
// not another handler's. Domains are never torn down: the arch side hands out
// an L1 page table and an ASID per domain and gives neither back, so they are
// allocated once, up front, and reused by whoever lands in the slot next.
extern struct k_mem_domain thread_domains[MAX_HANDLERS];

int userspace_main(void);

#endif
