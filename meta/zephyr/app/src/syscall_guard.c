#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/spinlock.h>

#include "syscall_guard.h"
#include "userspace.h"

LOG_MODULE_REGISTER(syscall_guard, CONFIG_ATM_LOG_LEVEL);

/*
 * One entry per thread that is inside a syscall or being aborted. Entries are
 * dropped as soon as neither holds, so a recycled thread object never inherits
 * one: the user threads are the handlers plus the accept loop, and none of them
 * can be in two places at once.
 */
static struct guard {
    struct k_thread *thread;  /* NULL for a free entry */
    bool inside;              /* between syscall_guard_enter() and _exit() */
    bool abort_requested;     /* abort at syscall_guard_exit(), or being aborted now */
} guards[MAX_HANDLERS + 1];

static struct k_spinlock guard_lock;

static struct guard *guard_find(struct k_thread *thread)
{
    for (size_t i = 0; i < ARRAY_SIZE(guards); ++i) {
        if (guards[i].thread == thread) {
            return &guards[i];
        }
    }
    return NULL;
}

static void guard_free(struct guard *guard)
{
    guard->thread = NULL;
    guard->inside = false;
    guard->abort_requested = false;
}

void syscall_guard_enter(void)
{
    struct k_thread *self = k_current_get();
    bool doomed = false;

    k_spinlock_key_t key = k_spin_lock(&guard_lock);
    struct guard *guard = guard_find(self);
    if (guard != NULL) {
        // only syscall_guard_abort() leaves an entry for a thread outside a
        // syscall, and it is aborting us right now: do not take anything
        doomed = guard->abort_requested;
    } else {
        guard = guard_find(NULL);
        if (guard != NULL) {
            guard->thread = self;
        }
    }
    if (guard != NULL) {
        guard->inside = true;
    }
    k_spin_unlock(&guard_lock, key);

    if (doomed) {
        k_thread_abort(self);
    }
    // there is one entry per user thread, so this cannot happen; if it does,
    // the thread runs unguarded, which is what it did before this existed
    __ASSERT(guard != NULL, "syscall guard table full");
}

void syscall_guard_exit(void)
{
    struct k_thread *self = k_current_get();
    bool abort = false;

    k_spinlock_key_t key = k_spin_lock(&guard_lock);
    struct guard *guard = guard_find(self);
    if (guard != NULL) {
        abort = guard->abort_requested;
        guard_free(guard);
    }
    k_spin_unlock(&guard_lock, key);

    if (abort) {
        LOG_WRN("aborting a handler on its way out of a syscall");
        k_thread_abort(self);
    }
}

bool syscall_guard_abort(struct k_thread *thread)
{
    k_spinlock_key_t key = k_spin_lock(&guard_lock);
    struct guard *guard = guard_find(thread);
    if (guard != NULL) {
        // inside: it aborts itself in syscall_guard_exit()
        guard->abort_requested = true;
        k_spin_unlock(&guard_lock, key);
        return false;
    }
    // Outside: abort it, but leave an entry behind until it is gone, so that a
    // syscall it enters in the meantime (on another CPU) aborts it on entry
    // instead of taking a lock first.
    guard = guard_find(NULL);
    if (guard != NULL) {
        guard->thread = thread;
        guard->abort_requested = true;
    }
    k_spin_unlock(&guard_lock, key);

    k_thread_abort(thread);

    if (guard != NULL) {
        key = k_spin_lock(&guard_lock);
        guard_free(guard);
        k_spin_unlock(&guard_lock, key);
    }
    return true;
}

bool syscall_guard_forget(struct k_thread *thread)
{
    bool inside = false;

    k_spinlock_key_t key = k_spin_lock(&guard_lock);
    struct guard *guard = guard_find(thread);
    if (guard != NULL) {
        inside = guard->inside;
        guard_free(guard);
    }
    k_spin_unlock(&guard_lock, key);
    return inside;
}
