#ifndef SYSCALL_GUARD_H
#define SYSCALL_GUARD_H

#include <stdbool.h>
#include <zephyr/kernel.h>

/*
 * Keeps the supervisor from aborting a thread while it is inside one of our
 * syscalls.
 *
 * k_thread_abort() does not release the mutexes a thread holds. A handler cut
 * down in the middle of a syscall leaves the lock it held (store_lock, the
 * FatFS volume lock, a socket lock) owned by a dead thread, and once the
 * thread object is freed and recycled, the next k_mutex_lock() on it follows a
 * dangling owner pointer into priority inheritance and faults. So an abort
 * that finds its target inside a syscall is deferred, and the thread aborts
 * itself on the way out, with nothing held.
 *
 * Every z_vrfy_atmlab_*() brackets its z_impl call with enter/exit.
 */

void syscall_guard_enter(void);

/* does not return if an abort was requested while the thread was inside */
void syscall_guard_exit(void);

/*
 * Aborts thread right away if it is not inside a syscall, otherwise marks it
 * to abort itself at syscall_guard_exit(). Returns true if it was aborted now.
 */
bool syscall_guard_abort(struct k_thread *thread);

/*
 * For the fatal error handler: the faulting thread will not pass through
 * syscall_guard_exit(), so forget it before its thread object can be recycled.
 * Returns true if it faulted inside a syscall, where it may hold a lock that
 * dropping the thread would leave owned by a dead one.
 */
bool syscall_guard_forget(struct k_thread *thread);

#endif /* SYSCALL_GUARD_H */
