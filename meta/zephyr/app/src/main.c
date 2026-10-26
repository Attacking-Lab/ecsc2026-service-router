#include <zephyr/kernel.h>

#include <zephyr/app_memory/mem_domain.h>
#include <zephyr/app_memory/partitions.h>
#include <zephyr/fatal.h>
#include <zephyr/fs/fs.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/storage/disk_access.h>
#include <zephyr/sys/libc-hooks.h>
#include <zephyr/sys/printk.h>

#include <ff.h>

#include "aal5.h"
#include "syscall_guard.h"
#include "userspace.h"

#if CONFIG_SELFTEST
#include "test/selftest.h"
#endif

struct k_mem_domain thread_domains[MAX_HANDLERS];

// A handler domain starts out with nothing of its own: the thread's stack is
// mapped into it when the thread joins (and unmapped when it dies), and
// text/rodata are mapped shared for every ring. The C library's globals are the
// one thing that has to be handed over explicitly, or printf() faults.
//
// This has to run before anything maps memory that is not identity-mapped --
// the PCI BARs, above all. A domain is a copy of the kernel page tables taken
// when the domain is created, and arch_mem_domain_init() makes that copy by
// resetting every page it copies to the attributes saved at boot. Pages mapped
// after boot have no saved attributes, so they come out of the copy *unmapped*:
// a domain created after the PCIe/virtio drivers is missing their BARs, and the
// virtio ISR dies with a load-prohibited fault the first time it fires while a
// handler thread is current. Taking the copy first avoids the whole problem,
// because arch_mem_map() propagates every later mapping into every existing
// domain. Hence PRE_KERNEL_1, right after the memory domain subsystem itself
// (which initialises at KERNEL_INIT_PRIORITY_DEFAULT) and before the drivers.
static int init_thread_domains(void)
{
    struct k_mem_partition *parts[] = { &z_libc_partition };

    for (size_t i = 0; i < ARRAY_SIZE(thread_domains); ++i) {
        int error = k_mem_domain_init(&thread_domains[i], ARRAY_SIZE(parts), parts);
        if (error != 0) {
            printk("Failed to initialize thread domain %zu: %d\n", i, error);
            return error;
        }
    }

    return 0;
}

BUILD_ASSERT(CONFIG_KERNEL_INIT_PRIORITY_DEFAULT < 50);
SYS_INIT(init_thread_domains, PRE_KERNEL_1, 50);

static FATFS fat_fs;
static struct fs_mount_t fat_mount = { .type = FS_FATFS, .mnt_point = "/disk0:", .fs_data = &fat_fs, };

int main(void) {
#if CONFIG_SELFTEST
    run_selftests();
#endif

    int error;

    error = disk_access_ioctl("disk0", DISK_IOCTL_CTRL_INIT, NULL);
    if (error != 0) {
        printk("Failed to initialize disk: %d\n", error);
        k_panic();
    }

    error = fs_mount(&fat_mount);
    if (error != 0) {
        printk("Failed to mount disk at %s: %d\n", fat_mount.mnt_point, error);
        k_panic();
    }

    userspace_main();

    printk("Initialization done.\n");
    return 0;
}

// The default error handler would panic the entire system.
// This will only kill the thread that caused the panic.
void k_sys_fatal_error_handler(unsigned int reason, const struct arch_esf *esf) {
    // What thread are we on?
    struct k_thread *thread = k_current_get();
    const char *name = k_thread_name_get(thread);
    if (name == NULL || name[0] == '\0') {
        name = "unknown";
    }

    // k_is_in_isr() is always true here: on Xtensa the exception entry bumps
    // the nesting count before calling into C. Only a deeper nesting means the
    // fault happened inside an ISR.
    bool fault_in_isr = arch_curr_cpu()->nested > 1;

    // A user thread that faulted inside one of our syscalls may hold a kernel
    // lock (store_lock, the FatFS volume, the disk). Dropping it would leave
    // that lock owned by a dead thread whose object gets recycled, and every
    // later locker would fault in priority inheritance; halting is better.
    // K_OOPS in the z_vrfy_*() checks fires before the guard and holds nothing.
    bool fault_in_syscall = syscall_guard_forget(thread);

    // Only a faulting user thread can be dropped on its own. k_is_user_context()
    // cannot answer this (we are already privileged), but we can ask the thread.
    if (fault_in_isr || fault_in_syscall || (thread->base.user_options & K_USER) == 0) {
        // Flush the deferred log backend, or the fault that got us here is dropped.
        LOG_PANIC();
        printk("Fatal error %u in kernel context on thread: %p (%s)%s\n", reason, thread, name,
                fault_in_syscall ? " inside a syscall" : "");
        k_fatal_halt(reason);
    }

    // The system keeps running, so do not use LOG_PANIC() (it latches the logger
    // into synchronous mode for good, which costs ~1 KB of stack per printk) or
    // log_flush() (it sleeps, which is not allowed inside the exception handler).
    printk("Fatal error on thread: %p (%s)\n", thread, name);
    log_thread_trigger();
}
