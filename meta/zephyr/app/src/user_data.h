#ifndef USER_DATA_H
#define USER_DATA_H

/*
 * Key/value storage for user threads, one file per key on the FAT volume, with
 * a claim on each key so that only whoever registered it can read or replace
 * it. The user-mode side reaches all of it through the atmlab_user_data_*
 * syscalls (atmlab_syscall.h).
 *
 * A claim carries a handle the caller chose: the device has no entropy worth
 * the name, so it does not try to mint one. Claiming is one-shot (a claimed key
 * answers -EEXIST) and a value is written once (a key that already has one
 * answers -EEXIST as well), which keeps a stolen handle from becoming a way to
 * destroy somebody's data.
 */

/*
 * A key is whatever the volume will store. With long names off, FatFS takes an
 * 8.3 short name: eight characters, optionally a dot and three more.
 */
#define USER_DATA_KEY_MAX       12
/* largest value stored under one key */
#define USER_DATA_VALUE_MAX     64
/* the capability registered with a claim, and presented to use it */
#define USER_DATA_HANDLE_SIZE   8

/* where the values live, one file per key */
#define USER_DATA_ROOT          "/disk0:/user"
/*
 * The claim index. Deliberately *not* under USER_DATA_ROOT: anything in there
 * is addressable as a key, and an index inside the namespace it indexes is an
 * index anyone can ask for by name.
 */
#define USER_DATA_INDEX         "/disk0:/idx"

/*
 * Claims the index holds. Pre-allocated, never grown, and allocated
 * round-robin, so this is also the number of claims that fit before the oldest
 * is evicted. 32768 x 32 bytes = 1 MiB, against a live set on the order of a
 * hundred.
 */
#define USER_DATA_SLOTS         32768

#endif /* USER_DATA_H */
