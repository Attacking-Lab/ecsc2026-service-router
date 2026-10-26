#include <zephyr/kernel.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/fs/fs.h>
#include <zephyr/internal/syscall_handler.h>
#include <zephyr/syscalls/atmlab_syscall.h>

#include "syscall_guard.h"
#include "user_data.h"

/*
 * Kernel side of the user data store. User threads cannot touch the filesystem,
 * so they get here through the three syscalls below.
 *
 * Two things live on the volume: the values, one file per key under
 * USER_DATA_ROOT, and the claim index at USER_DATA_INDEX. The index is
 * pre-allocated and fixed-size, so a record write never extends a cluster
 * chain; it is the persistent copy and nothing looks a key up in it. Lookups go
 * to the mirror in RAM, which is rebuilt from the file at startup.
 *
 * The handle is stored and handed back, and never checked here: it is the CoAP
 * layer's capability, and this layer has no opinion about who may use it. What
 * is enforced here are the storage invariants -- a key is claimed once, a value
 * is written once -- which hold no matter who is asking.
 *
 * FatFS is built reentrant (CONFIG_FS_FATFS_REENTRANT), which makes each fs_*
 * call atomic against the volume. It does not make a *sequence* of them atomic,
 * and everything here is a sequence, so store_lock covers each operation from
 * end to end -- the mirror as well as the volume, since handler threads are
 * preemptible and would otherwise observe a half-updated table.
 */

/* root + '/' + key + NUL */
#define USER_DATA_PATH_SIZE (sizeof(USER_DATA_ROOT) + 1 + USER_DATA_KEY_MAX)

/* power of two, and comfortably above USER_DATA_SLOTS to keep chains short */
#define USER_DATA_BUCKETS   65536

/* one entry of the claim index, as it sits on the volume */
struct claim {
    uint32_t seq;                               /* 0: free. Otherwise the claim's order */
    uint8_t  key_len;
    uint8_t  reserved[3];
    char     key[USER_DATA_KEY_MAX];            /* exactly as the caller sent it */
    uint8_t  handle[USER_DATA_HANDLE_SIZE];
    uint8_t  pad[4];
};

BUILD_ASSERT(sizeof(struct claim) == 32, "the index is addressed by slot, so records are fixed-size");
BUILD_ASSERT(512 % sizeof(struct claim) == 0, "a record must not straddle two sectors");
BUILD_ASSERT(USER_DATA_SLOTS < UINT16_MAX, "slot indices are stored as uint16_t + 1");

static struct k_mutex store_lock;
static bool store_ready;

/* the index, mirrored */
static struct claim records[USER_DATA_SLOTS];
/* key -> slot + 1, 0 for an empty bucket */
static uint16_t buckets[USER_DATA_BUCKETS];
/* slot -> next slot + 1 in the same bucket, 0 at the end of the chain */
static uint16_t chain[USER_DATA_SLOTS];
/* the next claim's sequence number; its slot is seq % USER_DATA_SLOTS */
static uint32_t next_seq;

/*
 * Keys
 */

/*
 * A key is whatever the volume will store, so this is the set create_name()
 * refuses (ff.c), plus the separators. Note strchr() matches the terminator,
 * which is how NUL ends up rejected too.
 */
static bool key_char_ok(uint8_t c)
{
    return c != '/' && c != '\\' && c != 0x7F &&
           strchr("*+,:;<=>[]|\"?", (int)c) == NULL;
}

// validates the key and renders the path its value lives at
static int user_data_path(char *out, size_t out_size, const char *key, size_t key_len)
{
    if (key_len == 0 || key_len > USER_DATA_KEY_MAX) {
        return -EINVAL;
    }
    for (size_t i = 0; i < key_len; ++i) {
        if (!key_char_ok((uint8_t)key[i])) {
            return -EINVAL;
        }
    }

    int len = snprintf(out, out_size, USER_DATA_ROOT "/%.*s", (int)key_len, key);
    return (len < 0 || (size_t)len >= out_size) ? -EINVAL : 0;
}

/*
 * The mirror
 */

static uint32_t key_hash(const char *key, size_t key_len)
{
    uint32_t hash = 2166136261u; /* FNV-1a */

    for (size_t i = 0; i < key_len; ++i) {
        hash = (hash ^ (uint8_t)key[i]) * 16777619u;
    }
    return hash & (USER_DATA_BUCKETS - 1);
}

static void mirror_insert(uint16_t slot)
{
    uint32_t bucket = key_hash(records[slot].key, records[slot].key_len);

    chain[slot] = buckets[bucket];
    buckets[bucket] = slot + 1;
}

static void mirror_remove(uint16_t slot)
{
    uint32_t bucket = key_hash(records[slot].key, records[slot].key_len);
    uint16_t *link = &buckets[bucket];

    while (*link != 0) {
        uint16_t current = *link - 1;

        if (current == slot) {
            *link = chain[slot];
            chain[slot] = 0;
            return;
        }
        link = &chain[current];
    }
}

/*
 * The key as the caller sent it, byte for byte. FatFS is the one that decides
 * what those bytes name on the volume.
 */
static struct claim *mirror_find(const char *key, size_t key_len)
{
    uint16_t entry = buckets[key_hash(key, key_len)];

    while (entry != 0) {
        struct claim *record = &records[entry - 1];

        if (record->key_len == key_len && memcmp(record->key, key, key_len) == 0) {
            return record;
        }
        entry = chain[entry - 1];
    }
    return NULL;
}

/*
 * Startup
 */

// mkdisk.sh creates the directory, but a disk from elsewhere may lack it
static int user_data_ensure_root(void)
{
    struct fs_dirent entry;
    if (fs_stat(USER_DATA_ROOT, &entry) == 0) {
        return entry.type == FS_DIR_ENTRY_DIR ? 0 : -ENOTDIR;
    }

    int error = fs_mkdir(USER_DATA_ROOT);
    return error == -EEXIST ? 0 : error;
}

// lays down a zeroed index, so that every later write lands in an allocated cluster
static int index_create(void)
{
    static const uint8_t zeros[512];
    struct fs_file_t file;
    int error;

    fs_file_t_init(&file);
    error = fs_open(&file, USER_DATA_INDEX, FS_O_WRITE | FS_O_CREATE);
    if (error != 0) {
        return error;
    }

    for (size_t written = 0; written < sizeof(records); written += sizeof(zeros)) {
        if (fs_write(&file, zeros, sizeof(zeros)) != (ssize_t)sizeof(zeros)) {
            fs_close(&file);
            return -EIO;
        }
    }
    return fs_close(&file);
}

static int index_load(void)
{
    struct fs_file_t file;
    struct fs_dirent entry;
    int error;

    if (fs_stat(USER_DATA_INDEX, &entry) == -ENOENT) {
        error = index_create();
        if (error != 0) {
            return error;
        }
    }

    fs_file_t_init(&file);
    error = fs_open(&file, USER_DATA_INDEX, FS_O_READ);
    if (error != 0) {
        return error;
    }
    ssize_t read = fs_read(&file, records, sizeof(records));
    error = fs_close(&file);
    if (read != (ssize_t)sizeof(records)) {
        // a short index is one we did not write; start over rather than guess
        memset(records, 0, sizeof(records));
        return error != 0 ? error : index_create();
    }
    return error;
}

/*
 * Rebuilds the mirror from the records, and picks up where the last boot left
 * off: slots are handed out round-robin, so the next sequence number is one
 * past the highest we can see.
 */
static void mirror_build(void)
{
    memset(buckets, 0, sizeof(buckets));
    memset(chain, 0, sizeof(chain));
    next_seq = 1;

    for (uint16_t slot = 0; slot < USER_DATA_SLOTS; ++slot) {
        struct claim *record = &records[slot];

        if (record->seq == 0) {
            continue;
        }
        // a record we cannot address is one we cannot have written
        if (record->key_len == 0 || record->key_len > USER_DATA_KEY_MAX) {
            record->seq = 0;
            continue;
        }
        mirror_insert(slot);
        if (record->seq >= next_seq) {
            next_seq = record->seq + 1;
        }
    }
}

static int store_init(void)
{
    int error;

    if (store_ready) {
        return 0;
    }

    error = user_data_ensure_root();
    if (error != 0) {
        return error;
    }
    error = index_load();
    if (error != 0) {
        return error;
    }
    mirror_build();

    store_ready = true;
    return 0;
}

/*
 * Claims
 */

static int index_store(uint16_t slot)
{
    struct fs_file_t file;
    int error;

    fs_file_t_init(&file);
    error = fs_open(&file, USER_DATA_INDEX, FS_O_WRITE);
    if (error != 0) {
        return error;
    }
    error = fs_seek(&file, (off_t)slot * sizeof(struct claim), FS_SEEK_SET);
    if (error == 0) {
        ssize_t written = fs_write(&file, &records[slot], sizeof(struct claim));
        if (written != (ssize_t)sizeof(struct claim)) {
            error = -EIO;
        }
    }

    int close_error = fs_close(&file);
    return error != 0 ? error : close_error;
}

/*
 * Registers a handle against a key, so that later reads and the one write can
 * present it. Returns 0, or a negative errno (-EINVAL for a bad key, -EEXIST if
 * the key is claimed already).
 */
int z_impl_atmlab_user_data_claim(const char *key, size_t key_len, const void *handle)
{
    char path[USER_DATA_PATH_SIZE];
    uint8_t claimed[USER_DATA_HANDLE_SIZE];
    int error;

    memcpy(claimed, handle, sizeof(claimed));

    k_mutex_lock(&store_lock, K_FOREVER);

    error = store_init();
    if (error != 0) {
        goto out;
    }
    error = user_data_path(path, sizeof(path), key, key_len);
    if (error != 0) {
        goto out;
    }
    if (mirror_find(key, key_len) != NULL) {
        error = -EEXIST;
        goto out;
    }

    uint16_t slot = (uint16_t)(next_seq % USER_DATA_SLOTS);

    /*
     * Evicting the oldest claim takes its value with it. Several claims can
     * name one file -- the volume decides what a key spells, not us -- so this
     * can unlink a file another claim still refers to. The index holds
     * USER_DATA_SLOTS claims against a live set of about a hundred, so it does
     * not come round in a game; anything that makes it come round is already
     * evicting live claims by the thousand.
     *
     * Unlink before overwriting the record: interrupted that way round, a claim
     * points at a file that is not there, which reads as "no value". The other
     * order leaves a value nobody has a claim on.
     */
    if (records[slot].seq != 0) {
        char evicted[USER_DATA_PATH_SIZE];

        if (user_data_path(evicted, sizeof(evicted), records[slot].key,
                    records[slot].key_len) == 0) {
            fs_unlink(evicted);
        }
        mirror_remove(slot);
    }

    memset(&records[slot], 0, sizeof(records[slot]));
    records[slot].seq = next_seq;
    records[slot].key_len = (uint8_t)key_len;
    memcpy(records[slot].key, key, key_len);
    memcpy(records[slot].handle, claimed, sizeof(claimed));

    error = index_store(slot);
    if (error != 0) {
        records[slot].seq = 0;
        goto out;
    }

    mirror_insert(slot);
    ++next_seq;

out:
    k_mutex_unlock(&store_lock);
    return error;
}

int z_vrfy_atmlab_user_data_claim(const char *key, size_t key_len, const void *handle)
{
    // lengths first, the memory checks compute key + key_len
    K_OOPS(K_SYSCALL_VERIFY(key_len <= USER_DATA_KEY_MAX));
    K_OOPS(K_SYSCALL_MEMORY_READ(key, key_len));
    K_OOPS(K_SYSCALL_MEMORY_READ(handle, USER_DATA_HANDLE_SIZE));
    syscall_guard_enter();
    int ret = z_impl_atmlab_user_data_claim(key, key_len, handle);
    syscall_guard_exit();
    return ret;
}
#include <zephyr/syscalls/atmlab_user_data_claim_mrsh.c>

/*
 * Hands back the handle registered for a key, for the caller to check against
 * whatever was presented to it. Returns 0, or a negative errno (-EINVAL for a
 * bad key, -ENOENT if the key is not claimed).
 */
int z_impl_atmlab_user_data_handle(const char *key, size_t key_len, void *handle)
{
    char path[USER_DATA_PATH_SIZE];
    int error;

    k_mutex_lock(&store_lock, K_FOREVER);

    error = store_init();
    if (error != 0) {
        goto out;
    }
    error = user_data_path(path, sizeof(path), key, key_len);
    if (error != 0) {
        goto out;
    }

    const struct claim *record = mirror_find(key, key_len);
    if (record == NULL) {
        error = -ENOENT;
        goto out;
    }
    memcpy(handle, record->handle, USER_DATA_HANDLE_SIZE);

out:
    k_mutex_unlock(&store_lock);
    return error;
}

int z_vrfy_atmlab_user_data_handle(const char *key, size_t key_len, void *handle)
{
    K_OOPS(K_SYSCALL_VERIFY(key_len <= USER_DATA_KEY_MAX));
    K_OOPS(K_SYSCALL_MEMORY_READ(key, key_len));
    K_OOPS(K_SYSCALL_MEMORY_WRITE(handle, USER_DATA_HANDLE_SIZE));
    syscall_guard_enter();
    int ret = z_impl_atmlab_user_data_handle(key, key_len, handle);
    syscall_guard_exit();
    return ret;
}
#include <zephyr/syscalls/atmlab_user_data_handle_mrsh.c>

/*
 * Stores the value for a claimed key. Returns 0, or a negative errno (-EINVAL
 * for a bad key or length, -ENOENT if the key is not claimed, -EEXIST if the
 * key already has a value).
 */
int z_impl_atmlab_user_data_write(const char *key, size_t key_len, const void *data,
        size_t data_len)
{
    char path[USER_DATA_PATH_SIZE];
    uint8_t value[USER_DATA_VALUE_MAX];
    struct fs_file_t file;
    struct fs_dirent entry;
    int error;

    if (data_len == 0 || data_len > sizeof(value)) {
        return -EINVAL;
    }
    memcpy(value, data, data_len);

    k_mutex_lock(&store_lock, K_FOREVER);

    error = store_init();
    if (error != 0) {
        goto out;
    }
    error = user_data_path(path, sizeof(path), key, key_len);
    if (error != 0) {
        goto out;
    }

    if (mirror_find(key, key_len) == NULL) {
        error = -ENOENT;
        goto out;
    }

    /*
     * Whether this key already has a value is the volume's answer and not the
     * index's: two claims can name one file, and only the volume knows that.
     * Asking the record instead would let the second claim overwrite the first
     * one's data.
     */
    if (fs_stat(path, &entry) == 0) {
        error = -EEXIST;
        goto out;
    }

    fs_file_t_init(&file);
    error = fs_open(&file, path, FS_O_WRITE | FS_O_CREATE);
    if (error != 0) {
        goto out;
    }
    ssize_t written = fs_write(&file, value, data_len);
    int close_error = fs_close(&file);
    if (written != (ssize_t)data_len) {
        error = -EIO;
    } else {
        error = close_error;
    }

out:
    k_mutex_unlock(&store_lock);
    return error;
}

int z_vrfy_atmlab_user_data_write(const char *key, size_t key_len, const void *data,
        size_t data_len)
{
    K_OOPS(K_SYSCALL_VERIFY(key_len <= USER_DATA_KEY_MAX));
    K_OOPS(K_SYSCALL_VERIFY(data_len <= USER_DATA_VALUE_MAX));
    K_OOPS(K_SYSCALL_MEMORY_READ(key, key_len));
    K_OOPS(K_SYSCALL_MEMORY_READ(data, data_len));
    syscall_guard_enter();
    int ret = z_impl_atmlab_user_data_write(key, key_len, data, data_len);
    syscall_guard_exit();
    return ret;
}
#include <zephyr/syscalls/atmlab_user_data_write_mrsh.c>

/*
 * Reads the value stored under a claimed key into buf. Returns the number of
 * bytes, or a negative errno (-EINVAL for a bad key, -ENOENT if there is no
 * claim or no value, -ENOMEM if buf is too small).
 */
int z_impl_atmlab_user_data_read(const char *key, size_t key_len, void *buf, size_t buf_len)
{
    char path[USER_DATA_PATH_SIZE];
    uint8_t value[USER_DATA_VALUE_MAX];
    struct fs_file_t file;
    int error;

    k_mutex_lock(&store_lock, K_FOREVER);

    error = store_init();
    if (error != 0) {
        goto out;
    }
    error = user_data_path(path, sizeof(path), key, key_len);
    if (error != 0) {
        goto out;
    }

    if (mirror_find(key, key_len) == NULL) {
        error = -ENOENT;
        goto out;
    }

    fs_file_t_init(&file);
    error = fs_open(&file, path, FS_O_READ);
    if (error != 0) {
        goto out;
    }
    ssize_t read = fs_read(&file, value, sizeof(value));
    int close_error = fs_close(&file);
    if (read < 0) {
        error = (int)read;
        goto out;
    }
    if (read == 0) {
        // claimed, but nothing written under it yet
        error = -ENOENT;
        goto out;
    }
    if (close_error != 0) {
        error = close_error;
        goto out;
    }
    if ((size_t)read > buf_len) {
        error = -ENOMEM;
        goto out;
    }

    memcpy(buf, value, (size_t)read);
    error = (int)read;

out:
    k_mutex_unlock(&store_lock);
    return error;
}

int z_vrfy_atmlab_user_data_read(const char *key, size_t key_len, void *buf, size_t buf_len)
{
    K_OOPS(K_SYSCALL_VERIFY(key_len <= USER_DATA_KEY_MAX));
    K_OOPS(K_SYSCALL_VERIFY(buf_len <= USER_DATA_VALUE_MAX));
    K_OOPS(K_SYSCALL_MEMORY_READ(key, key_len));
    K_OOPS(K_SYSCALL_MEMORY_WRITE(buf, buf_len));
    syscall_guard_enter();
    int ret = z_impl_atmlab_user_data_read(key, key_len, buf, buf_len);
    syscall_guard_exit();
    return ret;
}
#include <zephyr/syscalls/atmlab_user_data_read_mrsh.c>

static int user_data_sys_init(void)
{
    k_mutex_init(&store_lock);
    return 0;
}

SYS_INIT(user_data_sys_init, POST_KERNEL, CONFIG_APPLICATION_INIT_PRIORITY);
