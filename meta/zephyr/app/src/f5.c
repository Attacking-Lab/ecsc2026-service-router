#include <zephyr/kernel.h>

#include <stdio.h>

#include <zephyr/fs/fs.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/byteorder.h>

#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>

#include "atm.h"
#include "f5.h"

LOG_MODULE_REGISTER(f5_layer, CONFIG_ATM_LOG_LEVEL);

/* OAM EDC CRC-10, ITU-T I.610 10.1 5) */
static __noinline uint16_t f5_oam_edc(const uint8_t sdu[static ATM_SDU_SIZE])
{
    uint16_t crc = 0;
    for (size_t i = 0; i < ATM_SDU_SIZE - 2; i++) {
        crc ^= (uint16_t) sdu[i] << 2;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x200) ? ((crc << 1) ^ 0x233) & 0x3ff : (crc << 1) & 0x3ff;
    }

    /* Fold in the reserved bits */
    for (int b = 7; b >= 2; b--) {
        uint16_t in = (sdu[ATM_SDU_SIZE - 2] >> b) & 1;
        uint16_t top = (crc >> 9) & 1;
        crc = (crc << 1) & 0x3ff;
        if (top ^ in)
            crc ^= 0x233;
    }

    return crc;
}

static void f5_oam_update_edc(uint8_t sdu[static ATM_SDU_SIZE])
{
    /* Reserved bits are kept unmodified */
    uint16_t edc = f5_oam_edc(sdu);
    sdu[ATM_SDU_SIZE - 2] = (sdu[ATM_SDU_SIZE - 2] & 0xfc) | ((edc >> 8) & 0x3);
    sdu[ATM_SDU_SIZE - 1] = edc & 0xff;
}


/* Ensure that a directory exists. */
static __noinline int fs_ensure_dir(const char *path)
{
    struct fs_dirent entry;
    if (fs_stat(path, &entry) == 0)
        return entry.type == FS_DIR_ENTRY_DIR ? 0 : -ENOTDIR;

    int result = fs_mkdir(path);
    return result == -EEXIST ? 0 : result;
}


/* Storage generations */
static uint16_t current_storage_generation = F5_INVALID_GENERATION_ID;
static uint32_t next_slot = 0;
static int64_t  last_rotate = 0;

#define GENERATION_FILE CONFIG_OAM_STORAGE_ROOT "/gen"

static __noinline int load_generation(uint16_t *generation)
{
    struct fs_dirent entry;
    struct fs_file_t file;
    uint16_t data;

    if (fs_stat(GENERATION_FILE, &entry) == -ENOENT)
        return -ENOENT;

    fs_file_t_init(&file);

    int error = fs_open(&file, GENERATION_FILE, FS_O_READ);
    if (error)
        return error;

    ssize_t read = fs_read(&file, &data, sizeof(data));
    fs_close(&file);

    if (read != (ssize_t) sizeof(data))
        return -EIO;

    *generation = F5_GEN_ID(data);
    return 0;
}

static __noinline int rotate_generation(int64_t timer)
{
    current_storage_generation = F5_GEN_ID(current_storage_generation + 1);
    next_slot = 0;
    last_rotate = timer;

    struct fs_file_t file;
    fs_file_t_init(&file);

    int error = fs_open(&file, GENERATION_FILE, FS_O_WRITE | FS_O_CREATE);
    if (error)
        return error;

    ssize_t written = fs_write(&file, &current_storage_generation, sizeof(current_storage_generation));
    error = fs_close(&file);

    return (written != (ssize_t) sizeof(current_storage_generation)) ? -EIO : error;
}

static __noinline void f5_next_id(uint16_t *generation, uint32_t *slot)
{
    int64_t now = k_uptime_get();

    if (current_storage_generation == F5_INVALID_GENERATION_ID) {
        if (fs_ensure_dir(CONFIG_OAM_STORAGE_ROOT))
            LOG_ERR_RATELIMIT("failed to create the storage root");

        int error = load_generation(&current_storage_generation);
        if (error && error != -ENOENT)
            LOG_WRN_RATELIMIT("storage is corrupted");

        /* Bump the generation, we don't persist next_slot */
        if (rotate_generation(now))
            LOG_ERR_RATELIMIT("failed to persist storage generation");
    } else if (now > last_rotate + CONFIG_OAM_STORAGE_ROTATION_MS || next_slot >= CONFIG_OAM_SLOTS_PER_GENERATION) {
        if (rotate_generation(now))
            LOG_ERR_RATELIMIT("failed to rotate storage generation");
    }

    *generation = F5_GEN_ID(current_storage_generation);
    *slot = next_slot++;
}


static __noinline int open_storage(struct fs_file_t *zfp, uint16_t generation, fs_mode_t flags)
{
    char buffer[sizeof(CONFIG_OAM_STORAGE_ROOT) + 5];
    snprintf(buffer, sizeof(buffer), CONFIG_OAM_STORAGE_ROOT "/%04X", F5_GEN_FILEID(generation));
    return fs_open(zfp, buffer, flags);
}

static __noinline int write_record(uint16_t generation, uint32_t slot, const struct f5_record *record)
{
    int error, close_error;
    struct fs_file_t file;

    fs_file_t_init(&file);
    error = open_storage(&file, generation, FS_O_WRITE | FS_O_CREATE);
    if (error)
        return error;

    error = fs_seek(&file, F5_GEN_SLOTID(slot) * CONFIG_OAM_RECORD_SIZE, FS_SEEK_SET);
    if (!error) {
        ssize_t written = fs_write(&file, record, sizeof(*record));
        if (written != (ssize_t) sizeof(*record))
            error = -EIO;
    }

    close_error = fs_close(&file);
    return error ?: close_error;
}

static __noinline int read_record(uint16_t generation, uint32_t slot, struct f5_record *record)
{
    int error, close_error;
    struct fs_file_t file;

    fs_file_t_init(&file);
    error = open_storage(&file, generation, FS_O_READ);
    if (error)
        return error;

    error = fs_seek(&file, F5_GEN_SLOTID(slot) * CONFIG_OAM_RECORD_SIZE, FS_SEEK_SET);
    if (!error) {
        ssize_t read = fs_read(&file, record, sizeof(*record));
        if (read != (ssize_t) sizeof(*record))
            error = -EIO;
    }

    close_error = fs_close(&file);
    return error ?: close_error;
}


/* ID packing/unpacking */
static void f5_id_encode(f5_id_t id, uint16_t generation, uint32_t slot)
{
    sys_put_be16(generation, &id[0]);
    sys_put_be16(F5_GEN_SLOTID(slot), &id[2]);
}

static void f5_id_decode(const f5_id_t id, uint16_t *generation, uint32_t *slot)
{
    *generation = sys_get_be16(&id[0]);
    *slot = sys_get_be16(&id[2]);
}

/* Cryptography */
static const char *suite_names[F5CS_COUNT] = {
    [F5CS_NULL] = "null",
    [F5CS_AES128CTR_CMAC] = "aes-128-ctr-cmac",
};

static const uint8_t key_lengths[F5CS_COUNT] = {
    [F5CS_NULL] = 0,
    [F5CS_AES128CTR_CMAC] = 16,
};

static int f5cs_aes_context_initialized = 0;
static struct mbedtls_aes_context f5cs_aes_context; /* Let's hope this stays single-threaded */

static __noinline int f5cs_encrypt(f5_suite_t suite, const uint8_t *key, size_t key_length, const uint8_t *plaintext, size_t data_length, const f5_id_t id, struct f5_record *record)
{
    int error;
    if (data_length > sizeof(f5_data_t)) {
        LOG_WRN("too much data for encrypted record");
        return -EINVAL;
    }

    if (suite >= F5CS_COUNT) {
invalid_suite:
        LOG_WRN("invalid cipher suite id %d", suite);
        return -EINVAL;
    }
    record->suite = suite;

    if (key_length != key_lengths[suite] || key_length > sizeof(f5_key_t)) {
        LOG_WRN("invalid key length %zu for cipher suite %s", key_length, suite_names[suite]);
        return -EINVAL;
    }

    memcpy(record->payload, key, key_length);

    uint8_t *ciphertext = &record->payload[key_length];
    switch (suite) {
        case F5CS_NULL:
            memcpy(ciphertext, plaintext, data_length);
            break;
        case F5CS_AES128CTR_CMAC:
            if (!f5cs_aes_context_initialized) {
                mbedtls_aes_init(&f5cs_aes_context);
                f5cs_aes_context_initialized = 1;
            }

            error = mbedtls_aes_setkey_enc(&f5cs_aes_context, key, key_length * 8);
            if (error) {
                LOG_WRN("key initialization failed: %d", error);
                return -EINVAL;
            }

            size_t offset = 0;
            uint8_t nonce_counter[16], stream_block[16];
            memset(nonce_counter, 0, sizeof(nonce_counter));
            memcpy(nonce_counter, id, sizeof(f5_id_t));
            error = mbedtls_aes_crypt_ctr(&f5cs_aes_context, data_length, &offset, nonce_counter, stream_block, plaintext, ciphertext);
            if (error) {
                LOG_WRN("encryption failed: %d", error);
                return -EIO;
            }
            break;
        default:
            goto invalid_suite;
    }

    memset(ciphertext + data_length, 0x6a, sizeof(record->payload) - key_length - data_length);
    return 0;
}


static struct mbedtls_cipher_context_t f5cs_cmac_context;

static __noinline int f5cs_check(const struct f5_record *record, const uint8_t *nonce, size_t nonce_length, f5_data_t ciphertext, f5_mac_t mac)
{
    int error;
    if (record->suite >= F5CS_COUNT) {
invalid_suite:
        LOG_WRN("invalid cipher suite id %d", record->suite);
        return -EINVAL;
    }

    const uint8_t *key = record->payload;
    const uint8_t *ct = &record->payload[key_lengths[record->suite]];

    memcpy(ciphertext, ct, sizeof(f5_data_t));

    switch (record->suite) {
        case F5CS_NULL:
            memset(mac, 0x6a, sizeof(f5_mac_t));
            break;
        case F5CS_AES128CTR_CMAC:
            /* mbedtls has no way to reuse the CMAC context, so there's no point in keeping init state. */
            error = -EINVAL;
            mbedtls_cipher_init(&f5cs_cmac_context);
            const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
            if (!info ||
                (error = mbedtls_cipher_setup(&f5cs_cmac_context, info)) ||
                (error = mbedtls_cipher_cmac_starts(&f5cs_cmac_context, key, key_lengths[record->suite] * 8))) {
                LOG_WRN("failed to configure cmac: %d", error);
                mbedtls_cipher_free(&f5cs_cmac_context);
                return -EIO;
            }

            uint8_t tag[16];
            if ((error = mbedtls_cipher_cmac_update(&f5cs_cmac_context, ciphertext, sizeof(f5_data_t))) ||
                (error = mbedtls_cipher_cmac_update(&f5cs_cmac_context, nonce, nonce_length)) ||
                (error = mbedtls_cipher_cmac_finish(&f5cs_cmac_context, tag))) {
                LOG_WRN("failed to compute cmac: %d", error);
                mbedtls_cipher_free(&f5cs_cmac_context);
                return -EIO;
            }

            memcpy(mac, tag, sizeof(f5_mac_t));
            mbedtls_cipher_free(&f5cs_cmac_context);
            break;
        default:
            goto invalid_suite;
    }

    return 0;
}

static __noinline void f5cs_generate_key(uint8_t *key, size_t key_length)
{
    /* Intentionally weak key generation */
    uint32_t seed = k_uptime_get_32();
    while (key_length) {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        key[--key_length] = (uint8_t) seed;
    }
}


/*
 * Deferred OAM work. The F5 operations block on FatFS/virtio, so running them
 * inline in f5_rx() -- on atm_rx_thread, the single dispatcher for every
 * circuit, at priority 0 with the VC lock held -- makes an OAM flood
 * head-of-line blocking for the whole router. Queue the cell instead.
 *
 * The queue is fixed-size and lossy on purpose: an unbounded handoff would just
 * move the pile-up into the heap, and OAM is best-effort (I.610).
 *
 * There is exactly ONE worker thread, and that is load-bearing: the storage
 * generation state and the shared f5cs_aes_context/f5cs_cmac_context have no
 * locking. Do not add a second worker without giving them one.
 */
#define F5_WORK_PRIORITY   6    /* below the userspace/CoAP handlers (5) and the reaper (4) */
#define F5_WORK_STACKSIZE  4096
#define F5_WORK_BACKLOG    256  /* cells; a legitimate client has one OAM request in flight per circuit,
                                   so size this to cover every circuit that can exist at once
                                   (MAX_HANDLERS / the DSLAM's per-connection cap) rather than 64 */

struct f5_work_item {
    /* The circuit the request arrived on; vc is an identity only, see atm_tx_circuit() */
    const struct atm_vc *vc;
    uint32_t vpi;
    uint32_t vci;
    uint8_t  sdu[ATM_SDU_SIZE];
};

K_MSGQ_DEFINE(f5_work_queue, sizeof(struct f5_work_item), F5_WORK_BACKLOG, 4);


/* Main operations */
static __noinline void f5_put(struct f5_work_item *work)
{
    uint16_t gen;
    uint32_t slot;
    int error;
    f5_id_t id;
    f5_key_t key;
    struct f5_record record;
    uint8_t *sdu = work->sdu;

    const struct f5_put_request *request = (struct f5_put_request *) &sdu[1];

    f5cs_generate_key(key, sizeof(key));

    f5_next_id(&gen, &slot);
    f5_id_encode(id, gen, slot);

    if ((error = f5cs_encrypt(F5CS_AES128CTR_CMAC, key, sizeof(key), request->data, sizeof(request->data), id, &record))) {
        LOG_ERR("failed to encrypt record %04X:%04X: %d", gen, slot, error);
        return;
    }

    if ((error = write_record(gen, slot, &record))) {
        LOG_ERR("failed to write record %04X:%04X: %d", gen, slot, error);
        return;
    }

    /* Send back the ID and key */
    struct f5_put_response *response = (struct f5_put_response *) &sdu[1];
    memcpy(response->id, id, sizeof(response->id));
    memcpy(response->key, key, sizeof(response->key));
    memset(response->reserved, 0x6a, sizeof(response->reserved));
    sdu[0] |= F5_OP_RESPONSE_BIT;
    f5_oam_update_edc(sdu);
    atm_tx_circuit(work->vc, work->vpi, work->vci, sdu, false, PtiEndToEndOamF5Cell);
}

static __noinline void f5_get(struct f5_work_item *work)
{
    uint16_t gen;
    uint32_t slot;
    int error;
    struct f5_get_buffer_overflow {
        /* Strict stack ordering for buffer overflow internals */
        uint8_t nonce[sizeof(f5_data_t) /* two bytes short of the nonce length */];
        struct f5_record record; /* ... which will overlap with the cipher suite */
    } buffer_overflow;
    uint8_t nonce_length;
    uint8_t *sdu = work->sdu;

    const struct f5_get_request *request = (struct f5_get_request *) &sdu[1];
    nonce_length = request->nonce_length;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
    _Static_assert(
        offsetof(struct f5_get_buffer_overflow, nonce[sizeof(request->nonce)])
        ==
        offsetof(struct f5_get_buffer_overflow, record.suite) + sizeof(buffer_overflow.record.suite),
        "Bad buffer overflow construction in f5_get"
    );
#pragma GCC diagnostic pop

    if (&request->nonce[nonce_length] > (uint8_t *) request + sizeof(*request)) {
        LOG_DBG("dropping overlong GET request"); 
        return;
    }

    f5_id_decode(request->id, &gen, &slot);
    if ((error = read_record(gen, slot, &buffer_overflow.record))) {
        if (error != -ENOENT)
            LOG_ERR("failed to read record %04X:%04X: %d", gen, slot, error);
        return;
    }

    memcpy(buffer_overflow.nonce, request->nonce, nonce_length);

    /* Send back the ciphertext and MAC */
    struct f5_get_response *response = (struct f5_get_response *) &sdu[1];
    if ((error = f5cs_check(&buffer_overflow.record, buffer_overflow.nonce, nonce_length, response->ct, response->mac))) {
        LOG_ERR("failed to check record %04X:%04X: %d", gen, slot, error);
        return;
    }
    sdu[0] |= F5_OP_RESPONSE_BIT;
    f5_oam_update_edc(sdu);
    atm_tx_circuit(work->vc, work->vpi, work->vci, sdu, false, PtiEndToEndOamF5Cell);
}


/* Parse and execute one queued OAM cell. Runs on f5_work_thread. */
static void f5_execute(struct f5_work_item *work)
{
    uint8_t *sdu = work->sdu;

    if (sdu[ATM_SDU_SIZE - 2] & 0xfc) {
        LOG_WRN("dropping OAM cell with reserved fields on %u:%u", work->vpi, work->vci);
        return;
    }

    uint16_t edc = ((uint16_t) (sdu[ATM_SDU_SIZE - 2] & 3) << 8) | sdu[ATM_SDU_SIZE - 1];
    uint16_t expected = f5_oam_edc(sdu);
    if (edc != expected) {
        LOG_WRN("dropping OAM cell with invalid EDC (0x%x, expected 0x%x) on %u:%u", edc, expected, work->vpi, work->vci);
        return;
    }

    uint8_t oam_type = sdu[0] >> 4;
    uint8_t function_type = sdu[0] & 0xf;
    if (oam_type != 0xf) {
        LOG_WRN("dropping unsupported OAM cell (type 0x%x) on %u:%u", oam_type, work->vpi, work->vci);
        return;
    }

    switch (function_type) {
        case F5_OP_PUT:
            f5_put(work);
            break;
        case F5_OP_GET:
            f5_get(work);
            break;
        default:
            LOG_WRN("unsupported system management function in OAM cell (0x%x) on %u:%u", function_type, work->vpi, work->vci);
            break;
    }
}

static void f5_work_task(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    struct f5_work_item work;
    while (true) {
        /* The only consumer of the queue, so the F5 state below stays single-threaded */
        k_msgq_get(&f5_work_queue, &work, K_FOREVER);
        f5_execute(&work);
    }
}

K_THREAD_DEFINE(f5_work_thread, F5_WORK_STACKSIZE, f5_work_task, NULL, NULL, NULL, F5_WORK_PRIORITY, 0, 0);


/* ATM management cell callback. Runs on atm_rx_thread with the VC lock held: never block here. */
void f5_rx(struct atm_vc *vc, uint8_t sdu[static ATM_SDU_SIZE], bool loss_priority, enum atm_pti pti)
{
    if (pti != PtiEndToEndOamF5Cell) {
        LOG_WRN("dropping non-F5 OAM cell (PTI %d on %d:%d)", pti, vc->vpi, vc->vci);
        return;
    }

    /* atm_rx_task() frees the cell buffer as soon as we return: copy by value */
    struct f5_work_item work = { .vc = vc, .vpi = vc->vpi, .vci = vc->vci };
    memcpy(work.sdu, sdu, sizeof(work.sdu));

    if (k_msgq_put(&f5_work_queue, &work, K_NO_WAIT) != 0) {
        /* Bounded on purpose: better to lose OAM cells than to stall dispatch */
        LOG_WRN_RATELIMIT("OAM backlog is full, dropping cell on %u:%u", work.vpi, work.vci);
    }
}
