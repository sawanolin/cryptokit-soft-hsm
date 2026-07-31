/* KEK lifecycle and device-rooted HMAC-SM3 integrity management. */

#define KEK_RECORD_MAGIC   0x4B454B32U
#define KEK_RECORD_VERSION 2U
#define KEK_KEY_BITS       128U
#define KEK_KEY_BYTES      16U

typedef struct kek_record {
    uint32_t magic;
    uint32_t version;
    uint32_t index;
    uint32_t algorithm;
    uint32_t bits;
    BYTE key[KEK_KEY_BYTES];
    BYTE integrity[32];
} kek_record_t;

static int kek_path(uint32_t index, char *path, size_t path_len)
{
    if (index == 0 || index > 1024 || path == NULL) {
        return SDR_INARGERR;
    }
    int n = snprintf(path, path_len, "%s/keys/kek/%08u.bin",
                     storage_root(), index);
    return n > 0 && (size_t)n < path_len ? SDR_OK : SDR_FILEWERR;
}

static int kek_disabled_path(uint32_t index, char *path, size_t path_len)
{
    char record_path[512];
    if (kek_path(index, record_path, sizeof(record_path)) != SDR_OK) {
        return SDR_INARGERR;
    }
    int n = snprintf(path, path_len, "%s.disabled", record_path);
    return n > 0 && (size_t)n < path_len ? SDR_OK : SDR_FILEWERR;
}

static int kek_is_disabled(uint32_t index)
{
    char path[544];
    return kek_disabled_path(index, path, sizeof(path)) == SDR_OK &&
           access(path, F_OK) == 0;
}

static int kek_constant_time_equal(const BYTE *left, const BYTE *right, size_t len)
{
    BYTE difference = 0;
    for (size_t i = 0; i < len; ++i) {
        difference |= left[i] ^ right[i];
    }
    return difference == 0;
}

static int kek_compute_integrity(const kek_record_t *record, BYTE output[32])
{
    BYTE data[offsetof(kek_record_t, integrity) + 4];
    memcpy(data, record, offsetof(kek_record_t, integrity));
    data[sizeof(data) - 4] = (BYTE)(record->index >> 24);
    data[sizeof(data) - 3] = (BYTE)(record->index >> 16);
    data[sizeof(data) - 2] = (BYTE)(record->index >> 8);
    data[sizeof(data) - 1] = (BYTE)record->index;
    int ret = device_integrity_hmac(data, (uint32_t)sizeof(data), output);
    secure_clear(data, sizeof(data));
    return ret;
}

static int kek_write_record_locked(uint32_t index, const kek_record_t *record,
                                   int exclusive)
{
    char path[512];
    char temporary[560];
    int ret = kek_path(index, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }
    if (exclusive && access(path, F_OK) == 0) {
        return SDR_FILEEXISTS;
    }
    int n = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld",
                     path, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(temporary)) {
        return SDR_FILEWERR;
    }
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL |
                  O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return SDR_FILEWERR;
    }
    ssize_t written = write(fd, record, sizeof(*record));
    if (written != (ssize_t)sizeof(*record) || fsync(fd) != 0) {
        close(fd);
        unlink(temporary);
        return SDR_FILEWERR;
    }
    close(fd);
    if (exclusive && access(path, F_OK) == 0) {
        unlink(temporary);
        return SDR_FILEEXISTS;
    }
    if (rename(temporary, path) != 0) {
        unlink(temporary);
        return SDR_FILEWERR;
    }
    return SDR_OK;
}

static int kek_read_record_locked(uint32_t index, kek_record_t *record)
{
    if (record == NULL) {
        return SDR_INARGERR;
    }
    char path[512];
    int ret = kek_path(index, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? SDR_KEYNOTEXIST : SDR_KEYERR;
    }

    BYTE raw[sizeof(kek_record_t)] = {0};
    size_t used = 0;
    while (used < sizeof(raw)) {
        ssize_t got = read(fd, raw + used, sizeof(raw) - used);
        if (got < 0) {
            close(fd);
            secure_clear(raw, sizeof(raw));
            return SDR_KEYERR;
        }
        if (got == 0) {
            break;
        }
        used += (size_t)got;
    }
    BYTE trailing = 0;
    ssize_t extra = read(fd, &trailing, 1);
    close(fd);
    if (extra != 0) {
        secure_clear(raw, sizeof(raw));
        return SDR_KEYERR;
    }

    memset(record, 0, sizeof(*record));
    if (used == KEK_KEY_BYTES) {
        /* Upgrade the legacy raw 16-byte KEK record in place. */
        record->magic = KEK_RECORD_MAGIC;
        record->version = KEK_RECORD_VERSION;
        record->index = index;
        record->algorithm = SGD_SM4_ECB;
        record->bits = KEK_KEY_BITS;
        memcpy(record->key, raw, KEK_KEY_BYTES);
        ret = kek_compute_integrity(record, record->integrity);
        if (ret == SDR_OK) {
            ret = kek_write_record_locked(index, record, 0);
        }
    } else if (used != sizeof(*record)) {
        ret = SDR_KEYERR;
    } else {
        memcpy(record, raw, sizeof(*record));
        if (record->magic != KEK_RECORD_MAGIC ||
            record->version != KEK_RECORD_VERSION ||
            record->index != index ||
            record->algorithm != SGD_SM4_ECB ||
            record->bits != KEK_KEY_BITS) {
            ret = SDR_KEYERR;
        } else {
            BYTE expected[32] = {0};
            ret = kek_compute_integrity(record, expected);
            if (ret == SDR_OK && !kek_constant_time_equal(
                    expected, record->integrity, sizeof(expected))) {
                ret = SDR_KEYERR;
            }
            secure_clear(expected, sizeof(expected));
        }
    }
    secure_clear(raw, sizeof(raw));
    if (ret != SDR_OK) {
        secure_clear(record, sizeof(*record));
    }
    return ret;
}

static int load_kek(uint32_t index, BYTE kek[16])
{
    if (index == 0 || index > 1024 || kek == NULL) {
        return SDR_KEYNOTEXIST;
    }
    if (ensure_storage_tree() != SDR_OK) {
        return SDR_FILEWERR;
    }
    pthread_mutex_lock(&g_storage_mutex);
    int ret = kek_is_disabled(index) ? SDR_KEYNOTEXIST : SDR_OK;
    kek_record_t record;
    if (ret == SDR_OK) {
        ret = kek_read_record_locked(index, &record);
    }
    if (ret == SDR_OK) {
        memcpy(kek, record.key, KEK_KEY_BYTES);
    } else {
        secure_clear(kek, KEK_KEY_BYTES);
    }
    secure_clear(&record, sizeof(record));
    pthread_mutex_unlock(&g_storage_mutex);
    return ret;
}

int kek_admin_create(uint32_t index)
{
    if (ensure_storage_tree() != SDR_OK) {
        return SDR_FILEWERR;
    }
    if (index == 0 || index > 1024) {
        return SDR_INARGERR;
    }

    kek_record_t record;
    memset(&record, 0, sizeof(record));
    record.magic = KEK_RECORD_MAGIC;
    record.version = KEK_RECORD_VERSION;
    record.index = index;
    record.algorithm = SGD_SM4_ECB;
    record.bits = KEK_KEY_BITS;
    int ret = crypto_generate_random(sizeof(record.key), record.key);
    if (ret == SDR_OK) {
        ret = kek_compute_integrity(&record, record.integrity);
    }

    pthread_mutex_lock(&g_storage_mutex);
    if (ret == SDR_OK) {
        ret = kek_write_record_locked(index, &record, 1);
    }
    if (ret == SDR_OK) {
        char disabled[544];
        if (kek_disabled_path(index, disabled, sizeof(disabled)) == SDR_OK) {
            unlink(disabled);
        }
    }
    pthread_mutex_unlock(&g_storage_mutex);
    secure_clear(&record, sizeof(record));
    return ret;
}

int kek_admin_delete(uint32_t index)
{
    char path[512];
    char disabled[544];
    if (kek_path(index, path, sizeof(path)) != SDR_OK ||
        kek_disabled_path(index, disabled, sizeof(disabled)) != SDR_OK) {
        return SDR_INARGERR;
    }
    pthread_mutex_lock(&g_storage_mutex);
    int ret;
    if (unlink(path) != 0) {
        ret = errno == ENOENT ? SDR_KEYNOTEXIST : SDR_FILEWERR;
    } else {
        unlink(disabled);
        ret = SDR_OK;
    }
    pthread_mutex_unlock(&g_storage_mutex);
    return ret;
}

int kek_admin_set_enabled(uint32_t index, bool enabled)
{
    char disabled[544];
    if (kek_disabled_path(index, disabled, sizeof(disabled)) != SDR_OK) {
        return SDR_INARGERR;
    }
    pthread_mutex_lock(&g_storage_mutex);
    kek_record_t record;
    int ret = kek_read_record_locked(index, &record);
    secure_clear(&record, sizeof(record));
    if (ret == SDR_OK && enabled) {
        if (unlink(disabled) != 0 && errno != ENOENT) {
            ret = SDR_FILEWERR;
        }
    } else if (ret == SDR_OK) {
        int fd = open(disabled, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || fsync(fd) != 0) {
            ret = SDR_FILEWERR;
        }
        if (fd >= 0) {
            close(fd);
        }
    }
    pthread_mutex_unlock(&g_storage_mutex);
    return ret;
}

int kek_admin_verify(uint32_t index)
{
    if (index == 0 || index > 1024) {
        return SDR_INARGERR;
    }
    pthread_mutex_lock(&g_storage_mutex);
    kek_record_t record;
    int ret = kek_read_record_locked(index, &record);
    secure_clear(&record, sizeof(record));
    pthread_mutex_unlock(&g_storage_mutex);
    return ret;
}

int kek_admin_list(BYTE *output, uint32_t *output_len, uint32_t *key_count)
{
    if (output == NULL || output_len == NULL || *output_len < 3) {
        return SDR_INARGERR;
    }
    size_t capacity = *output_len;
    size_t used = 0;
    uint32_t count = 0;
    output[used++] = '[';

    pthread_mutex_lock(&g_storage_mutex);
    for (uint32_t index = 1; index <= 1024; ++index) {
        char path[512];
        if (kek_path(index, path, sizeof(path)) != SDR_OK ||
            access(path, F_OK) != 0) {
            continue;
        }
        kek_record_t record;
        int ret = kek_read_record_locked(index, &record);
        if (ret != SDR_OK) {
            secure_clear(&record, sizeof(record));
            pthread_mutex_unlock(&g_storage_mutex);
            return ret;
        }

        BYTE digest[32] = {0};
        ULONG digest_len = sizeof(digest);
        ret = crypto_hash_digest(SGD_SM3, record.key, sizeof(record.key),
                                 digest, &digest_len);
        secure_clear(&record, sizeof(record));
        if (ret != SDR_OK || digest_len != sizeof(digest)) {
            secure_clear(digest, sizeof(digest));
            pthread_mutex_unlock(&g_storage_mutex);
            return SDR_KEYERR;
        }
        static const char hex[] = "0123456789abcdef";
        char fingerprint[65];
        for (size_t i = 0; i < sizeof(digest); ++i) {
            fingerprint[i * 2] = hex[digest[i] >> 4];
            fingerprint[i * 2 + 1] = hex[digest[i] & 0x0f];
        }
        fingerprint[64] = '\0';
        secure_clear(digest, sizeof(digest));

        struct stat st;
        long long created_at = stat(path, &st) == 0
            ? (long long)st.st_mtime : 0;
        int n = snprintf((char *)output + used, capacity - used,
            "%s{\"type\":\"kek\",\"index\":%u,\"algorithm\":\"SM4\","
            "\"purpose\":\"key-encryption\",\"bits\":128,\"enabled\":%s,"
            "\"integrity\":true,\"created_at\":%lld,\"fingerprint\":\"%s\"}",
            count == 0 ? "" : ",", index,
            kek_is_disabled(index) ? "false" : "true",
            created_at, fingerprint);
        if (n < 0 || (size_t)n >= capacity - used) {
            pthread_mutex_unlock(&g_storage_mutex);
            return SDR_NOBUFFER;
        }
        used += (size_t)n;
        ++count;
    }
    pthread_mutex_unlock(&g_storage_mutex);

    if (used + 2 > capacity) {
        return SDR_NOBUFFER;
    }
    output[used++] = ']';
    output[used] = '\0';
    *output_len = (uint32_t)used;
    if (key_count != NULL) {
        *key_count = count;
    }
    return SDR_OK;
}
