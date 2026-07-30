/* KEK lifecycle management.  Key bytes never leave this translation unit. */

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

int kek_admin_create(uint32_t index)
{
    if (ensure_storage_tree() != SDR_OK) {
        return SDR_FILEWERR;
    }
    char path[512];
    int ret = kek_path(index, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }

    BYTE key[16] = {0};
    ret = crypto_generate_random(sizeof(key), key);
    if (ret != SDR_OK) {
        return ret;
    }

    pthread_mutex_lock(&g_storage_mutex);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        ret = errno == EEXIST ? SDR_FILEEXISTS : SDR_FILEWERR;
    } else {
        ssize_t written = write(fd, key, sizeof(key));
        ret = written == (ssize_t)sizeof(key) && fsync(fd) == 0
            ? SDR_OK : SDR_FILEWERR;
        close(fd);
        if (ret != SDR_OK) {
            unlink(path);
        } else {
            char disabled[544];
            if (kek_disabled_path(index, disabled, sizeof(disabled)) == SDR_OK) {
                unlink(disabled);
            }
        }
    }
    pthread_mutex_unlock(&g_storage_mutex);
    secure_clear(key, sizeof(key));
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
    char path[512];
    char disabled[544];
    if (kek_path(index, path, sizeof(path)) != SDR_OK ||
        kek_disabled_path(index, disabled, sizeof(disabled)) != SDR_OK) {
        return SDR_INARGERR;
    }
    pthread_mutex_lock(&g_storage_mutex);
    int ret = SDR_OK;
    if (access(path, F_OK) != 0) {
        ret = SDR_KEYNOTEXIST;
    } else if (enabled) {
        if (unlink(disabled) != 0 && errno != ENOENT) {
            ret = SDR_FILEWERR;
        }
    } else {
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
        if (kek_path(index, path, sizeof(path)) != SDR_OK) {
            continue;
        }
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            continue;
        }
        BYTE key[16] = {0};
        BYTE digest[32] = {0};
        ssize_t got = read(fd, key, sizeof(key));
        BYTE trailing = 0;
        ssize_t extra = read(fd, &trailing, 1);
        close(fd);
        if (got != (ssize_t)sizeof(key) || extra != 0) {
            secure_clear(key, sizeof(key));
            pthread_mutex_unlock(&g_storage_mutex);
            return SDR_KEYERR;
        }
        ULONG digest_len = sizeof(digest);
        int ret = crypto_hash_digest(SGD_SM3, key, sizeof(key),
                                     digest, &digest_len);
        secure_clear(key, sizeof(key));
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
            "\"created_at\":%lld,\"fingerprint\":\"%s\"}",
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
