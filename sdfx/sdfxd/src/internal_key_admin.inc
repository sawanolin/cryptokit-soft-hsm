/*
 * Included by internal_key_manager.c so the management helpers share the
 * private record format and password/KDF implementation without exporting
 * private-key material.
 */

static int disabled_marker_path(uint32_t type, uint32_t index,
                                char *path, size_t path_len)
{
    char key_path[512];
    int ret = internal_key_path(type, index, key_path, sizeof(key_path));
    if (ret != SDR_OK) {
        return ret;
    }
    int n = snprintf(path, path_len, "%s.disabled", key_path);
    return n > 0 && (size_t)n < path_len ? SDR_OK : SDR_FILEWERR;
}

static int internal_key_is_disabled(uint32_t type, uint32_t index)
{
    char marker[544];
    return disabled_marker_path(type, index, marker, sizeof(marker)) == SDR_OK &&
           access(marker, F_OK) == 0;
}

static int read_record(uint32_t type, uint32_t index, internal_key_record_t *record)
{
    int ret = read_record_raw(type, index, record);
    if (ret == SDR_OK && internal_key_is_disabled(type, index)) {
        secure_clear(record, sizeof(*record));
        return SDR_KEYNOTEXIST;
    }
    return ret;
}

static int write_record_atomic(uint32_t type, uint32_t index,
                               const internal_key_record_t *record)
{
    internal_key_record_t protected_record = *record;
    int ret = compute_record_integrity(&protected_record, protected_record.integrity);
    if (ret == SDR_OK) {
        ret = write_record_file(type, index, &protected_record, 0);
    }
    secure_clear(&protected_record, sizeof(protected_record));
    return ret;
}
int internal_key_admin_create(uint32_t type, uint32_t index,
                              const BYTE *password, uint32_t password_len)
{
    char path[512];
    int ret = internal_key_path(type, index, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }
    if (access(path, F_OK) == 0 || rsa_key_admin_exists(type, index)) {
        return SDR_FILEEXISTS;
    }
    return create_record(type, index, password, password_len);
}

int internal_key_admin_delete(uint32_t type, uint32_t index)
{
    char path[512];
    char marker[544];
    int ret = internal_key_path(type, index, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }
    if (disabled_marker_path(type, index, marker, sizeof(marker)) != SDR_OK) {
        return SDR_FILEWERR;
    }
    pthread_mutex_lock(&g_internal_key_mutex);
    if (unlink(path) != 0) {
        ret = errno == ENOENT ? SDR_KEYNOTEXIST : SDR_FILEWERR;
    } else {
        unlink(marker);
        ret = SDR_OK;
    }
    pthread_mutex_unlock(&g_internal_key_mutex);
    return ret;
}

int internal_key_admin_set_enabled(uint32_t type, uint32_t index, bool enabled)
{
    internal_key_record_t record;
    int ret = read_record_raw(type, index, &record);
    secure_clear(&record, sizeof(record));
    if (ret != SDR_OK) {
        return ret;
    }
    char marker[544];
    ret = disabled_marker_path(type, index, marker, sizeof(marker));
    if (ret != SDR_OK) {
        return ret;
    }
    pthread_mutex_lock(&g_internal_key_mutex);
    if (enabled) {
        if (unlink(marker) != 0 && errno != ENOENT) {
            ret = SDR_FILEWERR;
        } else {
            ret = SDR_OK;
        }
    } else {
        int fd = open(marker, O_WRONLY | O_CREAT, 0600);
        if (fd < 0 || (fsync(fd) != 0 && errno != EINVAL)) {
            ret = SDR_FILEWERR;
        } else {
            ret = SDR_OK;
        }
        if (fd >= 0) {
            close(fd);
        }
    }
    pthread_mutex_unlock(&g_internal_key_mutex);
    return ret;
}

int internal_key_admin_export_public(uint32_t type, uint32_t index,
                                     ECCrefPublicKey *public_key)
{
    if (public_key == NULL) {
        return SDR_OUTARGERR;
    }
    internal_key_record_t record;
    int ret = read_record_raw(type, index, &record);
    if (ret == SDR_OK) {
        memcpy(public_key, &record.public_key, sizeof(*public_key));
    }
    secure_clear(&record, sizeof(record));
    return ret;
}

int internal_key_admin_change_password(uint32_t type, uint32_t index,
                                       const BYTE *old_password,
                                       uint32_t old_password_len,
                                       const BYTE *new_password,
                                       uint32_t new_password_len)
{
    if (old_password_len > INTERNAL_PASSWORD_MAX || new_password_len > INTERNAL_PASSWORD_MAX ||
        (old_password_len != 0 && (old_password == NULL || old_password_len < 8)) ||
        (new_password_len != 0 && (new_password == NULL || new_password_len < 8))) {
        return SDR_INARGERR;
    }

    internal_key_record_t record;
    BYTE old_derived[32] = {0};
    BYTE new_derived[32] = {0};
    BYTE verifier[32] = {0};
    BYTE private_scalar[32] = {0};

    pthread_mutex_lock(&g_internal_key_mutex);
    int ret = read_record_raw(type, index, &record);
    if (ret == SDR_OK && record_is_passwordless(&record)) {
        ret = old_password_len == 0
            ? derive_device_secret(type, index, record.salt, old_derived)
            : SDR_PRKRERR;
    } else if (ret == SDR_OK) {
        ret = derive_password(old_password, old_password_len, record.salt, old_derived);
        if (ret == SDR_OK) ret = make_verifier(old_derived, verifier);
        if (ret == SDR_OK && !constant_time_equal(verifier, record.verifier, sizeof(verifier))) {
            ret = SDR_PRKRERR;
        }
    }
    if (ret == SDR_OK) {
        ULONG length = sizeof(private_scalar);
        ret = crypto_symmetric_decrypt(SGD_SM4_CTR, old_derived, 16,
                                       record.salt, sizeof(record.salt),
                                       record.encrypted_private,
                                       sizeof(record.encrypted_private),
                                       private_scalar, &length);
        if (ret == SDR_OK && length != sizeof(private_scalar)) ret = SDR_KEYERR;
    }
    if (ret == SDR_OK) ret = crypto_generate_random(sizeof(record.salt), record.salt);
    if (ret == SDR_OK) {
        ret = new_password_len == 0
            ? derive_device_secret(type, index, record.salt, new_derived)
            : derive_password(new_password, new_password_len, record.salt, new_derived);
    }
    memset(record.verifier, 0, sizeof(record.verifier));
    if (ret == SDR_OK && new_password_len != 0) ret = make_verifier(new_derived, record.verifier);
    if (ret == SDR_OK) {
        ULONG length = sizeof(record.encrypted_private);
        ret = crypto_symmetric_encrypt(SGD_SM4_CTR, new_derived, 16,
                                       record.salt, sizeof(record.salt),
                                       private_scalar, sizeof(private_scalar),
                                       record.encrypted_private, &length);
        if (ret == SDR_OK && length != sizeof(record.encrypted_private)) ret = SDR_KEYERR;
    }
    if (ret == SDR_OK) ret = write_record_atomic(type, index, &record);
    pthread_mutex_unlock(&g_internal_key_mutex);

    secure_clear(&record, sizeof(record));
    secure_clear(old_derived, sizeof(old_derived));
    secure_clear(new_derived, sizeof(new_derived));
    secure_clear(verifier, sizeof(verifier));
    secure_clear(private_scalar, sizeof(private_scalar));
    return ret;
}
static void fingerprint_public_key(const ECCrefPublicKey *public_key,
                                   char fingerprint[65])
{
    BYTE digest[32] = {0};
    ULONG digest_len = sizeof(digest);
    static const char hex[] = "0123456789abcdef";
    if (crypto_hash_digest(SGD_SM3, (const BYTE *)public_key,
                           sizeof(*public_key), digest, &digest_len) != SDR_OK ||
        digest_len != sizeof(digest)) {
        fingerprint[0] = '\0';
        return;
    }
    for (size_t i = 0; i < sizeof(digest); ++i) {
        fingerprint[i * 2] = hex[digest[i] >> 4];
        fingerprint[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    fingerprint[64] = '\0';
    secure_clear(digest, sizeof(digest));
}

int internal_key_admin_integrity_init(void)
{
    BYTE key[32] = {0};
    int ret = ensure_device_key(key);
    secure_clear(key, sizeof(key));
    return ret;
}

int internal_key_admin_verify(uint32_t type, uint32_t index)
{
    internal_key_record_t record;
    int ret = read_record_raw(type, index, &record);
    secure_clear(&record, sizeof(record));
    return ret;
}

int internal_key_admin_reindex(uint32_t type, uint32_t old_index, uint32_t new_index)
{
    if (old_index == new_index || old_index == 0 || new_index == 0 ||
        old_index > INTERNAL_KEY_INDEX_MAX || new_index > INTERNAL_KEY_INDEX_MAX) {
        return SDR_INARGERR;
    }
    char old_path[512], new_path[512];
    if (internal_key_path(type, old_index, old_path, sizeof(old_path)) != SDR_OK ||
        internal_key_path(type, new_index, new_path, sizeof(new_path)) != SDR_OK) {
        return SDR_INARGERR;
    }
    pthread_mutex_lock(&g_internal_key_mutex);
    if (access(new_path, F_OK) == 0) {
        pthread_mutex_unlock(&g_internal_key_mutex);
        return SDR_FILEEXISTS;
    }
    internal_key_record_t record;
    int ret = read_record_raw(type, old_index, &record);
    BYTE scalar[32] = {0}, old_secret[32] = {0}, new_secret[32] = {0};
    if (ret == SDR_OK && record_is_passwordless(&record)) {
        ret = derive_device_secret(type, old_index, record.salt, old_secret);
        if (ret == SDR_OK) {
            ULONG length = sizeof(scalar);
            ret = crypto_symmetric_decrypt(SGD_SM4_CTR, old_secret, 16,
                    record.salt, sizeof(record.salt), record.encrypted_private,
                    sizeof(record.encrypted_private), scalar, &length);
            if (ret == SDR_OK && length != sizeof(scalar)) ret = SDR_KEYERR;
        }
        if (ret == SDR_OK) ret = derive_device_secret(type, new_index, record.salt, new_secret);
        if (ret == SDR_OK) {
            ULONG length = sizeof(record.encrypted_private);
            ret = crypto_symmetric_encrypt(SGD_SM4_CTR, new_secret, 16,
                    record.salt, sizeof(record.salt), scalar, sizeof(scalar),
                    record.encrypted_private, &length);
            if (ret == SDR_OK && length != sizeof(record.encrypted_private)) ret = SDR_KEYERR;
        }
    }
    if (ret == SDR_OK) {
        record.index = new_index;
        ret = compute_record_integrity(&record, record.integrity);
    }
    if (ret == SDR_OK) ret = write_record_file(type, new_index, &record, 1);
    if (ret == SDR_OK) {
        char old_disabled[544] = {0}, new_disabled[544] = {0};
        int disabled = internal_key_is_disabled(type, old_index);
        if (disabled_marker_path(type, old_index, old_disabled, sizeof(old_disabled)) != SDR_OK ||
            disabled_marker_path(type, new_index, new_disabled, sizeof(new_disabled)) != SDR_OK) {
            ret = SDR_FILEWERR;
        } else if (disabled) {
            int fd = open(new_disabled, O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (fd < 0) ret = SDR_FILEWERR; else { fsync(fd); close(fd); }
        }
        if (ret == SDR_OK) {
            unlink(old_path);
            unlink(old_disabled);
        } else {
            unlink(new_path);
            if (new_disabled[0] != '\0') {
                unlink(new_disabled);
            }
        }
    }
    pthread_mutex_unlock(&g_internal_key_mutex);
    secure_clear(&record, sizeof(record));
    secure_clear(scalar, sizeof(scalar));
    secure_clear(old_secret, sizeof(old_secret));
    secure_clear(new_secret, sizeof(new_secret));
    return ret;
}
int internal_key_admin_list(BYTE *output, uint32_t *output_len,
                            uint32_t *key_count)
{
    if (output == NULL || output_len == NULL || *output_len < 3) {
        return SDR_INARGERR;
    }
    size_t capacity = *output_len;
    size_t used = 0;
    uint32_t count = 0;
    output[used++] = '[';

    pthread_mutex_lock(&g_internal_key_mutex);
    for (uint32_t type = SDFX_INTERNAL_KEY_SIGN;
         type <= SDFX_INTERNAL_KEY_ENC; ++type) {
        for (uint32_t index = 1; index <= INTERNAL_KEY_INDEX_MAX; ++index) {
            internal_key_record_t record;
            int ret = read_record_raw(type, index, &record);
            if (ret == SDR_KEYNOTEXIST) {
                continue;
            }
            if (ret != SDR_OK) {
                pthread_mutex_unlock(&g_internal_key_mutex);
                return ret;
            }
            char fingerprint[65];
            fingerprint_public_key(&record.public_key, fingerprint);
            char path[512];
            struct stat st;
            long long created_at = 0;
            if (internal_key_path(type, index, path, sizeof(path)) == SDR_OK &&
                stat(path, &st) == 0) {
                created_at = (long long)st.st_mtime;
            }
            int n = snprintf((char *)output + used, capacity - used,
                "%s{\"type\":\"%s\",\"index\":%u,\"algorithm\":\"SM2\","
                "\"purpose\":\"%s\",\"bits\":256,\"enabled\":%s,"
                "\"integrity\":true,\"password_protected\":%s,"
                "\"created_at\":%lld,\"fingerprint\":\"%s\"}",
                count == 0 ? "" : ",",
                type == SDFX_INTERNAL_KEY_SIGN ? "sign" : "enc",
                index,
                type == SDFX_INTERNAL_KEY_SIGN ? "signature" : "encryption",
                internal_key_is_disabled(type, index) ? "false" : "true",
                record_is_passwordless(&record) ? "false" : "true",
                created_at, fingerprint);
            secure_clear(&record, sizeof(record));
            if (n < 0 || (size_t)n >= capacity - used) {
                pthread_mutex_unlock(&g_internal_key_mutex);
                return SDR_NOBUFFER;
            }
            used += (size_t)n;
            count++;
        }
    }
    pthread_mutex_unlock(&g_internal_key_mutex);

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


