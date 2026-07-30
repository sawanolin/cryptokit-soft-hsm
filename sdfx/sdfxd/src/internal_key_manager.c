/*
 * Internal SM2 key storage and session-scoped private-key permissions.
 *
 * Private scalars are encrypted at rest with a password-derived SM4 key.
 * Passwords and derived secrets never leave the daemon.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "daemon_internal.h"

#define INTERNAL_KEY_MAGIC       0x534D324BU
#define INTERNAL_KEY_VERSION     2U
#define INTERNAL_KEY_INDEX_MAX   1024U
#define INTERNAL_PASSWORD_MAX    256U
#define INTERNAL_KDF_ROUNDS      20000U

typedef struct internal_key_record {
    uint32_t magic;
    uint32_t version;
    uint32_t type;
    uint32_t index;
    ECCrefPublicKey public_key;
    BYTE salt[16];
    BYTE verifier[32];
    BYTE encrypted_private[32];
    BYTE integrity[32];
} internal_key_record_t;

static pthread_mutex_t g_internal_key_mutex = PTHREAD_MUTEX_INITIALIZER;

static void secure_clear(void *ptr, size_t len)
{
    volatile BYTE *p = (volatile BYTE *)ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
}

static int constant_time_equal(const BYTE *left, const BYTE *right, size_t len)
{
    BYTE diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= left[i] ^ right[i];
    }
    return diff == 0;
}

static const char *storage_root(void)
{
    const char *root = getenv("SDFX_DATA_DIR");
    return root != NULL && root[0] != '\0' ? root : "/var/lib/sdfx";
}

static int ensure_dir(const char *path)
{
    if (mkdir(path, 0700) == 0 || errno == EEXIST) {
        return SDR_OK;
    }
    return SDR_FILEWERR;
}

static int ensure_internal_key_tree(void)
{
    char path[512];
    const char *parts[] = {"/keys", "/keys/sm2", "/keys/sm2/sign", "/keys/sm2/enc"};

    if (ensure_dir(storage_root()) != SDR_OK) {
        return SDR_FILEWERR;
    }
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        int n = snprintf(path, sizeof(path), "%s%s", storage_root(), parts[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) || ensure_dir(path) != SDR_OK) {
            return SDR_FILEWERR;
        }
    }
    return SDR_OK;
}

static int ensure_device_key(BYTE key[32])
{
    char master[512];
    char path[544];
    int n = snprintf(master, sizeof(master), "%s/master", storage_root());
    if (n <= 0 || (size_t)n >= sizeof(master) || ensure_dir(storage_root()) != SDR_OK ||
        ensure_dir(master) != SDR_OK) {
        return SDR_FILEWERR;
    }
    n = snprintf(path, sizeof(path), "%s/device-integrity.key", master);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        return SDR_FILEWERR;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT) {
        BYTE generated[32] = {0};
        int ret = crypto_generate_random(sizeof(generated), generated);
        if (ret != SDR_OK) {
            return ret;
        }
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0400);
        if (fd >= 0) {
            ssize_t written = write(fd, generated, sizeof(generated));
            ret = written == (ssize_t)sizeof(generated) && fsync(fd) == 0
                ? SDR_OK : SDR_FILEWERR;
            close(fd);
            if (ret != SDR_OK) {
                unlink(path);
                secure_clear(generated, sizeof(generated));
                return ret;
            }
        } else if (errno != EEXIST) {
            secure_clear(generated, sizeof(generated));
            return SDR_FILEWERR;
        }
        secure_clear(generated, sizeof(generated));
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    }
    if (fd < 0) {
        return SDR_KEYERR;
    }
    struct stat st;
    ssize_t got = read(fd, key, 32);
    BYTE extra = 0;
    ssize_t trailing = read(fd, &extra, 1);
    int valid = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && got == 32 && trailing == 0;
    close(fd);
    if (!valid) {
        secure_clear(key, 32);
        return SDR_KEYERR;
    }
    return SDR_OK;
}

static int hmac_sm3(const BYTE key[32], const BYTE *data, size_t data_len, BYTE output[32])
{
    BYTE ipad[64];
    BYTE opad[64];
    BYTE inner[32];
    size_t buffer_len = 64 + data_len;
    if (buffer_len < 96) {
        buffer_len = 96;
    }
    BYTE *buffer = malloc(buffer_len);
    if (buffer == NULL) {
        return SDR_NOBUFFER;
    }
    memset(ipad, 0x36, sizeof(ipad));
    memset(opad, 0x5c, sizeof(opad));
    for (size_t i = 0; i < 32; ++i) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    memcpy(buffer, ipad, 64);
    memcpy(buffer + 64, data, data_len);
    ULONG length = sizeof(inner);
    int ret = crypto_hash_digest(SGD_SM3, buffer, (ULONG)(64 + data_len), inner, &length);
    if (ret == SDR_OK && length == sizeof(inner)) {
        memcpy(buffer, opad, 64);
        memcpy(buffer + 64, inner, sizeof(inner));
        length = 32;
        ret = crypto_hash_digest(SGD_SM3, buffer, 96, output, &length);
        if (ret == SDR_OK && length != 32) {
            ret = SDR_KEYERR;
        }
    }
    secure_clear(buffer, buffer_len);
    free(buffer);
    secure_clear(ipad, sizeof(ipad));
    secure_clear(opad, sizeof(opad));
    secure_clear(inner, sizeof(inner));
    return ret;
}

static int derive_device_secret(uint32_t type, uint32_t index,
                                const BYTE salt[16], BYTE derived[32])
{
    BYTE key[32] = {0};
    BYTE context[48] = "SDFX-SM2-NO-PASSWORD";
    context[24] = (BYTE)(type >> 24);
    context[25] = (BYTE)(type >> 16);
    context[26] = (BYTE)(type >> 8);
    context[27] = (BYTE)type;
    context[28] = (BYTE)(index >> 24);
    context[29] = (BYTE)(index >> 16);
    context[30] = (BYTE)(index >> 8);
    context[31] = (BYTE)index;
    memcpy(context + 32, salt, 16);
    int ret = ensure_device_key(key);
    if (ret == SDR_OK) {
        ret = hmac_sm3(key, context, sizeof(context), derived);
    }
    secure_clear(key, sizeof(key));
    secure_clear(context, sizeof(context));
    return ret;
}

static int record_is_passwordless(const internal_key_record_t *record)
{
    BYTE value = 0;
    for (size_t i = 0; i < sizeof(record->verifier); ++i) {
        value |= record->verifier[i];
    }
    return value == 0;
}
static int internal_key_path(uint32_t type, uint32_t index, char *path, size_t path_len)
{
    if ((type != SDFX_INTERNAL_KEY_SIGN && type != SDFX_INTERNAL_KEY_ENC) ||
        index == 0 || index > INTERNAL_KEY_INDEX_MAX || path == NULL) {
        return SDR_INARGERR;
    }
    int n = snprintf(path, path_len, "%s/keys/sm2/%s/%08u.key", storage_root(),
                     type == SDFX_INTERNAL_KEY_SIGN ? "sign" : "enc", index);
    return n > 0 && (size_t)n < path_len ? SDR_OK : SDR_FILEWERR;
}

static int compute_record_integrity(const internal_key_record_t *record, BYTE output[32])
{
    BYTE key[32] = {0};
    BYTE data[offsetof(internal_key_record_t, integrity) + 4];
    memcpy(data, record, offsetof(internal_key_record_t, integrity));
    data[sizeof(data) - 4] = (BYTE)(record->index >> 24);
    data[sizeof(data) - 3] = (BYTE)(record->index >> 16);
    data[sizeof(data) - 2] = (BYTE)(record->index >> 8);
    data[sizeof(data) - 1] = (BYTE)record->index;
    int ret = ensure_device_key(key);
    if (ret == SDR_OK) {
        ret = hmac_sm3(key, data, sizeof(data), output);
    }
    secure_clear(key, sizeof(key));
    secure_clear(data, sizeof(data));
    return ret;
}

static int write_record_file(uint32_t type, uint32_t index,
                             const internal_key_record_t *record, int exclusive)
{
    char path[512];
    char temporary[560];
    int ret = internal_key_path(type, index, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }
    int n = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(temporary)) {
        return SDR_FILEWERR;
    }
    int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW;
    int fd = open(temporary, flags, 0600);
    if (fd < 0) {
        return SDR_FILEWERR;
    }
    ssize_t written = write(fd, record, sizeof(*record));
    if (written != (ssize_t)sizeof(*record) || fsync(fd) != 0) {
        close(fd); unlink(temporary); return SDR_FILEWERR;
    }
    close(fd);
    if (exclusive && access(path, F_OK) == 0) {
        unlink(temporary); return SDR_FILEEXISTS;
    }
    if (rename(temporary, path) != 0) {
        unlink(temporary); return SDR_FILEWERR;
    }
    return SDR_OK;
}
static int derive_password(const BYTE *password, uint32_t password_len,
                           const BYTE salt[16], BYTE derived[32])
{
    if (password == NULL || password_len == 0 || password_len > INTERNAL_PASSWORD_MAX) {
        return SDR_INARGERR;
    }

    BYTE *initial = malloc((size_t)password_len + 16);
    if (initial == NULL) {
        return SDR_NOBUFFER;
    }
    memcpy(initial, password, password_len);
    memcpy(initial + password_len, salt, 16);
    ULONG digest_len = 32;
    int ret = crypto_hash_digest(SGD_SM3, initial, password_len + 16,
                                 derived, &digest_len);
    secure_clear(initial, (size_t)password_len + 16);
    free(initial);
    if (ret != SDR_OK || digest_len != 32) {
        return ret == SDR_OK ? SDR_KEYERR : ret;
    }

    BYTE round_input[52];
    memcpy(round_input + 32, salt, 16);
    for (uint32_t round = 1; round < INTERNAL_KDF_ROUNDS; ++round) {
        memcpy(round_input, derived, 32);
        round_input[48] = (BYTE)(round >> 24);
        round_input[49] = (BYTE)(round >> 16);
        round_input[50] = (BYTE)(round >> 8);
        round_input[51] = (BYTE)round;
        digest_len = 32;
        ret = crypto_hash_digest(SGD_SM3, round_input, sizeof(round_input),
                                 derived, &digest_len);
        if (ret != SDR_OK || digest_len != 32) {
            secure_clear(round_input, sizeof(round_input));
            secure_clear(derived, 32);
            return ret == SDR_OK ? SDR_KEYERR : ret;
        }
    }
    secure_clear(round_input, sizeof(round_input));
    return SDR_OK;
}

static int make_verifier(const BYTE derived[32], BYTE verifier[32])
{
    static const BYTE label[] = "SDFX-SM2-PRIVATE-KEY";
    BYTE input[32 + sizeof(label) - 1];
    memcpy(input, derived, 32);
    memcpy(input + 32, label, sizeof(label) - 1);
    ULONG length = 32;
    int ret = crypto_hash_digest(SGD_SM3, input, sizeof(input), verifier, &length);
    secure_clear(input, sizeof(input));
    return ret == SDR_OK && length == 32 ? SDR_OK : SDR_KEYERR;
}

static int read_record(uint32_t type, uint32_t index, internal_key_record_t *record);

static int read_record_raw(uint32_t type, uint32_t index, internal_key_record_t *record)
{
    char path[512];
    int ret = internal_key_path(type, index, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? SDR_KEYNOTEXIST : SDR_KEYERR;
    }
    memset(record, 0, sizeof(*record));
    ssize_t got = read(fd, record, sizeof(*record));
    BYTE extra = 0;
    ssize_t trailing = read(fd, &extra, 1);
    close(fd);
    const size_t legacy_size = offsetof(internal_key_record_t, integrity);
    if ((got != (ssize_t)sizeof(*record) && got != (ssize_t)legacy_size) || trailing != 0 ||
        record->magic != INTERNAL_KEY_MAGIC ||
        (record->version != 1U && record->version != INTERNAL_KEY_VERSION) ||
        record->type != type || record->index != index ||
        record->public_key.bits != 256) {
        secure_clear(record, sizeof(*record));
        return SDR_KEYERR;
    }

    BYTE expected[32] = {0};
    if (got == (ssize_t)legacy_size && record->version == 1U) {
        record->version = INTERNAL_KEY_VERSION;
        ret = compute_record_integrity(record, record->integrity);
        if (ret == SDR_OK) {
            ret = write_record_file(type, index, record, 0);
        }
    } else if (got != (ssize_t)sizeof(*record) ||
               record->version != INTERNAL_KEY_VERSION) {
        ret = SDR_KEYERR;
    } else {
        ret = compute_record_integrity(record, expected);
        if (ret == SDR_OK &&
            !constant_time_equal(expected, record->integrity, sizeof(expected))) {
            ret = SDR_KEYERR;
        }
    }
    secure_clear(expected, sizeof(expected));
    if (ret != SDR_OK) {
        secure_clear(record, sizeof(*record));
    }
    return ret;
}
static int create_record(uint32_t type, uint32_t index,
                         const BYTE *password, uint32_t password_len)
{
    if (password_len > INTERNAL_PASSWORD_MAX ||
        (password_len != 0 && (password == NULL || password_len < 8))) {
        return SDR_INARGERR;
    }
    if (ensure_internal_key_tree() != SDR_OK) {
        return SDR_FILEWERR;
    }
    char path[512];
    int ret = internal_key_path(type, index, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }

    pthread_mutex_lock(&g_internal_key_mutex);
    if (access(path, F_OK) == 0) {
        pthread_mutex_unlock(&g_internal_key_mutex);
        return SDR_FILEEXISTS;
    }

    ECCrefPrivateKey private_key;
    internal_key_record_t record;
    BYTE derived[32] = {0};
    memset(&record, 0, sizeof(record));
    memset(&private_key, 0, sizeof(private_key));
    record.magic = INTERNAL_KEY_MAGIC;
    record.version = INTERNAL_KEY_VERSION;
    record.type = type;
    record.index = index;
    ret = crypto_sm2_generate_keypair(&record.public_key, &private_key);
    if (ret == SDR_OK) {
        ret = crypto_generate_random(sizeof(record.salt), record.salt);
    }
    if (ret == SDR_OK) {
        ret = password_len == 0
            ? derive_device_secret(type, index, record.salt, derived)
            : derive_password(password, password_len, record.salt, derived);
    }
    if (ret == SDR_OK && password_len != 0) {
        ret = make_verifier(derived, record.verifier);
    }
    if (ret == SDR_OK) {
        ULONG encrypted_len = sizeof(record.encrypted_private);
        ret = crypto_symmetric_encrypt(SGD_SM4_CTR, derived, 16,
                                       record.salt, sizeof(record.salt),
                                       private_key.K + ECCref_MAX_LEN - 32, 32,
                                       record.encrypted_private, &encrypted_len);
        if (ret == SDR_OK && encrypted_len != sizeof(record.encrypted_private)) {
            ret = SDR_KEYERR;
        }
    }
    if (ret == SDR_OK) {
        ret = compute_record_integrity(&record, record.integrity);
    }
    if (ret == SDR_OK) {
        ret = write_record_file(type, index, &record, 1);
    }
    secure_clear(&private_key, sizeof(private_key));
    secure_clear(derived, sizeof(derived));
    secure_clear(&record, sizeof(record));
    pthread_mutex_unlock(&g_internal_key_mutex);
    return ret;
}
static int derive_and_verify(uint32_t type, uint32_t index,
                             const BYTE *password, uint32_t password_len,
                             BYTE derived[32])
{
    internal_key_record_t record;
    int ret = read_record(type, index, &record);
    if (ret != SDR_OK) {
        return ret;
    }
    BYTE verifier[32] = {0};
    if (record_is_passwordless(&record)) {
        ret = password_len == 0
            ? derive_device_secret(type, index, record.salt, derived)
            : SDR_PRKRERR;
    } else if (password == NULL || password_len < 8 ||
               password_len > INTERNAL_PASSWORD_MAX) {
        ret = SDR_PRKRERR;
    } else {
        ret = derive_password(password, password_len, record.salt, derived);
        if (ret == SDR_OK) {
            ret = make_verifier(derived, verifier);
        }
        if (ret == SDR_OK && !constant_time_equal(verifier, record.verifier, 32)) {
            ret = SDR_PRKRERR;
        }
    }
    secure_clear(verifier, sizeof(verifier));
    secure_clear(&record, sizeof(record));
    if (ret != SDR_OK) {
        secure_clear(derived, 32);
    }
    return ret;
}
int internal_key_get_access(session_info_t *session, uint32_t index,
                            const BYTE *password, uint32_t password_len)
{
    if (session == NULL || index == 0 || password_len > INTERNAL_PASSWORD_MAX ||
        (password_len != 0 && password == NULL)) {
        return SDR_INARGERR;
    }
    BYTE sign_secret[32] = {0};
    BYTE enc_secret[32] = {0};
    int sign_ret = derive_and_verify(SDFX_INTERNAL_KEY_SIGN, index,
                                     password, password_len, sign_secret);
    int enc_ret = derive_and_verify(SDFX_INTERNAL_KEY_ENC, index,
                                    password, password_len, enc_secret);
    if (sign_ret == SDR_KEYNOTEXIST && enc_ret == SDR_KEYNOTEXIST) {
        return SDR_KEYNOTEXIST;
    }
    if (sign_ret != SDR_OK && enc_ret != SDR_OK) {
        secure_clear(sign_secret, sizeof(sign_secret));
        secure_clear(enc_secret, sizeof(enc_secret));
        return SDR_PRKRERR;
    }

    private_key_permission_t *permission = calloc(1, sizeof(*permission));
    if (permission == NULL) {
        secure_clear(sign_secret, sizeof(sign_secret));
        secure_clear(enc_secret, sizeof(enc_secret));
        return SDR_NOBUFFER;
    }
    permission->key_index = index;
    permission->sign_allowed = sign_ret == SDR_OK;
    permission->enc_allowed = enc_ret == SDR_OK;
    memcpy(permission->sign_secret, sign_secret, 32);
    memcpy(permission->enc_secret, enc_secret, 32);
    secure_clear(sign_secret, sizeof(sign_secret));
    secure_clear(enc_secret, sizeof(enc_secret));

    pthread_mutex_lock(&session->object_mutex);
    private_key_permission_t **cursor = &session->private_permissions;
    while (*cursor != NULL && (*cursor)->key_index != index) {
        cursor = &(*cursor)->next;
    }
    if (*cursor != NULL) {
        private_key_permission_t *old = *cursor;
        permission->next = old->next;
        *cursor = permission;
        secure_clear(old, sizeof(*old));
        free(old);
    } else {
        permission->next = session->private_permissions;
        session->private_permissions = permission;
    }
    pthread_mutex_unlock(&session->object_mutex);
    return SDR_OK;
}

int internal_key_release_access(session_info_t *session, uint32_t index)
{
    if (session == NULL || index == 0) {
        return SDR_INARGERR;
    }
    pthread_mutex_lock(&session->object_mutex);
    private_key_permission_t **cursor = &session->private_permissions;
    while (*cursor != NULL && (*cursor)->key_index != index) {
        cursor = &(*cursor)->next;
    }
    if (*cursor == NULL) {
        pthread_mutex_unlock(&session->object_mutex);
        return SDR_PARDENY;
    }
    private_key_permission_t *permission = *cursor;
    *cursor = permission->next;
    secure_clear(permission, sizeof(*permission));
    free(permission);
    pthread_mutex_unlock(&session->object_mutex);
    return SDR_OK;
}

static int get_permission_secret(session_info_t *session, uint32_t type,
                                 uint32_t index, BYTE derived[32])
{
    int ret = SDR_PARDENY;
    pthread_mutex_lock(&session->object_mutex);
    for (private_key_permission_t *entry = session->private_permissions;
         entry != NULL; entry = entry->next) {
        if (entry->key_index == index) {
            bool allowed = type == SDFX_INTERNAL_KEY_SIGN ?
                           entry->sign_allowed : entry->enc_allowed;
            if (allowed) {
                memcpy(derived, type == SDFX_INTERNAL_KEY_SIGN ?
                       entry->sign_secret : entry->enc_secret, 32);
                ret = SDR_OK;
            }
            break;
        }
    }
    pthread_mutex_unlock(&session->object_mutex);
    return ret;
}

static int load_private_key(session_info_t *session, uint32_t type,
                            uint32_t index, ECCrefPrivateKey *private_key)
{
    BYTE derived[32] = {0};
    internal_key_record_t record;
    int ret = read_record(type, index, &record);
    if (ret != SDR_OK) {
        return ret;
    }
    ret = get_permission_secret(session, type, index, derived);
    if (ret != SDR_OK && record_is_passwordless(&record)) {
        ret = derive_device_secret(type, index, record.salt, derived);
    }
    if (ret == SDR_OK) {
        memset(private_key, 0, sizeof(*private_key));
        private_key->bits = 256;
        ULONG private_len = 32;
        ret = crypto_symmetric_decrypt(SGD_SM4_CTR, derived, 16,
                                       record.salt, sizeof(record.salt),
                                       record.encrypted_private, 32,
                                       private_key->K + ECCref_MAX_LEN - 32,
                                       &private_len);
        if (ret == SDR_OK && private_len != 32) {
            ret = SDR_KEYERR;
        }
    }
    secure_clear(derived, sizeof(derived));
    secure_clear(&record, sizeof(record));
    if (ret != SDR_OK) {
        secure_clear(private_key, sizeof(*private_key));
    }
    return ret;
}
int internal_key_export_public(uint32_t type, uint32_t index,
                               ECCrefPublicKey *public_key)
{
    if (public_key == NULL) {
        return SDR_OUTARGERR;
    }
    internal_key_record_t record;
    int ret = read_record(type, index, &record);
    if (ret == SDR_OK) {
        memcpy(public_key, &record.public_key, sizeof(*public_key));
    }
    secure_clear(&record, sizeof(record));
    return ret;
}

int internal_key_sign(session_info_t *session, uint32_t index,
                      const BYTE *data, uint32_t data_len,
                      BYTE signature[64])
{
    if (session == NULL || data == NULL || data_len == 0 || signature == NULL) {
        return SDR_INARGERR;
    }
    ECCrefPrivateKey private_key;
    int ret = load_private_key(session, SDFX_INTERNAL_KEY_SIGN, index, &private_key);
    if (ret == SDR_OK) {
        ULONG signature_len = 64;
        ret = crypto_sm2_external_sign(&private_key, data, data_len,
                                       signature, &signature_len);
        if (ret == SDR_OK && signature_len != 64) {
            ret = SDR_SIGNERR;
        }
    }
    secure_clear(&private_key, sizeof(private_key));
    return ret;
}

int internal_key_verify(uint32_t index, const BYTE *data, uint32_t data_len,
                        const BYTE signature[64])
{
    ECCrefPublicKey public_key;
    int ret = internal_key_export_public(SDFX_INTERNAL_KEY_SIGN, index, &public_key);
    if (ret == SDR_OK) {
        ret = crypto_sm2_external_verify(&public_key, data, data_len, signature, 64);
    }
    secure_clear(&public_key, sizeof(public_key));
    return ret;
}

static int generate_and_wrap(session_info_t *session,
                             const ECCrefPublicKey *public_key,
                             uint32_t key_bits, ECCCipher *wrapped,
                             uint32_t wrapped_capacity, uint64_t *key_id)
{
    if (session == NULL || public_key == NULL || wrapped == NULL || key_id == NULL ||
        (key_bits != 128 && key_bits != 256)) {
        return SDR_INARGERR;
    }
    BYTE key[32];
    uint32_t key_len = key_bits / 8;
    int ret = crypto_generate_random(key_len, key);
    if (ret == SDR_OK) {
        ret = crypto_sm2_external_encrypt(public_key, key, key_len,
                                          wrapped, wrapped_capacity);
    }
    if (ret == SDR_OK) {
        ret = session_key_create(session, key, key_len, key_id);
    }
    secure_clear(key, sizeof(key));
    return ret;
}

int internal_key_generate_with_ipk(session_info_t *session, uint32_t index,
                                   uint32_t key_bits, ECCCipher *wrapped,
                                   uint32_t wrapped_capacity, uint64_t *key_id)
{
    ECCrefPublicKey public_key;
    int ret = internal_key_export_public(SDFX_INTERNAL_KEY_ENC, index, &public_key);
    if (ret == SDR_OK) {
        ret = generate_and_wrap(session, &public_key, key_bits, wrapped,
                                wrapped_capacity, key_id);
    }
    secure_clear(&public_key, sizeof(public_key));
    return ret;
}

int external_key_generate_with_epk(session_info_t *session,
                                   const ECCrefPublicKey *public_key,
                                   uint32_t key_bits, ECCCipher *wrapped,
                                   uint32_t wrapped_capacity, uint64_t *key_id)
{
    return generate_and_wrap(session, public_key, key_bits, wrapped,
                             wrapped_capacity, key_id);
}

int internal_key_import_with_isk(session_info_t *session, uint32_t index,
                                 const ECCCipher *wrapped, uint64_t *key_id)
{
    if (session == NULL || wrapped == NULL || key_id == NULL ||
        wrapped->L == 0 || wrapped->L > 32) {
        return SDR_INARGERR;
    }
    ECCrefPrivateKey private_key;
    BYTE key[32];
    ULONG key_len = sizeof(key);
    int ret = load_private_key(session, SDFX_INTERNAL_KEY_ENC, index, &private_key);
    if (ret == SDR_OK) {
        ret = crypto_sm2_external_decrypt(&private_key, wrapped, key, &key_len);
    }
    if (ret == SDR_OK && key_len != 16 && key_len != 32) {
        ret = SDR_KEYERR;
    }
    if (ret == SDR_OK) {
        ret = session_key_create(session, key, key_len, key_id);
    }
    secure_clear(&private_key, sizeof(private_key));
    secure_clear(key, sizeof(key));
    return ret;
}


#include "internal_key_admin.inc"

