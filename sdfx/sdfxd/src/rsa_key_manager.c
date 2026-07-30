/* Protected persistent RSA key management for GM/T 0018. */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "daemon_internal.h"

#define RSA_KEY_MAGIC 0x5253414BU
#define RSA_KEY_VERSION 1U
#define RSA_KEY_INDEX_MAX 1024U
#define RSA_PASSWORD_MAX 256U
#define RSA_KDF_ROUNDS 20000U

typedef struct rsa_key_record {
    uint32_t magic;
    uint32_t version;
    uint32_t type;
    uint32_t index;
    uint32_t bits;
    RSArefPublicKey public_key;
    BYTE salt[16];
    BYTE verifier[32];
    BYTE encrypted_private[sizeof(RSArefPrivateKey)];
    BYTE integrity[32];
} rsa_key_record_t;

static pthread_mutex_t g_rsa_key_mutex = PTHREAD_MUTEX_INITIALIZER;

static void rsa_wipe(void *ptr, size_t len)
{
    volatile BYTE *p = (volatile BYTE *)ptr;
    while (len-- > 0) *p++ = 0;
}

static int rsa_equal(const BYTE *a, const BYTE *b, size_t len)
{
    BYTE diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

static const char *rsa_storage_root(void)
{
    const char *root = getenv("SDFX_DATA_DIR");
    return root != NULL && root[0] != '\0' ? root : "/var/lib/sdfx";
}

static int rsa_ensure_dir(const char *path)
{
    return mkdir(path, 0700) == 0 || errno == EEXIST ? SDR_OK : SDR_FILEWERR;
}

static int rsa_ensure_tree(void)
{
    char path[512];
    const char *parts[] = {"/keys", "/keys/rsa", "/keys/rsa/sign", "/keys/rsa/enc"};
    if (rsa_ensure_dir(rsa_storage_root()) != SDR_OK) return SDR_FILEWERR;
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        int n = snprintf(path, sizeof(path), "%s%s", rsa_storage_root(), parts[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) || rsa_ensure_dir(path) != SDR_OK)
            return SDR_FILEWERR;
    }
    return SDR_OK;
}

static int rsa_path(uint32_t type, uint32_t index, char *path, size_t path_len)
{
    if ((type != SDFX_INTERNAL_KEY_SIGN && type != SDFX_INTERNAL_KEY_ENC) ||
        index == 0 || index > RSA_KEY_INDEX_MAX || path == NULL) return SDR_INARGERR;
    int n = snprintf(path, path_len, "%s/keys/rsa/%s/%08u.key", rsa_storage_root(),
                     type == SDFX_INTERNAL_KEY_SIGN ? "sign" : "enc", index);
    return n > 0 && (size_t)n < path_len ? SDR_OK : SDR_FILEWERR;
}

static int rsa_disabled_path(uint32_t type, uint32_t index, char *path, size_t path_len)
{
    char key_path[512];
    int ret = rsa_path(type, index, key_path, sizeof(key_path));
    if (ret != SDR_OK) return ret;
    int n = snprintf(path, path_len, "%s.disabled", key_path);
    return n > 0 && (size_t)n < path_len ? SDR_OK : SDR_FILEWERR;
}

static int rsa_is_disabled(uint32_t type, uint32_t index)
{
    char path[544];
    return rsa_disabled_path(type, index, path, sizeof(path)) == SDR_OK &&
           access(path, F_OK) == 0;
}

static int rsa_read_device_key(BYTE key[32])
{
    char path[544];
    int n = snprintf(path, sizeof(path), "%s/master/device-integrity.key", rsa_storage_root());
    if (n <= 0 || (size_t)n >= sizeof(path)) return SDR_FILEWERR;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return SDR_KEYERR;
    struct stat st;
    ssize_t got = read(fd, key, 32);
    BYTE extra = 0;
    ssize_t trailing = read(fd, &extra, 1);
    int valid = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && got == 32 && trailing == 0;
    close(fd);
    if (!valid) { rsa_wipe(key, 32); return SDR_KEYERR; }
    return SDR_OK;
}

static int rsa_hmac_sm3(const BYTE key[32], const BYTE *data, size_t data_len,
                        BYTE output[32])
{
    size_t size = 64 + data_len;
    if (size < 96) size = 96;
    BYTE *buffer = malloc(size);
    if (buffer == NULL) return SDR_NOBUFFER;
    BYTE ipad[64], opad[64], inner[32];
    memset(ipad, 0x36, sizeof(ipad)); memset(opad, 0x5c, sizeof(opad));
    for (size_t i = 0; i < 32; ++i) { ipad[i] ^= key[i]; opad[i] ^= key[i]; }
    memcpy(buffer, ipad, 64); memcpy(buffer + 64, data, data_len);
    ULONG len = 32;
    int ret = crypto_hash_digest(SGD_SM3, buffer, (ULONG)(64 + data_len), inner, &len);
    if (ret == SDR_OK && len == 32) {
        memcpy(buffer, opad, 64); memcpy(buffer + 64, inner, 32); len = 32;
        ret = crypto_hash_digest(SGD_SM3, buffer, 96, output, &len);
        if (ret == SDR_OK && len != 32) ret = SDR_KEYERR;
    }
    rsa_wipe(buffer, size); free(buffer); rsa_wipe(ipad, sizeof(ipad));
    rsa_wipe(opad, sizeof(opad)); rsa_wipe(inner, sizeof(inner));
    return ret;
}

static int rsa_derive_password(const BYTE *password, uint32_t password_len,
                               const BYTE salt[16], BYTE derived[32])
{
    if (password == NULL || password_len == 0 || password_len > RSA_PASSWORD_MAX)
        return SDR_INARGERR;
    BYTE *initial = malloc((size_t)password_len + 16);
    if (initial == NULL) return SDR_NOBUFFER;
    memcpy(initial, password, password_len); memcpy(initial + password_len, salt, 16);
    ULONG len = 32;
    int ret = crypto_hash_digest(SGD_SM3, initial, password_len + 16, derived, &len);
    rsa_wipe(initial, (size_t)password_len + 16); free(initial);
    BYTE round_input[52];
    memcpy(round_input + 32, salt, 16);
    for (uint32_t round = 1; ret == SDR_OK && round < RSA_KDF_ROUNDS; ++round) {
        memcpy(round_input, derived, 32);
        round_input[48] = (BYTE)(round >> 24); round_input[49] = (BYTE)(round >> 16);
        round_input[50] = (BYTE)(round >> 8); round_input[51] = (BYTE)round;
        len = 32;
        ret = crypto_hash_digest(SGD_SM3, round_input, sizeof(round_input), derived, &len);
        if (ret == SDR_OK && len != 32) ret = SDR_KEYERR;
    }
    rsa_wipe(round_input, sizeof(round_input));
    if (ret != SDR_OK) rsa_wipe(derived, 32);
    return ret;
}

static int rsa_device_secret(uint32_t type, uint32_t index, const BYTE salt[16],
                             BYTE derived[32])
{
    BYTE device[32] = {0};
    BYTE context[48] = "SDFX-RSA-NO-PASSWORD";
    context[24] = (BYTE)(type >> 24); context[25] = (BYTE)(type >> 16);
    context[26] = (BYTE)(type >> 8); context[27] = (BYTE)type;
    context[28] = (BYTE)(index >> 24); context[29] = (BYTE)(index >> 16);
    context[30] = (BYTE)(index >> 8); context[31] = (BYTE)index;
    memcpy(context + 32, salt, 16);
    int ret = rsa_read_device_key(device);
    if (ret == SDR_OK) ret = rsa_hmac_sm3(device, context, sizeof(context), derived);
    rsa_wipe(device, sizeof(device)); rsa_wipe(context, sizeof(context));
    return ret;
}

static int rsa_make_verifier(const BYTE derived[32], BYTE verifier[32])
{
    static const BYTE label[] = "SDFX-RSA-PRIVATE-KEY";
    BYTE input[32 + sizeof(label) - 1];
    memcpy(input, derived, 32); memcpy(input + 32, label, sizeof(label) - 1);
    ULONG len = 32;
    int ret = crypto_hash_digest(SGD_SM3, input, sizeof(input), verifier, &len);
    rsa_wipe(input, sizeof(input));
    return ret == SDR_OK && len == 32 ? SDR_OK : SDR_KEYERR;
}

static int rsa_passwordless(const rsa_key_record_t *record)
{
    BYTE value = 0;
    for (size_t i = 0; i < sizeof(record->verifier); ++i) value |= record->verifier[i];
    return value == 0;
}

static int rsa_record_hmac(const rsa_key_record_t *record, BYTE output[32])
{
    BYTE device[32] = {0};
    BYTE *data = malloc(offsetof(rsa_key_record_t, integrity) + 4);
    if (data == NULL) return SDR_NOBUFFER;
    memcpy(data, record, offsetof(rsa_key_record_t, integrity));
    size_t offset = offsetof(rsa_key_record_t, integrity);
    data[offset] = (BYTE)(record->index >> 24); data[offset + 1] = (BYTE)(record->index >> 16);
    data[offset + 2] = (BYTE)(record->index >> 8); data[offset + 3] = (BYTE)record->index;
    int ret = rsa_read_device_key(device);
    if (ret == SDR_OK) ret = rsa_hmac_sm3(device, data, offset + 4, output);
    rsa_wipe(device, sizeof(device)); rsa_wipe(data, offset + 4); free(data);
    return ret;
}

static int rsa_write_record(uint32_t type, uint32_t index,
                            const rsa_key_record_t *record, int exclusive)
{
    char path[512], temp[560];
    int ret = rsa_path(type, index, path, sizeof(path));
    if (ret != SDR_OK) return ret;
    int n = snprintf(temp, sizeof(temp), "%s.tmp.%ld", path, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(temp)) return SDR_FILEWERR;
    int fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return SDR_FILEWERR;
    ssize_t written = write(fd, record, sizeof(*record));
    if (written != (ssize_t)sizeof(*record) || fsync(fd) != 0) {
        close(fd); unlink(temp); return SDR_FILEWERR;
    }
    close(fd);
    if (exclusive && access(path, F_OK) == 0) { unlink(temp); return SDR_FILEEXISTS; }
    if (rename(temp, path) != 0) { unlink(temp); return SDR_FILEWERR; }
    return SDR_OK;
}

static int rsa_read_raw(uint32_t type, uint32_t index, rsa_key_record_t *record)
{
    char path[512];
    int ret = rsa_path(type, index, path, sizeof(path));
    if (ret != SDR_OK) return ret;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? SDR_KEYNOTEXIST : SDR_KEYERR;
    ssize_t got = read(fd, record, sizeof(*record)); BYTE extra = 0;
    ssize_t trailing = read(fd, &extra, 1); close(fd);
    if (got != (ssize_t)sizeof(*record) || trailing != 0 ||
        record->magic != RSA_KEY_MAGIC || record->version != RSA_KEY_VERSION ||
        record->type != type || record->index != index || record->bits != record->public_key.bits ||
        record->bits < 1024 || record->bits > RSAref_MAX_BITS) {
        rsa_wipe(record, sizeof(*record)); return SDR_KEYERR;
    }
    BYTE expected[32] = {0};
    ret = rsa_record_hmac(record, expected);
    if (ret == SDR_OK && !rsa_equal(expected, record->integrity, 32)) ret = SDR_KEYERR;
    rsa_wipe(expected, sizeof(expected));
    if (ret != SDR_OK) rsa_wipe(record, sizeof(*record));
    return ret;
}

static int rsa_read(uint32_t type, uint32_t index, rsa_key_record_t *record)
{
    int ret = rsa_read_raw(type, index, record);
    if (ret == SDR_OK && rsa_is_disabled(type, index)) {
        rsa_wipe(record, sizeof(*record)); return SDR_KEYNOTEXIST;
    }
    return ret;
}

int rsa_key_admin_exists(uint32_t type, uint32_t index)
{
    rsa_key_record_t record;
    int ret = rsa_read_raw(type, index, &record);
    rsa_wipe(&record, sizeof(record));
    return ret == SDR_OK;
}

int rsa_key_admin_create(uint32_t type, uint32_t index, uint32_t bits,
                         const BYTE *password, uint32_t password_len)
{
    if ((password_len != 0 && (password == NULL || password_len < 8)) ||
        password_len > RSA_PASSWORD_MAX || bits < 1024 || bits > RSAref_MAX_BITS ||
        (bits % 256U) != 0) return SDR_INARGERR;
    if (internal_key_admin_verify(type, index) == SDR_OK) return SDR_FILEEXISTS;
    int ret = rsa_ensure_tree();
    char path[512];
    if (ret == SDR_OK) ret = rsa_path(type, index, path, sizeof(path));
    if (ret != SDR_OK) return ret;
    pthread_mutex_lock(&g_rsa_key_mutex);
    if (access(path, F_OK) == 0) { pthread_mutex_unlock(&g_rsa_key_mutex); return SDR_FILEEXISTS; }
    rsa_key_record_t record; RSArefPrivateKey private_key; BYTE derived[32] = {0};
    memset(&record, 0, sizeof(record)); memset(&private_key, 0, sizeof(private_key));
    record.magic = RSA_KEY_MAGIC; record.version = RSA_KEY_VERSION;
    record.type = type; record.index = index; record.bits = bits;
    ret = crypto_rsa_generate_keypair(bits, &record.public_key, &private_key);
    if (ret == SDR_OK) ret = crypto_generate_random(sizeof(record.salt), record.salt);
    if (ret == SDR_OK) ret = password_len == 0
        ? rsa_device_secret(type, index, record.salt, derived)
        : rsa_derive_password(password, password_len, record.salt, derived);
    if (ret == SDR_OK && password_len != 0) ret = rsa_make_verifier(derived, record.verifier);
    if (ret == SDR_OK) {
        ULONG length = sizeof(record.encrypted_private);
        ret = crypto_symmetric_encrypt(SGD_SM4_CTR, derived, 16, record.salt, 16,
                (const BYTE *)&private_key, sizeof(private_key),
                record.encrypted_private, &length);
        if (ret == SDR_OK && length != sizeof(record.encrypted_private)) ret = SDR_KEYERR;
    }
    if (ret == SDR_OK) ret = rsa_record_hmac(&record, record.integrity);
    if (ret == SDR_OK) ret = rsa_write_record(type, index, &record, 1);
    rsa_wipe(&private_key, sizeof(private_key)); rsa_wipe(derived, sizeof(derived));
    rsa_wipe(&record, sizeof(record)); pthread_mutex_unlock(&g_rsa_key_mutex);
    return ret;
}

int rsa_key_admin_delete(uint32_t type, uint32_t index)
{
    char path[512], marker[544];
    int ret = rsa_path(type, index, path, sizeof(path));
    if (ret != SDR_OK || rsa_disabled_path(type, index, marker, sizeof(marker)) != SDR_OK)
        return ret == SDR_OK ? SDR_FILEWERR : ret;
    pthread_mutex_lock(&g_rsa_key_mutex);
    ret = unlink(path) == 0 ? SDR_OK : (errno == ENOENT ? SDR_KEYNOTEXIST : SDR_FILEWERR);
    if (ret == SDR_OK) unlink(marker);
    pthread_mutex_unlock(&g_rsa_key_mutex); return ret;
}

int rsa_key_admin_set_enabled(uint32_t type, uint32_t index, bool enabled)
{
    rsa_key_record_t record; int ret = rsa_read_raw(type, index, &record);
    rsa_wipe(&record, sizeof(record)); if (ret != SDR_OK) return ret;
    char marker[544]; ret = rsa_disabled_path(type, index, marker, sizeof(marker));
    if (ret != SDR_OK) return ret;
    pthread_mutex_lock(&g_rsa_key_mutex);
    if (enabled) ret = unlink(marker) == 0 || errno == ENOENT ? SDR_OK : SDR_FILEWERR;
    else { int fd = open(marker, O_WRONLY | O_CREAT, 0600); ret = fd < 0 ? SDR_FILEWERR : SDR_OK; if (fd >= 0) { fsync(fd); close(fd); } }
    pthread_mutex_unlock(&g_rsa_key_mutex); return ret;
}

int rsa_key_admin_export_public(uint32_t type, uint32_t index, RSArefPublicKey *public_key)
{
    if (public_key == NULL) return SDR_OUTARGERR;
    rsa_key_record_t record; int ret = rsa_read_raw(type, index, &record);
    if (ret == SDR_OK) memcpy(public_key, &record.public_key, sizeof(*public_key));
    rsa_wipe(&record, sizeof(record)); return ret;
}

int rsa_key_export_public(uint32_t type, uint32_t index, RSArefPublicKey *public_key)
{
    if (public_key == NULL) return SDR_OUTARGERR;
    rsa_key_record_t record; int ret = rsa_read(type, index, &record);
    if (ret == SDR_OK) memcpy(public_key, &record.public_key, sizeof(*public_key));
    rsa_wipe(&record, sizeof(record)); return ret;
}

static int rsa_derive_verify(uint32_t type, uint32_t index, const BYTE *password,
                             uint32_t password_len, BYTE derived[32])
{
    rsa_key_record_t record; int ret = rsa_read(type, index, &record);
    if (ret != SDR_OK) return ret;
    BYTE verifier[32] = {0};
    if (rsa_passwordless(&record)) ret = password_len == 0
        ? rsa_device_secret(type, index, record.salt, derived) : SDR_PRKRERR;
    else if (password == NULL || password_len < 8 || password_len > RSA_PASSWORD_MAX)
        ret = SDR_PRKRERR;
    else {
        ret = rsa_derive_password(password, password_len, record.salt, derived);
        if (ret == SDR_OK) ret = rsa_make_verifier(derived, verifier);
        if (ret == SDR_OK && !rsa_equal(verifier, record.verifier, 32)) ret = SDR_PRKRERR;
    }
    rsa_wipe(verifier, sizeof(verifier)); rsa_wipe(&record, sizeof(record));
    if (ret != SDR_OK) rsa_wipe(derived, 32); return ret;
}

int rsa_key_get_access(session_info_t *session, uint32_t index,
                       const BYTE *password, uint32_t password_len)
{
    if (session == NULL || index == 0 || password_len > RSA_PASSWORD_MAX ||
        (password_len != 0 && password == NULL)) return SDR_INARGERR;
    BYTE sign[32] = {0}, enc[32] = {0};
    int sr = rsa_derive_verify(SDFX_INTERNAL_KEY_SIGN, index, password, password_len, sign);
    int er = rsa_derive_verify(SDFX_INTERNAL_KEY_ENC, index, password, password_len, enc);
    if (sr == SDR_KEYNOTEXIST && er == SDR_KEYNOTEXIST) return SDR_KEYNOTEXIST;
    if (sr != SDR_OK && er != SDR_OK) { rsa_wipe(sign,32); rsa_wipe(enc,32); return SDR_PRKRERR; }
    rsa_private_key_permission_t *permission = calloc(1, sizeof(*permission));
    if (permission == NULL) { rsa_wipe(sign,32); rsa_wipe(enc,32); return SDR_NOBUFFER; }
    permission->key_index = index; permission->sign_allowed = sr == SDR_OK; permission->enc_allowed = er == SDR_OK;
    memcpy(permission->sign_secret, sign, 32); memcpy(permission->enc_secret, enc, 32);
    rsa_wipe(sign,32); rsa_wipe(enc,32);
    pthread_mutex_lock(&session->object_mutex);
    rsa_private_key_permission_t **cursor = &session->rsa_private_permissions;
    while (*cursor != NULL && (*cursor)->key_index != index) cursor = &(*cursor)->next;
    if (*cursor != NULL) { rsa_private_key_permission_t *old=*cursor; permission->next=old->next; *cursor=permission; rsa_wipe(old,sizeof(*old)); free(old); }
    else { permission->next=session->rsa_private_permissions; session->rsa_private_permissions=permission; }
    pthread_mutex_unlock(&session->object_mutex); return SDR_OK;
}

int rsa_key_release_access(session_info_t *session, uint32_t index)
{
    if (session == NULL || index == 0) return SDR_INARGERR;
    pthread_mutex_lock(&session->object_mutex);
    rsa_private_key_permission_t **cursor=&session->rsa_private_permissions;
    while (*cursor != NULL && (*cursor)->key_index != index) cursor=&(*cursor)->next;
    if (*cursor == NULL) { pthread_mutex_unlock(&session->object_mutex); return SDR_PARDENY; }
    rsa_private_key_permission_t *entry=*cursor; *cursor=entry->next;
    rsa_wipe(entry,sizeof(*entry)); free(entry); pthread_mutex_unlock(&session->object_mutex); return SDR_OK;
}

static int rsa_permission_secret(session_info_t *session, uint32_t type,
                                 uint32_t index, BYTE derived[32])
{
    int ret=SDR_PARDENY; pthread_mutex_lock(&session->object_mutex);
    for (rsa_private_key_permission_t *e=session->rsa_private_permissions;e!=NULL;e=e->next) {
        if (e->key_index == index) { bool allowed=type==SDFX_INTERNAL_KEY_SIGN?e->sign_allowed:e->enc_allowed;
            if (allowed) { memcpy(derived,type==SDFX_INTERNAL_KEY_SIGN?e->sign_secret:e->enc_secret,32); ret=SDR_OK; } break; }
    }
    pthread_mutex_unlock(&session->object_mutex); return ret;
}

static int rsa_load_private(session_info_t *session, uint32_t type, uint32_t index,
                            RSArefPrivateKey *private_key)
{
    rsa_key_record_t record; BYTE derived[32]={0}; int ret=rsa_read(type,index,&record);
    if (ret != SDR_OK) return ret;
    ret=rsa_permission_secret(session,type,index,derived);
    if (ret != SDR_OK && rsa_passwordless(&record)) ret=rsa_device_secret(type,index,record.salt,derived);
    if (ret == SDR_OK) { ULONG length=sizeof(*private_key); ret=crypto_symmetric_decrypt(SGD_SM4_CTR,derived,16,record.salt,16,record.encrypted_private,sizeof(record.encrypted_private),(BYTE *)private_key,&length); if(ret==SDR_OK && length!=sizeof(*private_key)) ret=SDR_KEYERR; }
    rsa_wipe(derived,32); rsa_wipe(&record,sizeof(record)); if(ret!=SDR_OK) rsa_wipe(private_key,sizeof(*private_key)); return ret;
}

int rsa_key_admin_change_password(uint32_t type, uint32_t index,
                                  const BYTE *old_password, uint32_t old_len,
                                  const BYTE *new_password, uint32_t new_len)
{
    if ((old_len && (old_password==NULL||old_len<8)) || (new_len && (new_password==NULL||new_len<8)) || old_len>256 || new_len>256) return SDR_INARGERR;
    pthread_mutex_lock(&g_rsa_key_mutex);
    rsa_key_record_t record; RSArefPrivateKey private_key; BYTE old_key[32]={0},new_key[32]={0},verify[32]={0};
    int ret=rsa_read_raw(type,index,&record);
    if(ret==SDR_OK && rsa_passwordless(&record)) ret=old_len==0?rsa_device_secret(type,index,record.salt,old_key):SDR_PRKRERR;
    else if(ret==SDR_OK) { ret=rsa_derive_password(old_password,old_len,record.salt,old_key); if(ret==SDR_OK)ret=rsa_make_verifier(old_key,verify); if(ret==SDR_OK&&!rsa_equal(verify,record.verifier,32))ret=SDR_PRKRERR; }
    if(ret==SDR_OK){ULONG length=sizeof(private_key);ret=crypto_symmetric_decrypt(SGD_SM4_CTR,old_key,16,record.salt,16,record.encrypted_private,sizeof(record.encrypted_private),(BYTE *)&private_key,&length);if(ret==SDR_OK&&length!=sizeof(private_key))ret=SDR_KEYERR;}
    if(ret==SDR_OK)ret=crypto_generate_random(16,record.salt);
    if(ret==SDR_OK)ret=new_len==0?rsa_device_secret(type,index,record.salt,new_key):rsa_derive_password(new_password,new_len,record.salt,new_key);
    memset(record.verifier,0,32);if(ret==SDR_OK&&new_len)ret=rsa_make_verifier(new_key,record.verifier);
    if(ret==SDR_OK){ULONG length=sizeof(record.encrypted_private);ret=crypto_symmetric_encrypt(SGD_SM4_CTR,new_key,16,record.salt,16,(BYTE *)&private_key,sizeof(private_key),record.encrypted_private,&length);if(ret==SDR_OK&&length!=sizeof(record.encrypted_private))ret=SDR_KEYERR;}
    if(ret==SDR_OK)ret=rsa_record_hmac(&record,record.integrity);if(ret==SDR_OK)ret=rsa_write_record(type,index,&record,0);
    rsa_wipe(&record,sizeof(record));rsa_wipe(&private_key,sizeof(private_key));rsa_wipe(old_key,32);rsa_wipe(new_key,32);rsa_wipe(verify,32);pthread_mutex_unlock(&g_rsa_key_mutex);return ret;
}

int rsa_key_admin_verify(uint32_t type, uint32_t index)
{
    rsa_key_record_t record; int ret=rsa_read_raw(type,index,&record); rsa_wipe(&record,sizeof(record)); return ret;
}

int rsa_key_admin_reindex(uint32_t type, uint32_t old_index, uint32_t new_index)
{
    if(old_index==new_index||old_index==0||new_index==0||old_index>1024||new_index>1024)return SDR_INARGERR;
    if(internal_key_admin_verify(type,new_index)==SDR_OK)return SDR_FILEEXISTS;
    char old_path[512],new_path[512],old_disabled[544]={0},new_disabled[544]={0};
    if(rsa_path(type,old_index,old_path,sizeof(old_path))!=SDR_OK||rsa_path(type,new_index,new_path,sizeof(new_path))!=SDR_OK)return SDR_INARGERR;
    pthread_mutex_lock(&g_rsa_key_mutex);if(access(new_path,F_OK)==0){pthread_mutex_unlock(&g_rsa_key_mutex);return SDR_FILEEXISTS;}
    rsa_key_record_t record;RSArefPrivateKey private_key;BYTE old_key[32]={0},new_key[32]={0};int ret=rsa_read_raw(type,old_index,&record);
    if(ret==SDR_OK&&rsa_passwordless(&record)){ret=rsa_device_secret(type,old_index,record.salt,old_key);if(ret==SDR_OK){ULONG length=sizeof(private_key);ret=crypto_symmetric_decrypt(SGD_SM4_CTR,old_key,16,record.salt,16,record.encrypted_private,sizeof(record.encrypted_private),(BYTE *)&private_key,&length);if(ret==SDR_OK&&length!=sizeof(private_key))ret=SDR_KEYERR;}if(ret==SDR_OK)ret=rsa_device_secret(type,new_index,record.salt,new_key);if(ret==SDR_OK){ULONG length=sizeof(record.encrypted_private);ret=crypto_symmetric_encrypt(SGD_SM4_CTR,new_key,16,record.salt,16,(BYTE *)&private_key,sizeof(private_key),record.encrypted_private,&length);if(ret==SDR_OK&&length!=sizeof(record.encrypted_private))ret=SDR_KEYERR;}}
    if(ret==SDR_OK){record.index=new_index;ret=rsa_record_hmac(&record,record.integrity);}if(ret==SDR_OK)ret=rsa_write_record(type,new_index,&record,1);
    if(ret==SDR_OK){int disabled=rsa_is_disabled(type,old_index);if(rsa_disabled_path(type,old_index,old_disabled,sizeof(old_disabled))!=SDR_OK||rsa_disabled_path(type,new_index,new_disabled,sizeof(new_disabled))!=SDR_OK)ret=SDR_FILEWERR;else if(disabled){int fd=open(new_disabled,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)ret=SDR_FILEWERR;else{fsync(fd);close(fd);}}if(ret==SDR_OK){unlink(old_path);unlink(old_disabled);}else{unlink(new_path);if(new_disabled[0])unlink(new_disabled);}}
    rsa_wipe(&record,sizeof(record));rsa_wipe(&private_key,sizeof(private_key));rsa_wipe(old_key,32);rsa_wipe(new_key,32);pthread_mutex_unlock(&g_rsa_key_mutex);return ret;
}

static void rsa_fingerprint(const RSArefPublicKey *key,char out[65])
{
    BYTE digest[32];ULONG len=32;static const char hex[]="0123456789abcdef";
    if(crypto_hash_digest(SGD_SM3,(const BYTE *)key,sizeof(*key),digest,&len)!=SDR_OK||len!=32){out[0]='\0';return;}
    for(size_t i=0;i<32;i++){out[i*2]=hex[digest[i]>>4];out[i*2+1]=hex[digest[i]&15];}out[64]='\0';rsa_wipe(digest,32);
}

int rsa_key_admin_list(BYTE *output,uint32_t *output_len,uint32_t *key_count)
{
    if(output==NULL||output_len==NULL||*output_len<3)return SDR_INARGERR;size_t capacity=*output_len,used=0;uint32_t count=0;output[used++]='[';
    pthread_mutex_lock(&g_rsa_key_mutex);
    for(uint32_t type=1;type<=2;type++)for(uint32_t index=1;index<=1024;index++){rsa_key_record_t record;int ret=rsa_read_raw(type,index,&record);if(ret==SDR_KEYNOTEXIST)continue;if(ret!=SDR_OK){pthread_mutex_unlock(&g_rsa_key_mutex);return ret;}char fp[65],path[512];struct stat st;long long created=0;rsa_fingerprint(&record.public_key,fp);if(rsa_path(type,index,path,sizeof(path))==SDR_OK&&stat(path,&st)==0)created=(long long)st.st_mtime;int n=snprintf((char *)output+used,capacity-used,"%s{\"type\":\"%s\",\"index\":%u,\"algorithm\":\"RSA\",\"purpose\":\"%s\",\"bits\":%u,\"enabled\":%s,\"integrity\":true,\"password_protected\":%s,\"created_at\":%lld,\"fingerprint\":\"%s\"}",count?",":"",type==1?"sign":"enc",index,type==1?"signature":"encryption",record.bits,rsa_is_disabled(type,index)?"false":"true",rsa_passwordless(&record)?"false":"true",created,fp);rsa_wipe(&record,sizeof(record));if(n<0||(size_t)n>=capacity-used){pthread_mutex_unlock(&g_rsa_key_mutex);return SDR_NOBUFFER;}used+=(size_t)n;count++;}
    pthread_mutex_unlock(&g_rsa_key_mutex);if(used+2>capacity)return SDR_NOBUFFER;output[used++]=']';output[used]='\0';*output_len=(uint32_t)used;if(key_count)*key_count=count;return SDR_OK;
}

int rsa_internal_public_operation(uint32_t index,const BYTE *input,uint32_t input_len,BYTE *output,uint32_t *output_len)
{RSArefPublicKey key;int ret=rsa_key_export_public(SDFX_INTERNAL_KEY_SIGN,index,&key);if(ret==SDR_OK)ret=crypto_rsa_public_operation(&key,input,input_len,output,output_len,0);rsa_wipe(&key,sizeof(key));return ret;}
int rsa_internal_private_operation(session_info_t *session,uint32_t index,const BYTE *input,uint32_t input_len,BYTE *output,uint32_t *output_len)
{RSArefPrivateKey key;int ret=rsa_load_private(session,SDFX_INTERNAL_KEY_SIGN,index,&key);if(ret==SDR_OK)ret=crypto_rsa_private_operation(&key,input,input_len,output,output_len,0);rsa_wipe(&key,sizeof(key));return ret;}

int rsa_generate_with_epk(session_info_t *session,const RSArefPublicKey *public_key,uint32_t key_bits,BYTE *wrapped,uint32_t *wrapped_len,uint64_t *key_id)
{if(session==NULL||public_key==NULL||wrapped==NULL||wrapped_len==NULL||key_id==NULL||(key_bits!=128&&key_bits!=256))return SDR_INARGERR;BYTE key[32];uint32_t len=key_bits/8;int ret=crypto_generate_random(len,key);if(ret==SDR_OK)ret=crypto_rsa_public_operation(public_key,key,len,wrapped,wrapped_len,1);if(ret==SDR_OK)ret=session_key_create(session,key,len,key_id);rsa_wipe(key,sizeof(key));return ret;}
int rsa_generate_with_ipk(session_info_t *session,uint32_t index,uint32_t key_bits,BYTE *wrapped,uint32_t *wrapped_len,uint64_t *key_id)
{RSArefPublicKey key;int ret=rsa_key_export_public(SDFX_INTERNAL_KEY_ENC,index,&key);if(ret==SDR_OK)ret=rsa_generate_with_epk(session,&key,key_bits,wrapped,wrapped_len,key_id);rsa_wipe(&key,sizeof(key));return ret;}
int rsa_import_with_isk(session_info_t *session,uint32_t index,const BYTE *wrapped,uint32_t wrapped_len,uint64_t *key_id)
{if(session==NULL||wrapped==NULL||key_id==NULL)return SDR_INARGERR;RSArefPrivateKey key;BYTE plain[32];uint32_t plain_len=sizeof(plain);int ret=rsa_load_private(session,SDFX_INTERNAL_KEY_ENC,index,&key);if(ret==SDR_OK)ret=crypto_rsa_private_operation(&key,wrapped,wrapped_len,plain,&plain_len,1);if(ret==SDR_OK&&plain_len!=16&&plain_len!=32)ret=SDR_KEYERR;if(ret==SDR_OK)ret=session_key_create(session,plain,plain_len,key_id);rsa_wipe(&key,sizeof(key));rsa_wipe(plain,sizeof(plain));return ret;}
