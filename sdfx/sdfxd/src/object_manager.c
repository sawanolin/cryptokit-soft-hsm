/*
 * Server-side object management for the software SDF device.
 * Session key material is never serialized to the client.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "daemon_internal.h"

static pthread_mutex_t g_storage_mutex = PTHREAD_MUTEX_INITIALIZER;

static void secure_clear(void *ptr, size_t len)
{
    volatile BYTE *p = (volatile BYTE *)ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
}

static const char *storage_root(void)
{
    const char *root = getenv("SDFX_DATA_DIR");
    return (root != NULL && root[0] != '\0') ? root : "/var/lib/sdfx";
}

static int ensure_dir(const char *path)
{
    if (mkdir(path, 0700) == 0 || errno == EEXIST) {
        return SDR_OK;
    }
    return SDR_FILEWERR;
}

static int ensure_storage_tree(void)
{
    char path[512];
    int n;

    if (ensure_dir(storage_root()) != SDR_OK) {
        return SDR_FILEWERR;
    }
    n = snprintf(path, sizeof(path), "%s/keys", storage_root());
    if (n <= 0 || (size_t)n >= sizeof(path) || ensure_dir(path) != SDR_OK) {
        return SDR_FILEWERR;
    }
    n = snprintf(path, sizeof(path), "%s/keys/kek", storage_root());
    if (n <= 0 || (size_t)n >= sizeof(path) || ensure_dir(path) != SDR_OK) {
        return SDR_FILEWERR;
    }
    n = snprintf(path, sizeof(path), "%s/files", storage_root());
    if (n <= 0 || (size_t)n >= sizeof(path) || ensure_dir(path) != SDR_OK) {
        return SDR_FILEWERR;
    }
    return SDR_OK;
}

int session_key_create(session_info_t *session, const BYTE *key, uint32_t key_len,
                       uint64_t *key_id)
{
    if (session == NULL || key == NULL || key_id == NULL ||
        key_len == 0 || key_len > sizeof(((session_key_t *)0)->key)) {
        return SDR_INARGERR;
    }

    session_key_t *entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
        return SDR_NOBUFFER;
    }
    memcpy(entry->key, key, key_len);
    entry->key_len = key_len;

    pthread_mutex_lock(&session->object_mutex);
    uint32_t local_id = ++session->next_key_id;
    if (local_id == 0) {
        local_id = ++session->next_key_id;
    }
    entry->key_id = ((uint64_t)session->session_id << 32) | local_id;
    entry->next = session->keys;
    session->keys = entry;
    *key_id = entry->key_id;
    pthread_mutex_unlock(&session->object_mutex);
    return SDR_OK;
}

int session_key_get(session_info_t *session, uint64_t key_id, BYTE *key,
                    uint32_t *key_len)
{
    if (session == NULL || key == NULL || key_len == NULL || key_id == 0) {
        return SDR_INARGERR;
    }
    if ((uint32_t)(key_id >> 32) != session->session_id) {
        return SDR_KEYNOTEXIST;
    }

    int ret = SDR_KEYNOTEXIST;
    pthread_mutex_lock(&session->object_mutex);
    for (session_key_t *entry = session->keys; entry != NULL; entry = entry->next) {
        if (entry->key_id == key_id) {
            if (*key_len < entry->key_len) {
                *key_len = entry->key_len;
                ret = SDR_NOBUFFER;
            } else {
                memcpy(key, entry->key, entry->key_len);
                *key_len = entry->key_len;
                ret = SDR_OK;
            }
            break;
        }
    }
    pthread_mutex_unlock(&session->object_mutex);
    return ret;
}

int session_key_destroy(session_info_t *session, uint64_t key_id)
{
    if (session == NULL || key_id == 0) {
        return SDR_INARGERR;
    }

    pthread_mutex_lock(&session->object_mutex);
    session_key_t *entry = session->keys;
    session_key_t *prev = NULL;
    while (entry != NULL && entry->key_id != key_id) {
        prev = entry;
        entry = entry->next;
    }
    if (entry == NULL) {
        pthread_mutex_unlock(&session->object_mutex);
        return SDR_KEYNOTEXIST;
    }
    if (prev == NULL) {
        session->keys = entry->next;
    } else {
        prev->next = entry->next;
    }
    secure_clear(entry, sizeof(*entry));
    free(entry);
    pthread_mutex_unlock(&session->object_mutex);
    return SDR_OK;
}

void session_objects_cleanup(session_info_t *session)
{
    if (session == NULL) {
        return;
    }
    pthread_mutex_lock(&session->object_mutex);
    session_key_t *entry = session->keys;
    session->keys = NULL;
    while (entry != NULL) {
        session_key_t *next = entry->next;
        secure_clear(entry, sizeof(*entry));
        free(entry);
        entry = next;
    }
    private_key_permission_t *permission = session->private_permissions;
    session->private_permissions = NULL;
    while (permission != NULL) {
        private_key_permission_t *next = permission->next;
        secure_clear(permission, sizeof(*permission));
        free(permission);
        permission = next;
    }
    rsa_private_key_permission_t *rsa_permission = session->rsa_private_permissions;
    session->rsa_private_permissions = NULL;
    while (rsa_permission != NULL) {
        rsa_private_key_permission_t *next = rsa_permission->next;
        secure_clear(rsa_permission, sizeof(*rsa_permission));
        free(rsa_permission);
        rsa_permission = next;
    }
    pthread_mutex_unlock(&session->object_mutex);
}

static int kek_is_disabled(uint32_t index);
static int load_kek(uint32_t index, BYTE kek[16]);

int kek_generate_wrapped(session_info_t *session, uint32_t key_bits,
                         uint32_t alg_id, uint32_t kek_index,
                         BYTE *wrapped, uint32_t *wrapped_len,
                         uint64_t *key_id)
{
    if (session == NULL || wrapped == NULL || wrapped_len == NULL || key_id == NULL ||
        (key_bits != 128 && key_bits != 256) || alg_id != SGD_SM4_ECB) {
        return alg_id == SGD_SM4_ECB ? SDR_INARGERR : SDR_ALGMODNOTSUPPORT;
    }

    uint32_t key_len = key_bits / 8;
    if (*wrapped_len < key_len) {
        *wrapped_len = key_len;
        return SDR_NOBUFFER;
    }

    BYTE kek[16];
    BYTE key[32];
    int ret = load_kek(kek_index, kek);
    if (ret == SDR_OK) {
        ret = crypto_generate_random(key_len, key);
    }
    if (ret == SDR_OK) {
        ULONG out_len = *wrapped_len;
        ret = crypto_symmetric_encrypt(SGD_SM4_ECB, kek, sizeof(kek), NULL, 0,
                                       key, key_len, wrapped, &out_len);
        *wrapped_len = out_len;
    }
    if (ret == SDR_OK) {
        ret = session_key_create(session, key, key_len, key_id);
    }
    secure_clear(kek, sizeof(kek));
    secure_clear(key, sizeof(key));
    return ret;
}

int kek_import_wrapped(session_info_t *session, uint32_t alg_id,
                       uint32_t kek_index, const BYTE *wrapped,
                       uint32_t wrapped_len, uint64_t *key_id)
{
    if (session == NULL || wrapped == NULL || key_id == NULL ||
        (wrapped_len != 16 && wrapped_len != 32) || alg_id != SGD_SM4_ECB) {
        return alg_id == SGD_SM4_ECB ? SDR_INARGERR : SDR_ALGMODNOTSUPPORT;
    }

    BYTE kek[16];
    BYTE key[32];
    int ret = load_kek(kek_index, kek);
    if (ret == SDR_OK) {
        ULONG key_len = sizeof(key);
        ret = crypto_symmetric_decrypt(SGD_SM4_ECB, kek, sizeof(kek), NULL, 0,
                                       wrapped, wrapped_len, key, &key_len);
        if (ret == SDR_OK && key_len != wrapped_len) {
            ret = SDR_KEYERR;
        }
        if (ret == SDR_OK) {
            ret = session_key_create(session, key, key_len, key_id);
        }
    }
    secure_clear(kek, sizeof(kek));
    secure_clear(key, sizeof(key));
    return ret;
}

int crypto_calculate_mac(session_info_t *session, uint64_t key_id,
                         uint32_t alg_id, const BYTE *iv,
                         const BYTE *data, uint32_t data_len,
                         BYTE *mac, uint32_t *mac_len)
{
    if (session == NULL || data == NULL || mac == NULL || mac_len == NULL ||
        alg_id != SGD_SM4_MAC || data_len == 0 || (data_len % 16) != 0) {
        return alg_id == SGD_SM4_MAC ? SDR_INARGERR : SDR_ALGMODNOTSUPPORT;
    }
    if (*mac_len < 16) {
        *mac_len = 16;
        return SDR_NOBUFFER;
    }

    BYTE key[64];
    uint32_t key_len = sizeof(key);
    int ret = session_key_get(session, key_id, key, &key_len);
    if (ret != SDR_OK) {
        secure_clear(key, sizeof(key));
        return ret;
    }

    BYTE zero_iv[16] = {0};
    BYTE *output = malloc(data_len);
    if (output == NULL) {
        secure_clear(key, sizeof(key));
        return SDR_NOBUFFER;
    }
    ULONG output_len = data_len;
    ret = crypto_symmetric_encrypt(SGD_SM4_CBC, key, key_len,
                                   iv != NULL ? iv : zero_iv, 16,
                                   data, data_len, output, &output_len);
    if (ret == SDR_OK && output_len == data_len) {
        memcpy(mac, output + output_len - 16, 16);
        *mac_len = 16;
    } else if (ret == SDR_OK) {
        ret = SDR_MACERR;
    }
    secure_clear(key, sizeof(key));
    secure_clear(output, data_len);
    free(output);
    return ret;
}

static int build_file_path(const BYTE *name, uint32_t name_len, char *path, size_t path_len)
{
    if (name == NULL || path == NULL || name_len == 0 || name_len > SDFX_MAX_FILE_NAME) {
        return SDR_INARGERR;
    }
    if (ensure_storage_tree() != SDR_OK) {
        return SDR_FILEWERR;
    }

    int n = snprintf(path, path_len, "%s/files/", storage_root());
    if (n <= 0 || (size_t)n >= path_len) {
        return SDR_FILEWERR;
    }
    size_t used = (size_t)n;
    static const char hex[] = "0123456789abcdef";
    if (used + (size_t)name_len * 2 + 1 > path_len) {
        return SDR_FILEWERR;
    }
    for (uint32_t i = 0; i < name_len; ++i) {
        path[used++] = hex[name[i] >> 4];
        path[used++] = hex[name[i] & 0x0f];
    }
    path[used] = '\0';
    return SDR_OK;
}

int user_file_create(const BYTE *name, uint32_t name_len, uint32_t file_size)
{
    if (file_size > SDFX_MAX_FILE_SIZE) {
        return SDR_FILESIZEERR;
    }
    char path[1024];
    int ret = build_file_path(name, name_len, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return errno == EEXIST ? SDR_FILEEXISTS : SDR_FILEWERR;
    }
    ret = ftruncate(fd, (off_t)file_size) == 0 ? SDR_OK : SDR_FILEWERR;
    close(fd);
    return ret;
}

int user_file_read(const BYTE *name, uint32_t name_len, uint32_t offset,
                   BYTE *buffer, uint32_t *length)
{
    if (buffer == NULL || length == NULL) {
        return SDR_OUTARGERR;
    }
    char path[1024];
    int ret = build_file_path(name, name_len, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return SDR_FILENOEXIST;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || offset > (uint64_t)st.st_size) {
        close(fd);
        return SDR_FILEOFSERR;
    }
    uint32_t available = (uint32_t)st.st_size - offset;
    uint32_t wanted = *length < available ? *length : available;
    ssize_t got = pread(fd, buffer, wanted, (off_t)offset);
    close(fd);
    if (got < 0) {
        return SDR_FILENOEXIST;
    }
    *length = (uint32_t)got;
    return SDR_OK;
}

int user_file_write(const BYTE *name, uint32_t name_len, uint32_t offset,
                    const BYTE *buffer, uint32_t length)
{
    if (buffer == NULL || length == 0) {
        return SDR_INARGERR;
    }
    char path[1024];
    int ret = build_file_path(name, name_len, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return SDR_FILENOEXIST;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || offset > (uint64_t)st.st_size ||
        length > (uint64_t)st.st_size - offset) {
        close(fd);
        return SDR_FILEOFSERR;
    }
    ssize_t written = pwrite(fd, buffer, length, (off_t)offset);
    if (written == (ssize_t)length && fsync(fd) != 0) {
        written = -1;
    }
    close(fd);
    return written == (ssize_t)length ? SDR_OK : SDR_FILEWERR;
}

int user_file_delete(const BYTE *name, uint32_t name_len)
{
    char path[1024];
    int ret = build_file_path(name, name_len, path, sizeof(path));
    if (ret != SDR_OK) {
        return ret;
    }
    if (unlink(path) == 0) {
        return SDR_OK;
    }
    return errno == ENOENT ? SDR_FILENOEXIST : SDR_FILEWERR;
}

#include "kek_admin.inc"
#include "backup_admin.inc"
