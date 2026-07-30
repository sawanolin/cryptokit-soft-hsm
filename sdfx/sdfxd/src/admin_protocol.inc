/*
 * Private Web-management protocol.  It deliberately reuses the existing TCP
 * transport instead of opening a second management socket.  Every request is
 * authenticated with the per-container 32-byte token generated at startup.
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define SDFX_ADMIN_TOKEN_LENGTH 32U
#define SDFX_ADMIN_TOKEN_DEFAULT_FILE "/run/sdfx/admin.token"

#include "admin_device.inc"
#include "admin_session.inc"
#include "admin_selftest.inc"

static int admin_read_token(BYTE token[SDFX_ADMIN_TOKEN_LENGTH])
{
    const char *path = getenv("SDFX_ADMIN_TOKEN_FILE");
    if (path == NULL || path[0] == '\0') {
        path = SDFX_ADMIN_TOKEN_DEFAULT_FILE;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return SDR_PARDENY;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size != SDFX_ADMIN_TOKEN_LENGTH) {
        close(fd);
        return SDR_PARDENY;
    }

    size_t offset = 0;
    while (offset < SDFX_ADMIN_TOKEN_LENGTH) {
        ssize_t got = read(fd, token + offset, SDFX_ADMIN_TOKEN_LENGTH - offset);
        if (got <= 0) {
            close(fd);
            memset(token, 0, SDFX_ADMIN_TOKEN_LENGTH);
            return SDR_PARDENY;
        }
        offset += (size_t)got;
    }
    close(fd);
    return SDR_OK;
}

static int admin_token_matches(const BYTE supplied[SDFX_ADMIN_TOKEN_LENGTH])
{
    BYTE expected[SDFX_ADMIN_TOKEN_LENGTH] = {0};
    int ret = admin_read_token(expected);
    unsigned int difference = 0;
    if (ret == SDR_OK) {
        for (size_t i = 0; i < SDFX_ADMIN_TOKEN_LENGTH; ++i) {
            difference |= supplied[i] ^ expected[i];
        }
        ret = difference == 0 ? SDR_OK : SDR_PARDENY;
    }
    memset(expected, 0, sizeof(expected));
    return ret;
}

static int handle_admin_command(daemon_context_t *ctx, ULONG cmd,
                                const sdfx_blob_req_t *req, size_t request_len,
                                sdfx_blob_resp_t *resp)
{
    if (ctx == NULL || req == NULL || resp == NULL ||
        request_len < sizeof(*req)) {
        return SDR_PROTOCOL_ERROR;
    }

    uint32_t data_len = sdfx_ntohl(req->data_length);
    if (data_len < SDFX_ADMIN_TOKEN_LENGTH ||
        data_len > SDFX_MAX_BLOB_LENGTH ||
        request_len != sizeof(*req) + data_len) {
        return SDR_PROTOCOL_ERROR;
    }
    int ret = admin_token_matches(req->data);
    if (ret != SDR_OK) {
        return ret;
    }

    const BYTE *secret = req->data + SDFX_ADMIN_TOKEN_LENGTH;
    uint32_t secret_len = data_len - SDFX_ADMIN_TOKEN_LENGTH;
    uint32_t p0 = sdfx_ntohl(req->param[0]);
    uint32_t p1 = sdfx_ntohl(req->param[1]);
    uint32_t p2 = sdfx_ntohl(req->param[2]);
    uint32_t p3 = sdfx_ntohl(req->param[3]);
    uint32_t output_len = 0;
    resp->object_handle = 0;

    switch (cmd) {
        case SDFX_CMD_ADMIN_STATUS: {
            if (secret_len != 0) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            uint32_t key_count = 0;
            uint32_t rsa_key_count = 0;
            output_len = SDFX_MAX_BLOB_LENGTH;
            ret = internal_key_admin_list(resp->data, &output_len, &key_count);
            if (ret == SDR_OK) {
                output_len = SDFX_MAX_BLOB_LENGTH;
                ret = rsa_key_admin_list(resp->data, &output_len, &rsa_key_count);
                key_count += rsa_key_count;
            }
            if (ret == SDR_OK) {
                int written = snprintf((char *)resp->data,
                                       SDFX_MAX_BLOB_LENGTH,
                    "{\"service\":\"sdfxd\",\"status\":\"running\","
                    "\"total_requests\":%llu,\"active_sessions\":%u,"
                    "\"keys\":%u}",
                    (unsigned long long)ctx->total_requests,
                    ctx->active_sessions_count, key_count);
                if (written < 0 || written >= (int)SDFX_MAX_BLOB_LENGTH) {
                    ret = SDR_NOBUFFER;
                } else {
                    output_len = (uint32_t)written;
                }
            }
            break;
        }
        case SDFX_CMD_ADMIN_KEY_LIST:
            if (secret_len != 0) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            output_len = SDFX_MAX_BLOB_LENGTH;
            ret = internal_key_admin_list(resp->data, &output_len, NULL);
            break;
        case SDFX_CMD_ADMIN_KEY_CREATE:
            if ((secret_len != 0 && secret_len < 8) || secret_len > 256) {
                ret = SDR_INARGERR;
                break;
            }
            ret = internal_key_admin_create(p0, p1, secret, secret_len);
            break;
        case SDFX_CMD_ADMIN_KEY_DELETE:
            ret = secret_len == 0
                ? internal_key_admin_delete(p0, p1) : SDR_PROTOCOL_ERROR;
            break;
        case SDFX_CMD_ADMIN_KEY_ENABLE:
        case SDFX_CMD_ADMIN_KEY_DISABLE:
            ret = secret_len == 0
                ? internal_key_admin_set_enabled(
                    p0, p1, cmd == SDFX_CMD_ADMIN_KEY_ENABLE)
                : SDR_PROTOCOL_ERROR;
            break;
        case SDFX_CMD_ADMIN_KEY_PUBLIC:
            if (secret_len != 0) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            output_len = sizeof(ECCrefPublicKey);
            ret = internal_key_admin_export_public(
                p0, p1, (ECCrefPublicKey *)resp->data);
            break;
        case SDFX_CMD_ADMIN_KEY_PASSWORD:
            if ((p2 != 0 && p2 < 8) || (p3 != 0 && p3 < 8) ||
                p2 > 256 || p3 > 256 || p2 + p3 != secret_len) {
                ret = SDR_INARGERR;
                break;
            }
            ret = internal_key_admin_change_password(
                p0, p1, secret, p2, secret + p2, p3);
            break;
        case SDFX_CMD_ADMIN_INTEGRITY_INIT:
            ret = secret_len == 0
                ? internal_key_admin_integrity_init() : SDR_PROTOCOL_ERROR;
            break;
        case SDFX_CMD_ADMIN_KEY_VERIFY:
            if (secret_len != 0) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            ret = internal_key_admin_verify(p0, p1);
            if (ret == SDR_OK) {
                int written = snprintf((char *)resp->data, SDFX_MAX_BLOB_LENGTH,
                    "{\"type\":\"%s\",\"index\":%u,\"algorithm\":\"HMAC-SM3\",\"valid\":true}",
                    p0 == SDFX_INTERNAL_KEY_SIGN ? "sign" : "enc", p1);
                if (written < 0 || written >= (int)SDFX_MAX_BLOB_LENGTH) ret = SDR_NOBUFFER;
                else output_len = (uint32_t)written;
            }
            break;
        case SDFX_CMD_ADMIN_KEY_REINDEX:
            ret = secret_len == 0
                ? internal_key_admin_reindex(p0, p1, p2) : SDR_PROTOCOL_ERROR;
            break;
        case SDFX_CMD_ADMIN_RSA_KEY_LIST:
            if (secret_len != 0) { ret = SDR_PROTOCOL_ERROR; break; }
            output_len = SDFX_MAX_BLOB_LENGTH;
            ret = rsa_key_admin_list(resp->data, &output_len, NULL);
            break;
        case SDFX_CMD_ADMIN_RSA_KEY_CREATE:
            if ((secret_len != 0 && secret_len < 8) || secret_len > 256) {
                ret = SDR_INARGERR; break;
            }
            ret = rsa_key_admin_create(p0, p1, p2, secret, secret_len);
            break;
        case SDFX_CMD_ADMIN_RSA_KEY_DELETE:
            ret = secret_len == 0 ? rsa_key_admin_delete(p0, p1) : SDR_PROTOCOL_ERROR;
            break;
        case SDFX_CMD_ADMIN_RSA_KEY_ENABLE:
        case SDFX_CMD_ADMIN_RSA_KEY_DISABLE:
            ret = secret_len == 0 ? rsa_key_admin_set_enabled(
                p0, p1, cmd == SDFX_CMD_ADMIN_RSA_KEY_ENABLE) : SDR_PROTOCOL_ERROR;
            break;
        case SDFX_CMD_ADMIN_RSA_KEY_PUBLIC:
            if (secret_len != 0) { ret = SDR_PROTOCOL_ERROR; break; }
            output_len = sizeof(RSArefPublicKey);
            ret = rsa_key_admin_export_public(p0, p1, (RSArefPublicKey *)resp->data);
            break;
        case SDFX_CMD_ADMIN_RSA_KEY_PASSWORD:
            if ((p2 != 0 && p2 < 8) || (p3 != 0 && p3 < 8) ||
                p2 > 256 || p3 > 256 || p2 + p3 != secret_len) {
                ret = SDR_INARGERR; break;
            }
            ret = rsa_key_admin_change_password(p0, p1, secret, p2, secret + p2, p3);
            break;
        case SDFX_CMD_ADMIN_RSA_KEY_VERIFY:
            if (secret_len != 0) { ret = SDR_PROTOCOL_ERROR; break; }
            ret = rsa_key_admin_verify(p0, p1);
            if (ret == SDR_OK) {
                int written = snprintf((char *)resp->data, SDFX_MAX_BLOB_LENGTH,
                    "{\"type\":\"%s\",\"index\":%u,\"algorithm\":\"HMAC-SM3\",\"valid\":true}",
                    p0 == SDFX_INTERNAL_KEY_SIGN ? "sign" : "enc", p1);
                if (written < 0 || written >= (int)SDFX_MAX_BLOB_LENGTH) ret = SDR_NOBUFFER;
                else output_len = (uint32_t)written;
            }
            break;
        case SDFX_CMD_ADMIN_RSA_KEY_REINDEX:
            ret = secret_len == 0 ? rsa_key_admin_reindex(p0, p1, p2) : SDR_PROTOCOL_ERROR;
            break;
        case SDFX_CMD_ADMIN_DEVICE_CONFIG:
            ret = p3 == 0
                ? admin_device_info_update(secret, secret_len, p0, p1, p2)
                : SDR_PROTOCOL_ERROR;
            break;
        case SDFX_CMD_ADMIN_SESSION_LIST:
            if (secret_len != 0) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            output_len = SDFX_MAX_BLOB_LENGTH;
            ret = admin_session_list(ctx, resp->data, &output_len);
            break;
        case SDFX_CMD_ADMIN_SESSION_CLOSE:
            ret = secret_len == 0 && p0 != 0
                ? session_manager_close_session(ctx, p0)
                : SDR_INARGERR;
            break;
        case SDFX_CMD_ADMIN_KEK_LIST:
            if (secret_len != 0) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            output_len = SDFX_MAX_BLOB_LENGTH;
            ret = kek_admin_list(resp->data, &output_len, NULL);
            break;
        case SDFX_CMD_ADMIN_KEK_CREATE:
            ret = secret_len == 0 ? kek_admin_create(p0) : SDR_PROTOCOL_ERROR;
            break;
        case SDFX_CMD_ADMIN_KEK_DELETE:
            ret = secret_len == 0 ? kek_admin_delete(p0) : SDR_PROTOCOL_ERROR;
            break;
        case SDFX_CMD_ADMIN_KEK_ENABLE:
        case SDFX_CMD_ADMIN_KEK_DISABLE:
            ret = secret_len == 0
                ? kek_admin_set_enabled(p0, cmd == SDFX_CMD_ADMIN_KEK_ENABLE)
                : SDR_PROTOCOL_ERROR;
            break;
        case SDFX_CMD_ADMIN_BACKUP_LIST:
            if (secret_len != 0) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            output_len = SDFX_MAX_BLOB_LENGTH;
            ret = backup_admin_list(resp->data, &output_len);
            break;
        case SDFX_CMD_ADMIN_BACKUP_CREATE:
            ret = backup_admin_create(ctx, secret, secret_len);
            break;
        case SDFX_CMD_ADMIN_BACKUP_RESTORE:
            ret = backup_admin_restore(ctx, secret, secret_len);
            if (ret == SDR_OK) {
                ret = admin_device_info_load();
            }
            break;
        case SDFX_CMD_ADMIN_BACKUP_DELETE:
            ret = backup_admin_delete(secret, secret_len);
            break;
        case SDFX_CMD_ADMIN_DEVICE_RESET:
            ret = secret_len == 0
                ? backup_admin_reset(ctx) : SDR_PROTOCOL_ERROR;
            if (ret == SDR_OK) {
                admin_device_info_reset_runtime();
            }
            break;
        case SDFX_CMD_ADMIN_SELFTEST:
            if (secret_len != 0) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            output_len = SDFX_MAX_BLOB_LENGTH;
            ret = admin_crypto_selftest(resp->data, &output_len);
            break;
        default:
            ret = SDR_NOTSUPPORT;
            break;
    }

    if (ret == SDR_OK) {
        resp->data_length = sdfx_htonl(output_len);
    }
    return ret;
}



