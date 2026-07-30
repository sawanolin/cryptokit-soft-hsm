/*
 * GM/T 0018 internal SM2 key and private-key access operations.
 */
#include "sdf_internal.h"

static LONG send_internal_blob(ULONG command, sdfx_remote_handle_t session_id,
                               const uint32_t params[4],
                               const BYTE *data, uint32_t data_len,
                               BYTE *response, size_t response_capacity,
                               size_t *response_len)
{
    if ((data_len > 0 && data == NULL) || data_len > SDFX_MAX_BLOB_LENGTH ||
        response == NULL || response_len == NULL) {
        return SDR_INARGERR;
    }
    size_t request_size = sizeof(sdfx_blob_req_t) + data_len;
    sdfx_blob_req_t *request = calloc(1, request_size);
    if (request == NULL) {
        return SDR_NOBUFFER;
    }
    request->session_handle = sdfx_htonll(session_id);
    for (size_t i = 0; i < 4; ++i) {
        request->param[i] = sdfx_htonl(params == NULL ? 0 : params[i]);
    }
    request->data_length = sdfx_htonl(data_len);
    if (data_len > 0) {
        memcpy(request->data, data, data_len);
    }
    LONG ret = sdf_send_request(command, request, request_size,
                                response, response_capacity, response_len);
    memset(request, 0, request_size);
    free(request);
    return ret;
}

static LONG create_local_key(const sdfx_blob_resp_t *response, HANDLE *key_handle)
{
    sdfx_remote_handle_t remote_id = sdfx_ntohll(response->object_handle);
    if (remote_id == 0 || key_handle == NULL) {
        return SDR_PROTOCOL_ERROR;
    }
    sdfx_remote_handle_t *stored_id = malloc(sizeof(*stored_id));
    if (stored_id == NULL) {
        return SDR_NOBUFFER;
    }
    *stored_id = remote_id;
    *key_handle = handle_manager_create_key_with_data(stored_id);
    if (*key_handle == NULL) {
        free(stored_id);
        return SDR_NOBUFFER;
    }
    return SDR_OK;
}

LONG SDF_GetPrivateKeyAccessRight(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                  LPSTR pucPassword, ULONG uiPwdLength)
{
    if (hSessionHandle == NULL || uiKeyIndex == 0 || uiPwdLength > 256 ||
        (uiPwdLength != 0 && pucPassword == NULL)) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    uint32_t params[4] = {uiKeyIndex, 0, 0, 0};
    BYTE response[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t)];
    size_t response_len = 0;
    return send_internal_blob(SDFX_CMD_GET_PRIVATE_ACCESS, session_id, params,
                              (const BYTE *)pucPassword, uiPwdLength,
                              response, sizeof(response), &response_len);
}

LONG SDF_ReleasePrivateKeyAccessRight(HANDLE hSessionHandle, ULONG uiKeyIndex)
{
    if (hSessionHandle == NULL || uiKeyIndex == 0) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    uint32_t params[4] = {uiKeyIndex, 0, 0, 0};
    BYTE response[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t)];
    size_t response_len = 0;
    return send_internal_blob(SDFX_CMD_RELEASE_PRIVATE_ACCESS, session_id,
                              params, NULL, 0, response, sizeof(response),
                              &response_len);
}

static LONG export_public_key(HANDLE session_handle, ULONG key_index,
                              ULONG command, ECCrefPublicKey *public_key)
{
    if (session_handle == NULL || key_index == 0 || public_key == NULL) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(session_handle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    uint32_t params[4] = {key_index, 0, 0, 0};
    BYTE response_buffer[sizeof(sdfx_message_header_t) +
                         sizeof(sdfx_blob_resp_t) + sizeof(ECCrefPublicKey)];
    size_t response_len = 0;
    ret = send_internal_blob(command, session_id, params, NULL, 0,
                             response_buffer, sizeof(response_buffer),
                             &response_len);
    if (ret != SDR_OK) {
        return ret;
    }
    sdfx_message_t *message = (sdfx_message_t *)response_buffer;
    sdfx_blob_resp_t *response = (sdfx_blob_resp_t *)message->data;
    uint32_t length = sdfx_ntohl(response->data_length);
    if (length != sizeof(*public_key) ||
        message->header.length < sizeof(*response) + length) {
        return SDR_PROTOCOL_ERROR;
    }
    memcpy(public_key, response->data, sizeof(*public_key));
    return SDR_OK;
}

LONG SDF_ExportSignPublicKey_ECC(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                 ECCrefPublicKey *pucPublicKey)
{
    return export_public_key(hSessionHandle, uiKeyIndex,
                             SDFX_CMD_EXPORT_SIGN_PUB_ECC, pucPublicKey);
}

LONG SDF_ExportEncPublicKey_ECC(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                ECCrefPublicKey *pucPublicKey)
{
    return export_public_key(hSessionHandle, uiKeyIndex,
                             SDFX_CMD_EXPORT_ENC_PUB_ECC, pucPublicKey);
}

static LONG parse_wrapped_key(const BYTE *response_buffer, ECCCipher *wrapped,
                              HANDLE *key_handle)
{
    const sdfx_message_t *message = (const sdfx_message_t *)response_buffer;
    const sdfx_blob_resp_t *response = (const sdfx_blob_resp_t *)message->data;
    uint32_t data_len = sdfx_ntohl(response->data_length);
    if (data_len < sizeof(ECCCipher) ||
        data_len > sizeof(ECCCipher) + 31 ||
        message->header.length < sizeof(*response) + data_len) {
        return SDR_PROTOCOL_ERROR;
    }
    uint32_t cipher_len = sdfx_ntohl(((const ECCCipher *)response->data)->L);
    if (cipher_len == 0 || cipher_len > 32 ||
        data_len != sizeof(ECCCipher) + cipher_len - 1) {
        return SDR_PROTOCOL_ERROR;
    }
    memcpy(wrapped, response->data, data_len);
    wrapped->L = cipher_len;
    return create_local_key(response, key_handle);
}

LONG SDF_GenerateKeyWithIPK_ECC(HANDLE hSessionHandle, ULONG uiIPKIndex,
                                ULONG uiKeyBits, ECCCipher *pucKey,
                                HANDLE *phKeyHandle)
{
    if (hSessionHandle == NULL || uiIPKIndex == 0 ||
        (uiKeyBits != 128 && uiKeyBits != 256) ||
        pucKey == NULL || phKeyHandle == NULL) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    uint32_t params[4] = {uiIPKIndex, uiKeyBits, 0, 0};
    BYTE response[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t) +
                  sizeof(ECCCipher) + 31];
    size_t response_len = 0;
    ret = send_internal_blob(SDFX_CMD_GENERATE_KEY_IPK_ECC, session_id,
                             params, NULL, 0, response, sizeof(response),
                             &response_len);
    return ret == SDR_OK ? parse_wrapped_key(response, pucKey, phKeyHandle) : ret;
}

LONG SDF_GenerateKeyWithEPK_ECC(HANDLE hSessionHandle, ULONG uiKeyBits,
                                ULONG uiAlgID, ECCrefPublicKey *pucPublicKey,
                                ECCCipher *pucKey, HANDLE *phKeyHandle)
{
    if (hSessionHandle == NULL || (uiKeyBits != 128 && uiKeyBits != 256) ||
        uiAlgID != SGD_SM2_3 || pucPublicKey == NULL ||
        pucKey == NULL || phKeyHandle == NULL) {
        return uiAlgID == SGD_SM2_3 ? SDR_INARGERR : SDR_ALGNOTSUPPORT;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    uint32_t params[4] = {uiKeyBits, uiAlgID, 0, 0};
    BYTE response[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t) +
                  sizeof(ECCCipher) + 31];
    size_t response_len = 0;
    ret = send_internal_blob(SDFX_CMD_GENERATE_KEY_EPK_ECC, session_id,
                             params, (const BYTE *)pucPublicKey,
                             sizeof(*pucPublicKey), response, sizeof(response),
                             &response_len);
    return ret == SDR_OK ? parse_wrapped_key(response, pucKey, phKeyHandle) : ret;
}

LONG SDF_ImportKeyWithISK_ECC(HANDLE hSessionHandle, ULONG uiISKIndex,
                              ECCCipher *pucKey, HANDLE *phKeyHandle)
{
    if (hSessionHandle == NULL || uiISKIndex == 0 || pucKey == NULL ||
        phKeyHandle == NULL || pucKey->L == 0 || pucKey->L > 32) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    size_t cipher_size = sizeof(ECCCipher) + pucKey->L - 1;
    BYTE cipher_buffer[sizeof(ECCCipher) + 31];
    memcpy(cipher_buffer, pucKey, cipher_size);
    ((ECCCipher *)cipher_buffer)->L = sdfx_htonl(pucKey->L);

    uint32_t params[4] = {uiISKIndex, 0, 0, 0};
    BYTE response[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t)];
    size_t response_len = 0;
    ret = send_internal_blob(SDFX_CMD_IMPORT_KEY_ISK_ECC, session_id, params,
                             cipher_buffer, (uint32_t)cipher_size,
                             response, sizeof(response), &response_len);
    memset(cipher_buffer, 0, sizeof(cipher_buffer));
    if (ret != SDR_OK) {
        return ret;
    }
    return create_local_key((const sdfx_blob_resp_t *)
                            ((const sdfx_message_t *)response)->data,
                            phKeyHandle);
}
