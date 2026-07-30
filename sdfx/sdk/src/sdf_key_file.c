/*
 * GM/T 0018-2023 session-key, MAC and user-file client operations.
 */
#include "sdf_internal.h"

static LONG send_blob_request(ULONG cmd, sdfx_remote_handle_t session_id,
                              sdfx_remote_handle_t object_id,
                              const uint32_t param[4],
                              const BYTE *data, uint32_t data_len,
                              BYTE *response, size_t response_size,
                              size_t *actual_size)
{
    if (data_len > SDFX_MAX_BLOB_LENGTH ||
        (data_len > 0 && data == NULL) || response == NULL || actual_size == NULL) {
        return SDR_INARGERR;
    }

    size_t request_size = sizeof(sdfx_blob_req_t) + data_len;
    sdfx_blob_req_t *request = calloc(1, request_size);
    if (request == NULL) {
        return SDR_NOBUFFER;
    }
    request->session_handle = sdfx_htonll(session_id);
    request->object_handle = sdfx_htonll(object_id);
    for (size_t i = 0; i < 4; ++i) {
        request->param[i] = sdfx_htonl(param == NULL ? 0 : param[i]);
    }
    request->data_length = sdfx_htonl(data_len);
    if (data_len > 0) {
        memcpy(request->data, data, data_len);
    }

    LONG ret = sdf_send_request(cmd, request, request_size,
                                response, response_size, actual_size);
    free(request);
    return ret;
}

static LONG create_local_key(const sdfx_blob_resp_t *response, HANDLE *key_handle)
{
    if (response == NULL || key_handle == NULL) {
        return SDR_OUTARGERR;
    }
    sdfx_remote_handle_t remote_id = sdfx_ntohll(response->object_handle);
    if (remote_id == 0) {
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

LONG SDF_GenerateKeyWithKEK(HANDLE hSessionHandle, ULONG uiKeyBits,
                            ULONG uiAlgID, ULONG uiKEKIndex,
                            BYTE *pucKey, ULONG *puiKeyLength,
                            HANDLE *phKeyHandle)
{
    if (hSessionHandle == NULL || pucKey == NULL || puiKeyLength == NULL ||
        phKeyHandle == NULL) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }

    uint32_t param[4] = {uiKeyBits, uiAlgID, uiKEKIndex, 0};
    BYTE response_buffer[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t) + 64];
    size_t response_len = 0;
    ret = send_blob_request(SDFX_CMD_GENERATE_KEY_KEK, session_id, 0, param,
                            NULL, 0, response_buffer, sizeof(response_buffer),
                            &response_len);
    if (ret != SDR_OK) {
        return ret;
    }

    sdfx_message_t *message = (sdfx_message_t *)response_buffer;
    sdfx_blob_resp_t *response = (sdfx_blob_resp_t *)message->data;
    uint32_t wrapped_len = sdfx_ntohl(response->data_length);
    if (wrapped_len > 64 ||
        message->header.length < sizeof(*response) + wrapped_len) {
        return SDR_PROTOCOL_ERROR;
    }
    if (*puiKeyLength < wrapped_len) {
        *puiKeyLength = wrapped_len;
        return SDR_NOBUFFER;
    }
    memcpy(pucKey, response->data, wrapped_len);
    *puiKeyLength = wrapped_len;
    return create_local_key(response, phKeyHandle);
}

LONG SDF_ImportKeyWithKEK(HANDLE hSessionHandle, ULONG uiAlgID,
                          ULONG uiKEKIndex, BYTE *pucKey,
                          ULONG uiKeyLength, HANDLE *phKeyHandle)
{
    if (hSessionHandle == NULL || pucKey == NULL || phKeyHandle == NULL ||
        uiKeyLength == 0 || uiKeyLength > 64) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }

    uint32_t param[4] = {uiAlgID, uiKEKIndex, uiKeyLength, 0};
    BYTE response_buffer[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t)];
    size_t response_len = 0;
    ret = send_blob_request(SDFX_CMD_IMPORT_KEY_KEK, session_id, 0, param,
                            pucKey, uiKeyLength, response_buffer,
                            sizeof(response_buffer), &response_len);
    if (ret != SDR_OK) {
        return ret;
    }
    sdfx_message_t *message = (sdfx_message_t *)response_buffer;
    return create_local_key((sdfx_blob_resp_t *)message->data, phKeyHandle);
}

LONG SDF_DestroyKey(HANDLE hSessionHandle, HANDLE hKeyHandle)
{
    if (hSessionHandle == NULL || hKeyHandle == NULL) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    sdfx_remote_handle_t key_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret == SDR_OK) {
        ret = sdf_get_server_key_id(hKeyHandle, &key_id);
    }
    if (ret != SDR_OK) {
        return ret;
    }

    uint32_t param[4] = {0};
    BYTE response_buffer[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t)];
    size_t response_len = 0;
    ret = send_blob_request(SDFX_CMD_DESTROY_KEY, session_id, key_id, param,
                            NULL, 0, response_buffer, sizeof(response_buffer),
                            &response_len);
    if (ret == SDR_OK) {
        handle_manager_destroy(hKeyHandle);
    }
    return ret;
}

LONG SDF_CalculateMAC(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                      BYTE *pucIV, BYTE *pucData, ULONG uiDataLength,
                      BYTE *pucMac, ULONG *puiMacLength)
{
    if (hSessionHandle == NULL || hKeyHandle == NULL || pucData == NULL ||
        uiDataLength == 0 || pucMac == NULL || puiMacLength == NULL) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    sdfx_remote_handle_t key_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret == SDR_OK) {
        ret = sdf_get_server_key_id(hKeyHandle, &key_id);
    }
    if (ret != SDR_OK) {
        return ret;
    }

    uint32_t iv_len = pucIV == NULL ? 0 : 16;
    if (uiDataLength > SDFX_MAX_BLOB_LENGTH - iv_len) {
        return SDR_INARGERR;
    }
    BYTE *payload = malloc(iv_len + uiDataLength);
    if (payload == NULL) {
        return SDR_NOBUFFER;
    }
    if (iv_len > 0) {
        memcpy(payload, pucIV, iv_len);
    }
    memcpy(payload + iv_len, pucData, uiDataLength);

    uint32_t param[4] = {uiAlgID, iv_len, uiDataLength, 0};
    BYTE response_buffer[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t) + 16];
    size_t response_len = 0;
    ret = send_blob_request(SDFX_CMD_CALCULATE_MAC, session_id, key_id, param,
                            payload, iv_len + uiDataLength, response_buffer,
                            sizeof(response_buffer), &response_len);
    free(payload);
    if (ret != SDR_OK) {
        return ret;
    }

    sdfx_message_t *message = (sdfx_message_t *)response_buffer;
    sdfx_blob_resp_t *response = (sdfx_blob_resp_t *)message->data;
    uint32_t mac_len = sdfx_ntohl(response->data_length);
    if (mac_len > 16 || message->header.length < sizeof(*response) + mac_len) {
        return SDR_PROTOCOL_ERROR;
    }
    if (*puiMacLength < mac_len) {
        *puiMacLength = mac_len;
        return SDR_NOBUFFER;
    }
    memcpy(pucMac, response->data, mac_len);
    *puiMacLength = mac_len;
    return SDR_OK;
}

LONG SDF_CreateFile(HANDLE hSessionHandle, LPSTR pucFileName,
                    ULONG uiNameLen, ULONG uiFileSize)
{
    if (hSessionHandle == NULL || pucFileName == NULL || uiNameLen == 0 ||
        uiNameLen > SDFX_MAX_FILE_NAME || uiFileSize > SDFX_MAX_FILE_SIZE) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    uint32_t param[4] = {uiNameLen, uiFileSize, 0, 0};
    BYTE response_buffer[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t)];
    size_t response_len = 0;
    return send_blob_request(SDFX_CMD_CREATE_FILE, session_id, 0, param,
                             (const BYTE *)pucFileName, uiNameLen,
                             response_buffer, sizeof(response_buffer), &response_len);
}

LONG SDF_ReadFile(HANDLE hSessionHandle, LPSTR pucFileName, ULONG uiNameLen,
                  ULONG uiOffset, ULONG *puiFileLength, BYTE *pucBuffer)
{
    if (hSessionHandle == NULL || pucFileName == NULL || uiNameLen == 0 ||
        uiNameLen > SDFX_MAX_FILE_NAME || puiFileLength == NULL ||
        pucBuffer == NULL || *puiFileLength > SDFX_MAX_BLOB_LENGTH) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    uint32_t param[4] = {uiNameLen, uiOffset, *puiFileLength, 0};
    size_t response_capacity = sizeof(sdfx_message_header_t) +
                               sizeof(sdfx_blob_resp_t) + *puiFileLength;
    BYTE *response_buffer = malloc(response_capacity);
    if (response_buffer == NULL) {
        return SDR_NOBUFFER;
    }
    size_t response_len = 0;
    ret = send_blob_request(SDFX_CMD_READ_FILE, session_id, 0, param,
                            (const BYTE *)pucFileName, uiNameLen,
                            response_buffer, response_capacity, &response_len);
    if (ret == SDR_OK) {
        sdfx_message_t *message = (sdfx_message_t *)response_buffer;
        sdfx_blob_resp_t *response = (sdfx_blob_resp_t *)message->data;
        uint32_t length = sdfx_ntohl(response->data_length);
        if (length > *puiFileLength ||
            message->header.length < sizeof(*response) + length) {
            ret = SDR_PROTOCOL_ERROR;
        } else {
            memcpy(pucBuffer, response->data, length);
            *puiFileLength = length;
        }
    }
    free(response_buffer);
    return ret;
}

LONG SDF_WriteFile(HANDLE hSessionHandle, LPSTR pucFileName, ULONG uiNameLen,
                   ULONG uiOffset, ULONG uiFileLength, BYTE *pucBuffer)
{
    if (hSessionHandle == NULL || pucFileName == NULL || uiNameLen == 0 ||
        uiNameLen > SDFX_MAX_FILE_NAME || pucBuffer == NULL ||
        uiFileLength == 0 ||
        uiFileLength > SDFX_MAX_BLOB_LENGTH - uiNameLen) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    BYTE *payload = malloc(uiNameLen + uiFileLength);
    if (payload == NULL) {
        return SDR_NOBUFFER;
    }
    memcpy(payload, pucFileName, uiNameLen);
    memcpy(payload + uiNameLen, pucBuffer, uiFileLength);
    uint32_t param[4] = {uiNameLen, uiOffset, uiFileLength, 0};
    BYTE response_buffer[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t)];
    size_t response_len = 0;
    ret = send_blob_request(SDFX_CMD_WRITE_FILE, session_id, 0, param,
                            payload, uiNameLen + uiFileLength,
                            response_buffer, sizeof(response_buffer), &response_len);
    free(payload);
    return ret;
}

LONG SDF_DeleteFile(HANDLE hSessionHandle, LPSTR pucFileName, ULONG uiNameLen)
{
    if (hSessionHandle == NULL || pucFileName == NULL || uiNameLen == 0 ||
        uiNameLen > SDFX_MAX_FILE_NAME) {
        return SDR_INARGERR;
    }
    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(hSessionHandle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    uint32_t param[4] = {uiNameLen, 0, 0, 0};
    BYTE response_buffer[sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t)];
    size_t response_len = 0;
    return send_blob_request(SDFX_CMD_DELETE_FILE, session_id, 0, param,
                             (const BYTE *)pucFileName, uiNameLen,
                             response_buffer, sizeof(response_buffer), &response_len);
}

