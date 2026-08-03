/*
 * GM/T 0018-2023 extended symmetric and keyed-hash client operations.
 */
#include "sdf_internal.h"

LONG sdf_extended_call_id(HANDLE session_handle,
                          sdfx_remote_handle_t object_id,
                          uint32_t operation, ULONG alg_id,
                          const uint32_t param[8],
                          const BYTE *data, uint32_t data_len,
                          BYTE **response_message)
{
    if (session_handle == NULL || response_message == NULL ||
        data_len > SDFX_MAX_BLOB_LENGTH || (data_len > 0 && data == NULL)) {
        return SDR_INARGERR;
    }

    sdfx_remote_handle_t session_id;
    LONG ret = sdf_validate_session_and_get_id(session_handle, &session_id);
    if (ret != SDR_OK) {
        return ret;
    }

    size_t request_size = sizeof(sdfx_extended_req_t) + data_len;
    sdfx_extended_req_t *request = calloc(1, request_size);
    BYTE *response = malloc(sizeof(sdfx_message_header_t) +
                            sizeof(sdfx_extended_resp_t) +
                            SDFX_MAX_BLOB_LENGTH);
    if (request == NULL || response == NULL) {
        free(request);
        free(response);
        return SDR_NOBUFFER;
    }

    request->session_handle = sdfx_htonll(session_id);
    request->object_handle = sdfx_htonll(object_id);
    request->operation = sdfx_htonl(operation);
    request->alg_id = sdfx_htonl(alg_id);
    for (size_t i = 0; i < 8; ++i) {
        request->param[i] = sdfx_htonl(param == NULL ? 0 : param[i]);
    }
    request->data_length = sdfx_htonl(data_len);
    if (data_len > 0) {
        memcpy(request->data, data, data_len);
    }

    size_t response_len = 0;
    ret = sdf_send_request(SDFX_CMD_EXTENDED_OPERATION, request, request_size,
        response, sizeof(sdfx_message_header_t) + sizeof(sdfx_extended_resp_t) +
        SDFX_MAX_BLOB_LENGTH, &response_len);
    free(request);
    if (ret != SDR_OK) {
        free(response);
        return ret;
    }

    sdfx_message_t *message = (sdfx_message_t *)response;
    if (message->header.length < sizeof(sdfx_extended_resp_t)) {
        free(response);
        return SDR_PROTOCOL_ERROR;
    }
    sdfx_extended_resp_t *extended = (sdfx_extended_resp_t *)message->data;
    uint32_t output_len = sdfx_ntohl(extended->data_length);
    if (output_len > SDFX_MAX_BLOB_LENGTH ||
        message->header.length != sizeof(*extended) + output_len) {
        free(response);
        return SDR_PROTOCOL_ERROR;
    }

    *response_message = response;
    return SDR_OK;
}

static LONG extended_call(HANDLE session_handle, HANDLE key_handle,
                          uint32_t operation, ULONG alg_id,
                          const uint32_t param[8],
                          const BYTE *data, uint32_t data_len,
                          BYTE **response_message)
{
    sdfx_remote_handle_t object_id = 0;
    if (key_handle != NULL) {
        LONG ret = sdf_get_server_key_id(key_handle, &object_id);
        if (ret != SDR_OK) {
            return ret;
        }
    }
    return sdf_extended_call_id(session_handle, object_id, operation, alg_id,
                                param, data, data_len, response_message);
}

static LONG copy_extended_output(BYTE *message_buffer, BYTE *output,
                                 ULONG *output_len)
{
    if (message_buffer == NULL || output_len == NULL) {
        free(message_buffer);
        return SDR_INARGERR;
    }
    sdfx_message_t *message = (sdfx_message_t *)message_buffer;
    sdfx_extended_resp_t *response =
        (sdfx_extended_resp_t *)message->data;
    uint32_t length = sdfx_ntohl(response->data_length);
    if (*output_len < length || (length > 0 && output == NULL)) {
        *output_len = length;
        free(message_buffer);
        return SDR_NOBUFFER;
    }
    if (length > 0) {
        memcpy(output, response->data, length);
    }
    *output_len = length;
    free(message_buffer);
    return SDR_OK;
}

static LONG stream_init(HANDLE session, HANDLE key, ULONG alg_id,
                        BYTE *iv, ULONG iv_len, int decrypt)
{
    uint32_t param[8] = {(uint32_t)decrypt, iv_len, 0};
    BYTE *response = NULL;
    LONG ret = extended_call(session, key, SDFX_EXT_SYM_INIT, alg_id, param,
                             iv, iv_len, &response);
    free(response);
    return ret;
}

static LONG stream_update(HANDLE session, uint32_t operation,
                          BYTE *input, ULONG input_len,
                          BYTE *output, ULONG *output_len)
{
    if (input == NULL || input_len == 0 || output == NULL ||
        output_len == NULL) {
        return SDR_INARGERR;
    }
    BYTE *response = NULL;
    LONG ret = extended_call(session, NULL, operation, 0, NULL,
                             input, input_len, &response);
    if (ret != SDR_OK) {
        return ret;
    }
    return copy_extended_output(response, output, output_len);
}

static LONG stream_final(HANDLE session, BYTE *output, ULONG *output_len)
{
    if (output_len == NULL || (output == NULL && *output_len != 0)) {
        return SDR_INARGERR;
    }
    BYTE *response = NULL;
    LONG ret = extended_call(session, NULL, SDFX_EXT_SYM_FINAL, 0, NULL,
                             NULL, 0, &response);
    if (ret != SDR_OK) {
        return ret;
    }
    return copy_extended_output(response, output, output_len);
}

LONG SDF_EncryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucIV, ULONG uiIVLength)
{
    return stream_init(hSessionHandle, hKeyHandle, uiAlgID,
                       pucIV, uiIVLength, 0);
}

LONG SDF_EncryptUpdate(HANDLE hSessionHandle, BYTE *pucData,
                       ULONG uiDataLength, BYTE *pucEncData,
                       ULONG *puiEncDataLength)
{
    return stream_update(hSessionHandle, SDFX_EXT_SYM_UPDATE, pucData,
                         uiDataLength, pucEncData, puiEncDataLength);
}

LONG SDF_EncryptFinal(HANDLE hSessionHandle, BYTE *pucLastEncData,
                      ULONG *puiLastEncDataLength)
{
    return stream_final(hSessionHandle, pucLastEncData,
                        puiLastEncDataLength);
}

LONG SDF_DecryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucIV, ULONG uiIVLength)
{
    return stream_init(hSessionHandle, hKeyHandle, uiAlgID,
                       pucIV, uiIVLength, 1);
}

LONG SDF_DecryptUpdate(HANDLE hSessionHandle, BYTE *pucEncData,
                       ULONG uiEncDataLength, BYTE *pucData,
                       ULONG *puiDataLength)
{
    return stream_update(hSessionHandle, SDFX_EXT_SYM_UPDATE, pucEncData,
                         uiEncDataLength, pucData, puiDataLength);
}

LONG SDF_DecryptFinal(HANDLE hSessionHandle, BYTE *pucLastData,
                      ULONG *puiLastDataLength)
{
    return stream_final(hSessionHandle, pucLastData, puiLastDataLength);
}

LONG SDF_CalculateMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle,
                          ULONG uiAlgID, BYTE *pucIV, ULONG uiIVLength)
{
    uint32_t param[8] = {uiIVLength, 0};
    BYTE *response = NULL;
    LONG ret = extended_call(hSessionHandle, hKeyHandle, SDFX_EXT_MAC_INIT,
                             uiAlgID, param, pucIV, uiIVLength, &response);
    free(response);
    return ret;
}

LONG SDF_CalculateMACUpdate(HANDLE hSessionHandle, BYTE *pucData,
                            ULONG uiDataLength)
{
    if (pucData == NULL || uiDataLength == 0) {
        return SDR_INARGERR;
    }
    BYTE *response = NULL;
    LONG ret = extended_call(hSessionHandle, NULL, SDFX_EXT_MAC_UPDATE, 0,
                             NULL, pucData, uiDataLength, &response);
    free(response);
    return ret;
}

LONG SDF_CalculateMACFinal(HANDLE hSessionHandle, BYTE *pucMac,
                           ULONG *puiMacLength)
{
    if (pucMac == NULL || puiMacLength == NULL) {
        return SDR_INARGERR;
    }
    BYTE *response = NULL;
    LONG ret = extended_call(hSessionHandle, NULL, SDFX_EXT_MAC_FINAL, 0,
                             NULL, NULL, 0, &response);
    if (ret != SDR_OK) {
        return ret;
    }
    return copy_extended_output(response, pucMac, puiMacLength);
}

LONG SDF_HMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID)
{
    BYTE *response = NULL;
    LONG ret = extended_call(hSessionHandle, hKeyHandle, SDFX_EXT_HMAC_INIT,
                             uiAlgID, NULL, NULL, 0, &response);
    free(response);
    return ret;
}

LONG SDF_HMACUpdate(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength)
{
    if (pucData == NULL || uiDataLength == 0) {
        return SDR_INARGERR;
    }
    BYTE *response = NULL;
    LONG ret = extended_call(hSessionHandle, NULL, SDFX_EXT_HMAC_UPDATE, 0,
                             NULL, pucData, uiDataLength, &response);
    free(response);
    return ret;
}

LONG SDF_HMACFinal(HANDLE hSessionHandle, BYTE *pucHMac,
                   ULONG *puiHMacLength)
{
    if (pucHMac == NULL || puiHMacLength == NULL) {
        return SDR_INARGERR;
    }
    BYTE *response = NULL;
    LONG ret = extended_call(hSessionHandle, NULL, SDFX_EXT_HMAC_FINAL, 0,
                             NULL, NULL, 0, &response);
    if (ret != SDR_OK) {
        return ret;
    }
    return copy_extended_output(response, pucHMac, puiHMacLength);
}

static LONG auth_init(HANDLE session, HANDLE key, ULONG alg_id,
                      BYTE *iv, ULONG iv_len, BYTE *aad, ULONG aad_len,
                      BYTE *tag, ULONG tag_len, ULONG data_len, int decrypt)
{
    if (iv == NULL || iv_len == 0 || (aad_len > 0 && aad == NULL) ||
        tag_len == 0 || tag_len > 16 || (decrypt && tag == NULL) ||
        iv_len + aad_len + (decrypt ? tag_len : 0) > SDFX_MAX_BLOB_LENGTH) {
        return SDR_INARGERR;
    }

    uint32_t payload_len = iv_len + aad_len + (decrypt ? tag_len : 0);
    BYTE *payload = malloc(payload_len);
    if (payload == NULL) {
        return SDR_NOBUFFER;
    }
    memcpy(payload, iv, iv_len);
    if (aad_len > 0) {
        memcpy(payload + iv_len, aad, aad_len);
    }
    if (decrypt) {
        memcpy(payload + iv_len + aad_len, tag, tag_len);
    }

    uint32_t param[8] = {(uint32_t)decrypt, iv_len, aad_len, tag_len,
                         data_len, 0};
    BYTE *response = NULL;
    LONG ret = extended_call(session, key, SDFX_EXT_AUTH_INIT, alg_id,
                             param, payload, payload_len, &response);
    memset(payload, 0, payload_len);
    free(payload);
    free(response);
    return ret;
}

static LONG auth_oneshot(HANDLE session, HANDLE key, ULONG alg_id,
                         BYTE *iv, ULONG iv_len, BYTE *aad, ULONG aad_len,
                         BYTE *input_tag, ULONG input_tag_len,
                         BYTE *input, ULONG input_len, BYTE *output,
                         ULONG *output_len, BYTE *output_tag,
                         ULONG *output_tag_len, int decrypt)
{
    ULONG tag_len = decrypt ? input_tag_len :
                    (output_tag_len == NULL ? 0 : *output_tag_len);
    if (input == NULL || input_len == 0 || output == NULL ||
        output_len == NULL || iv == NULL || iv_len == 0 ||
        (aad_len > 0 && aad == NULL) || tag_len == 0 || tag_len > 16 ||
        (decrypt && input_tag == NULL) ||
        (!decrypt && (output_tag == NULL || output_tag_len == NULL))) {
        return SDR_INARGERR;
    }

    uint32_t overhead = iv_len + aad_len + (decrypt ? tag_len : 0);
    if (overhead > SDFX_MAX_BLOB_LENGTH ||
        input_len > SDFX_MAX_BLOB_LENGTH - overhead) {
        return SDR_INARGERR;
    }
    uint32_t payload_len = overhead + input_len;
    BYTE *payload = malloc(payload_len);
    if (payload == NULL) {
        return SDR_NOBUFFER;
    }
    BYTE *cursor = payload;
    memcpy(cursor, iv, iv_len);
    cursor += iv_len;
    if (aad_len > 0) {
        memcpy(cursor, aad, aad_len);
        cursor += aad_len;
    }
    if (decrypt) {
        memcpy(cursor, input_tag, tag_len);
        cursor += tag_len;
    }
    memcpy(cursor, input, input_len);

    uint32_t param[8] = {(uint32_t)decrypt, iv_len, aad_len, tag_len,
                         input_len, 0};
    BYTE *message_buffer = NULL;
    LONG ret = extended_call(session, key, SDFX_EXT_AUTH_ONESHOT, alg_id,
                             param, payload, payload_len, &message_buffer);
    memset(payload, 0, payload_len);
    free(payload);
    if (ret != SDR_OK) {
        return ret;
    }

    sdfx_message_t *message = (sdfx_message_t *)message_buffer;
    sdfx_extended_resp_t *response =
        (sdfx_extended_resp_t *)message->data;
    uint32_t text_len = sdfx_ntohl(response->param[0]);
    uint32_t returned_tag_len = sdfx_ntohl(response->param[1]);
    uint32_t total_len = sdfx_ntohl(response->data_length);
    if (text_len + returned_tag_len != total_len ||
        (decrypt && returned_tag_len != 0)) {
        free(message_buffer);
        return SDR_PROTOCOL_ERROR;
    }
    if (*output_len < text_len ||
        (!decrypt && *output_tag_len < returned_tag_len)) {
        *output_len = text_len;
        if (!decrypt) {
            *output_tag_len = returned_tag_len;
        }
        free(message_buffer);
        return SDR_NOBUFFER;
    }
    memcpy(output, response->data, text_len);
    *output_len = text_len;
    if (!decrypt) {
        memcpy(output_tag, response->data + text_len, returned_tag_len);
        *output_tag_len = returned_tag_len;
    }
    free(message_buffer);
    return SDR_OK;
}

LONG SDF_AuthEnc(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucStartVar, ULONG uiStartVarLength,
                 BYTE *pucAad, ULONG uiAadLength,
                 BYTE *pucData, ULONG uiDataLength,
                 BYTE *pucEncData, ULONG *puiEncDataLength,
                 BYTE *pucAuthData, ULONG *puiAuthDataLength)
{
    return auth_oneshot(hSessionHandle, hKeyHandle, uiAlgID,
        pucStartVar, uiStartVarLength, pucAad, uiAadLength,
        NULL, 0, pucData, uiDataLength, pucEncData, puiEncDataLength,
        pucAuthData, puiAuthDataLength, 0);
}

LONG SDF_AuthDec(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucStartVar, ULONG uiStartVarLength,
                 BYTE *pucAad, ULONG uiAadLength,
                 BYTE *pucAuthData, ULONG uiAuthDataLength,
                 BYTE *pucEncData, ULONG uiEncDataLength,
                 BYTE *pucData, ULONG *puiDataLength)
{
    return auth_oneshot(hSessionHandle, hKeyHandle, uiAlgID,
        pucStartVar, uiStartVarLength, pucAad, uiAadLength,
        pucAuthData, uiAuthDataLength, pucEncData, uiEncDataLength,
        pucData, puiDataLength, NULL, NULL, 1);
}

LONG SDF_AuthEncInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucStartVar, ULONG uiStartVarLength,
                     BYTE *pucAad, ULONG uiAadLength, ULONG uiDataLength)
{
    return auth_init(hSessionHandle, hKeyHandle, uiAlgID, pucStartVar,
                     uiStartVarLength, pucAad, uiAadLength, NULL, 16,
                     uiDataLength, 0);
}

LONG SDF_AuthEncUpdate(HANDLE hSessionHandle, BYTE *pucData,
                       ULONG uiDataLength, BYTE *pucEncData,
                       ULONG *puiEncDataLength)
{
    return stream_update(hSessionHandle, SDFX_EXT_AUTH_UPDATE, pucData,
                         uiDataLength, pucEncData, puiEncDataLength);
}

LONG SDF_AuthEncFinal(HANDLE hSessionHandle, BYTE *pucLastEncData,
                      ULONG *puiLastEncDataLength, BYTE *pucAuthData,
                      ULONG *puiAuthDataLength)
{
    if (puiLastEncDataLength == NULL || pucAuthData == NULL ||
        puiAuthDataLength == NULL) {
        return SDR_INARGERR;
    }
    uint32_t param[8] = {16, 0};
    BYTE *message_buffer = NULL;
    LONG ret = extended_call(hSessionHandle, NULL, SDFX_EXT_AUTH_FINAL, 0,
                             param, NULL, 0, &message_buffer);
    if (ret != SDR_OK) {
        return ret;
    }
    sdfx_message_t *message = (sdfx_message_t *)message_buffer;
    sdfx_extended_resp_t *response =
        (sdfx_extended_resp_t *)message->data;
    uint32_t last_len = sdfx_ntohl(response->param[0]);
    uint32_t tag_len = sdfx_ntohl(response->param[1]);
    if (last_len + tag_len != sdfx_ntohl(response->data_length)) {
        free(message_buffer);
        return SDR_PROTOCOL_ERROR;
    }
    if (*puiLastEncDataLength < last_len || *puiAuthDataLength < tag_len ||
        (last_len > 0 && pucLastEncData == NULL)) {
        *puiLastEncDataLength = last_len;
        *puiAuthDataLength = tag_len;
        free(message_buffer);
        return SDR_NOBUFFER;
    }
    if (last_len > 0) {
        memcpy(pucLastEncData, response->data, last_len);
    }
    memcpy(pucAuthData, response->data + last_len, tag_len);
    *puiLastEncDataLength = last_len;
    *puiAuthDataLength = tag_len;
    free(message_buffer);
    return SDR_OK;
}

LONG SDF_AuthDecInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucStartVar, ULONG uiStartVarLength,
                     BYTE *pucAad, ULONG uiAadLength,
                     BYTE *pucAuthData, ULONG uiAuthDataLength,
                     ULONG uiDataLength)
{
    return auth_init(hSessionHandle, hKeyHandle, uiAlgID, pucStartVar,
                     uiStartVarLength, pucAad, uiAadLength, pucAuthData,
                     uiAuthDataLength, uiDataLength, 1);
}

LONG SDF_AuthDecUpdate(HANDLE hSessionHandle, BYTE *pucEncData,
                       ULONG uiEncDataLength, BYTE *pucData,
                       ULONG *puiDataLength)
{
    return stream_update(hSessionHandle, SDFX_EXT_AUTH_UPDATE, pucEncData,
                         uiEncDataLength, pucData, puiDataLength);
}

LONG SDF_AuthDecFinal(HANDLE hSessionHandle, BYTE *pucLastData,
                      ULONG *puiLastDataLength)
{
    if (puiLastDataLength == NULL) {
        return SDR_INARGERR;
    }
    uint32_t param[8] = {0};
    BYTE *message_buffer = NULL;
    LONG ret = extended_call(hSessionHandle, NULL, SDFX_EXT_AUTH_FINAL, 0,
                             param, NULL, 0, &message_buffer);
    if (ret != SDR_OK) {
        return ret;
    }
    return copy_extended_output(message_buffer, pucLastData,
                                puiLastDataLength);
}

static LONG external_crypt(HANDLE session, ULONG alg_id, BYTE *key,
                           ULONG key_len, BYTE *iv, ULONG iv_len,
                           BYTE *input, ULONG input_len, BYTE *output,
                           ULONG *output_len, int decrypt)
{
    if (key == NULL || key_len == 0 || input == NULL || input_len == 0 ||
        output == NULL || output_len == NULL ||
        key_len + iv_len > SDFX_MAX_BLOB_LENGTH ||
        input_len > SDFX_MAX_BLOB_LENGTH - key_len - iv_len ||
        (iv_len > 0 && iv == NULL)) {
        return SDR_INARGERR;
    }
    uint32_t payload_len = key_len + iv_len + input_len;
    BYTE *payload = malloc(payload_len);
    if (payload == NULL) {
        return SDR_NOBUFFER;
    }
    memcpy(payload, key, key_len);
    if (iv_len > 0) {
        memcpy(payload + key_len, iv, iv_len);
    }
    memcpy(payload + key_len + iv_len, input, input_len);
    uint32_t param[8] = {(uint32_t)decrypt, key_len, iv_len, 0};
    BYTE *response = NULL;
    LONG ret = extended_call(session, NULL, SDFX_EXT_EXTERNAL_CRYPT,
                             alg_id, param, payload, payload_len, &response);
    memset(payload, 0, key_len);
    free(payload);
    if (ret != SDR_OK) {
        return ret;
    }
    return copy_extended_output(response, output, output_len);
}

LONG SDF_ExternalKeyEncrypt(HANDLE hSessionHandle, ULONG uiAlgID,
                            BYTE *pucKey, ULONG uiKeyLength,
                            BYTE *pucIV, ULONG uiIVLength,
                            BYTE *pucData, ULONG uiDataLength,
                            BYTE *pucEncData, ULONG *puiEncDataLength)
{
    return external_crypt(hSessionHandle, uiAlgID, pucKey, uiKeyLength,
        pucIV, uiIVLength, pucData, uiDataLength, pucEncData,
        puiEncDataLength, 0);
}

LONG SDF_ExternalKeyDecrypt(HANDLE hSessionHandle, ULONG uiAlgID,
                            BYTE *pucKey, ULONG uiKeyLength,
                            BYTE *pucIV, ULONG uiIVLength,
                            BYTE *pucEncData, ULONG uiEncDataLength,
                            BYTE *pucData, ULONG *puiDataLength)
{
    return external_crypt(hSessionHandle, uiAlgID, pucKey, uiKeyLength,
        pucIV, uiIVLength, pucEncData, uiEncDataLength, pucData,
        puiDataLength, 1);
}

static LONG external_stream_init(HANDLE session, ULONG alg_id, BYTE *key,
                                 ULONG key_len, BYTE *iv, ULONG iv_len,
                                 int decrypt)
{
    if (key == NULL || key_len == 0 || key_len + iv_len > SDFX_MAX_BLOB_LENGTH ||
        (iv_len > 0 && iv == NULL)) {
        return SDR_INARGERR;
    }
    uint32_t payload_len = key_len + iv_len;
    BYTE *payload = malloc(payload_len);
    if (payload == NULL) {
        return SDR_NOBUFFER;
    }
    memcpy(payload, key, key_len);
    if (iv_len > 0) {
        memcpy(payload + key_len, iv, iv_len);
    }
    uint32_t param[8] = {(uint32_t)decrypt, key_len, iv_len, 0};
    BYTE *response = NULL;
    LONG ret = extended_call(session, NULL, SDFX_EXT_EXTERNAL_SYM_INIT,
                             alg_id, param, payload, payload_len, &response);
    memset(payload, 0, key_len);
    free(payload);
    free(response);
    return ret;
}

LONG SDF_ExternalKeyEncryptInit(HANDLE hSessionHandle, ULONG uiAlgID,
                                BYTE *pucKey, ULONG uiKeyLength,
                                BYTE *pucIV, ULONG uiIVLength)
{
    return external_stream_init(hSessionHandle, uiAlgID, pucKey, uiKeyLength,
                                pucIV, uiIVLength, 0);
}

LONG SDF_ExternalKeyDecryptInit(HANDLE hSessionHandle, ULONG uiAlgID,
                                BYTE *pucKey, ULONG uiKeyLength,
                                BYTE *pucIV, ULONG uiIVLength)
{
    return external_stream_init(hSessionHandle, uiAlgID, pucKey, uiKeyLength,
                                pucIV, uiIVLength, 1);
}

LONG SDF_ExternalKeyHMACInit(HANDLE hSessionHandle, ULONG uiAlgID,
                             BYTE *pucKey, ULONG uiKeyLength)
{
    if (pucKey == NULL || uiKeyLength == 0 ||
        uiKeyLength > SDFX_MAX_BLOB_LENGTH) {
        return SDR_INARGERR;
    }
    uint32_t param[8] = {uiKeyLength, 0};
    BYTE *response = NULL;
    LONG ret = extended_call(hSessionHandle, NULL,
        SDFX_EXT_EXTERNAL_HMAC_INIT, uiAlgID, param, pucKey, uiKeyLength,
        &response);
    free(response);
    return ret;
}
