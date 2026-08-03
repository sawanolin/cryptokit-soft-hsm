/*
 * GM/T 0018-2023 SM2 key-agreement client operations.
 */
#include "sdf_internal.h"

static LONG create_remote_handle(sdfx_remote_handle_t remote_id,
                                 int agreement, HANDLE *handle)
{
    if (remote_id == 0 || handle == NULL) return SDR_PROTOCOL_ERROR;
    sdfx_remote_handle_t *stored = malloc(sizeof(*stored));
    if (stored == NULL) return SDR_NOBUFFER;
    *stored = remote_id;
    *handle = agreement ? handle_manager_create_agreement_with_data(stored) :
                          handle_manager_create_key_with_data(stored);
    if (*handle == NULL) {
        free(stored);
        return SDR_NOBUFFER;
    }
    return SDR_OK;
}

static LONG validate_response(BYTE *buffer, uint32_t expected,
                              sdfx_extended_resp_t **response)
{
    if (buffer == NULL || response == NULL) {
        free(buffer);
        return SDR_PROTOCOL_ERROR;
    }
    sdfx_message_t *message = (sdfx_message_t *)buffer;
    sdfx_extended_resp_t *extended = (sdfx_extended_resp_t *)message->data;
    if (sdfx_ntohl(extended->data_length) != expected) {
        free(buffer);
        return SDR_PROTOCOL_ERROR;
    }
    *response = extended;
    return SDR_OK;
}

LONG SDF_GenerateAgreementDataWithECC(
    HANDLE hSessionHandle, ULONG uiISKIndex, ULONG uiKeyBits,
    BYTE *pucSponsorID, ULONG uiSponsorIDLength,
    ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey,
    HANDLE *phAgreementHandle)
{
    if (hSessionHandle == NULL || uiISKIndex == 0 || pucSponsorID == NULL ||
        uiSponsorIDLength == 0 ||
        uiSponsorIDLength > SDFX_MAX_SM2_ID_LENGTH ||
        pucSponsorPublicKey == NULL || pucSponsorTmpPublicKey == NULL ||
        phAgreementHandle == NULL) return SDR_INARGERR;
    *phAgreementHandle = NULL;
    uint32_t param[8] = {uiISKIndex, uiKeyBits, uiSponsorIDLength, 0};
    BYTE *buffer = NULL;
    LONG ret = sdf_extended_call_id(hSessionHandle, 0,
        SDFX_EXT_AGREEMENT_SPONSOR, SGD_SM2_2, param, pucSponsorID,
        uiSponsorIDLength, &buffer);
    if (ret != SDR_OK) return ret;

    sdfx_extended_resp_t *response = NULL;
    ret = validate_response(buffer, 2 * sizeof(ECCrefPublicKey), &response);
    if (ret != SDR_OK) return ret;
    memcpy(pucSponsorPublicKey, response->data, sizeof(ECCrefPublicKey));
    memcpy(pucSponsorTmpPublicKey, response->data + sizeof(ECCrefPublicKey),
           sizeof(ECCrefPublicKey));
    ret = create_remote_handle(sdfx_ntohll(response->object_handle), 1,
                               phAgreementHandle);
    free(buffer);
    return ret;
}

LONG SDF_GenerateKeyWithECC(
    HANDLE hSessionHandle, BYTE *pucResponseID, ULONG uiResponseIDLength,
    ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey,
    HANDLE hAgreementHandle, HANDLE *phKeyHandle)
{
    if (hSessionHandle == NULL || pucResponseID == NULL ||
        uiResponseIDLength == 0 ||
        uiResponseIDLength > SDFX_MAX_SM2_ID_LENGTH ||
        pucResponsePublicKey == NULL || pucResponseTmpPublicKey == NULL ||
        hAgreementHandle == NULL || phKeyHandle == NULL) return SDR_INARGERR;
    *phKeyHandle = NULL;

    sdfx_remote_handle_t agreement_id;
    LONG ret = sdf_get_server_agreement_id(hAgreementHandle, &agreement_id);
    if (ret != SDR_OK) return ret;
    uint32_t payload_len = uiResponseIDLength + 2 * sizeof(ECCrefPublicKey);
    BYTE *payload = malloc(payload_len);
    if (payload == NULL) return SDR_NOBUFFER;
    memcpy(payload, pucResponseID, uiResponseIDLength);
    memcpy(payload + uiResponseIDLength, pucResponsePublicKey,
           sizeof(ECCrefPublicKey));
    memcpy(payload + uiResponseIDLength + sizeof(ECCrefPublicKey),
           pucResponseTmpPublicKey, sizeof(ECCrefPublicKey));

    uint32_t param[8] = {uiResponseIDLength, 0};
    BYTE *buffer = NULL;
    ret = sdf_extended_call_id(hSessionHandle, agreement_id,
        SDFX_EXT_AGREEMENT_KEY, SGD_SM2_2, param, payload, payload_len,
        &buffer);
    free(payload);
    if (ret != SDR_OK) return ret;

    sdfx_extended_resp_t *response = NULL;
    ret = validate_response(buffer, 0, &response);
    if (ret == SDR_OK) {
        ret = create_remote_handle(sdfx_ntohll(response->object_handle), 0,
                                   phKeyHandle);
    }
    free(buffer);
    if (ret == SDR_OK) handle_manager_destroy(hAgreementHandle);
    return ret;
}

LONG SDF_GenerateAgreementDataAndKeyWithECC(
    HANDLE hSessionHandle, ULONG uiISKIndex, ULONG uiKeyBits,
    BYTE *pucResponseID, ULONG uiResponseIDLength,
    BYTE *pucSponsorID, ULONG uiSponsorIDLength,
    ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey,
    ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey,
    HANDLE *phKeyHandle)
{
    if (hSessionHandle == NULL || uiISKIndex == 0 ||
        pucResponseID == NULL || uiResponseIDLength == 0 ||
        uiResponseIDLength > SDFX_MAX_SM2_ID_LENGTH ||
        pucSponsorID == NULL || uiSponsorIDLength == 0 ||
        uiSponsorIDLength > SDFX_MAX_SM2_ID_LENGTH ||
        pucSponsorPublicKey == NULL || pucSponsorTmpPublicKey == NULL ||
        pucResponsePublicKey == NULL || pucResponseTmpPublicKey == NULL ||
        phKeyHandle == NULL) return SDR_INARGERR;
    *phKeyHandle = NULL;

    uint32_t payload_len = uiResponseIDLength + uiSponsorIDLength +
                           2 * sizeof(ECCrefPublicKey);
    if (payload_len > SDFX_MAX_BLOB_LENGTH) return SDR_INARGERR;
    BYTE *payload = malloc(payload_len);
    if (payload == NULL) return SDR_NOBUFFER;
    BYTE *cursor = payload;
    memcpy(cursor, pucResponseID, uiResponseIDLength);
    cursor += uiResponseIDLength;
    memcpy(cursor, pucSponsorID, uiSponsorIDLength);
    cursor += uiSponsorIDLength;
    memcpy(cursor, pucSponsorPublicKey, sizeof(ECCrefPublicKey));
    cursor += sizeof(ECCrefPublicKey);
    memcpy(cursor, pucSponsorTmpPublicKey, sizeof(ECCrefPublicKey));

    uint32_t param[8] = {uiISKIndex, uiKeyBits, uiResponseIDLength,
                         uiSponsorIDLength, 0};
    BYTE *buffer = NULL;
    LONG ret = sdf_extended_call_id(hSessionHandle, 0,
        SDFX_EXT_AGREEMENT_RESPONSE, SGD_SM2_2, param, payload, payload_len,
        &buffer);
    free(payload);
    if (ret != SDR_OK) return ret;

    sdfx_extended_resp_t *response = NULL;
    ret = validate_response(buffer, 2 * sizeof(ECCrefPublicKey), &response);
    if (ret == SDR_OK) {
        memcpy(pucResponsePublicKey, response->data, sizeof(ECCrefPublicKey));
        memcpy(pucResponseTmpPublicKey,
               response->data + sizeof(ECCrefPublicKey),
               sizeof(ECCrefPublicKey));
        ret = create_remote_handle(sdfx_ntohll(response->object_handle), 0,
                                   phKeyHandle);
    }
    free(buffer);
    return ret;
}
