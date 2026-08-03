/*
 * GM/T 0018-2023 Appendix C VPN client operations.
 */
#include "sdf_internal.h"

static LONG create_key_from_id(sdfx_remote_handle_t id, HANDLE *handle)
{
    if (id == 0 || handle == NULL) return SDR_PROTOCOL_ERROR;
    sdfx_remote_handle_t *stored = malloc(sizeof(*stored));
    if (stored == NULL) return SDR_NOBUFFER;
    *stored = id;
    *handle = handle_manager_create_key_with_data(stored);
    if (*handle == NULL) {
        free(stored);
        return SDR_NOBUFFER;
    }
    return SDR_OK;
}

static LONG vpn_response(BYTE *buffer, sdfx_extended_resp_t **response,
                         uint32_t *data_len)
{
    if (buffer == NULL || response == NULL || data_len == NULL)
        return SDR_PROTOCOL_ERROR;
    sdfx_message_t *message = (sdfx_message_t *)buffer;
    *response = (sdfx_extended_resp_t *)message->data;
    *data_len = sdfx_ntohl((*response)->data_length);
    return SDR_OK;
}

static BYTE *concat_inputs(const ECCrefPublicKey *public_key,
                           const BYTE *const input[4],
                           const uint32_t length[4],
                           uint32_t *output_len)
{
    uint64_t total = public_key == NULL ? 0 : sizeof(*public_key);
    for (size_t i = 0; i < 4; ++i) {
        if (length[i] > 0 && input[i] == NULL) return NULL;
        total += length[i];
    }
    if (total == 0 || total > SDFX_MAX_BLOB_LENGTH) return NULL;
    BYTE *output = malloc((size_t)total);
    if (output == NULL) return NULL;
    BYTE *cursor = output;
    if (public_key != NULL) {
        memcpy(cursor, public_key, sizeof(*public_key));
        cursor += sizeof(*public_key);
    }
    for (size_t i = 0; i < 4; ++i) {
        if (length[i] > 0) {
            memcpy(cursor, input[i], length[i]);
            cursor += length[i];
        }
    }
    *output_len = (uint32_t)total;
    return output;
}

static LONG copy_cipher_blob(ECCCipher *output, const BYTE *input,
                             uint32_t blob_len)
{
    if (output == NULL || input == NULL || blob_len < sizeof(ECCCipher))
        return SDR_PROTOCOL_ERROR;
    uint32_t cipher_len = sdfx_ntohl(((const ECCCipher *)input)->L);
    if (cipher_len == 0 ||
        blob_len != sizeof(ECCCipher) + cipher_len - 1)
        return SDR_PROTOCOL_ERROR;
    memcpy(output, input, blob_len);
    output->L = cipher_len;
    return SDR_OK;
}

static LONG create_key_set(HANDLE session, const BYTE *data, uint32_t count,
                           HANDLE **handles)
{
    HANDLE created[4] = {0};
    for (uint32_t i = 0; i < count; ++i) {
        sdfx_remote_handle_t wire;
        memcpy(&wire, data + i * sizeof(wire), sizeof(wire));
        LONG ret = create_key_from_id(sdfx_ntohll(wire), &created[i]);
        if (ret != SDR_OK) {
            for (uint32_t j = 0; j < i; ++j)
                SDF_DestroyKey(session, created[j]);
            return ret;
        }
    }
    for (uint32_t i = 0; i < count; ++i) *handles[i] = created[i];
    return SDR_OK;
}

LONG SDF_GenerateKeywithIKE(
    HANDLE hSessionHandle, BYTE *pucSponsorNonce, ULONG uiSponsorNonceLength,
    BYTE *pucResponseNonce, ULONG uiResponseNonceLength,
    BYTE *pucSponsorCookie, ULONG uiSponsorCookieLength,
    BYTE *pucResponseCookie, ULONG uiResponseCookieLength, ULONG uiPrfAlgID,
    HANDLE *phKeyHandleD, ULONG uiKeyBitsD,
    HANDLE *phKeyHandleA, ULONG uiKeyBitsA,
    HANDLE *phKeyHandleE, ULONG uiKeyBitsE)
{
    if (hSessionHandle == NULL || phKeyHandleD == NULL ||
        phKeyHandleA == NULL || phKeyHandleE == NULL) return SDR_INARGERR;
    const BYTE *inputs[4] = {pucSponsorNonce, pucResponseNonce,
                             pucSponsorCookie, pucResponseCookie};
    uint32_t lengths[4] = {uiSponsorNonceLength, uiResponseNonceLength,
                           uiSponsorCookieLength, uiResponseCookieLength};
    uint32_t payload_len = 0;
    BYTE *payload = concat_inputs(NULL, inputs, lengths, &payload_len);
    if (payload == NULL) return SDR_INARGERR;
    uint32_t param[8] = {lengths[0], lengths[1], lengths[2], lengths[3],
                         uiKeyBitsD, uiKeyBitsA, uiKeyBitsE, 0};
    BYTE *buffer = NULL;
    LONG ret = sdf_extended_call_id(hSessionHandle, 0, SDFX_EXT_VPN_IKE,
        uiPrfAlgID, param, payload, payload_len, &buffer);
    free(payload);
    if (ret != SDR_OK) return ret;
    sdfx_extended_resp_t *response;
    uint32_t response_len;
    ret = vpn_response(buffer, &response, &response_len);
    if (ret == SDR_OK && response_len != 3 * sizeof(sdfx_remote_handle_t))
        ret = SDR_PROTOCOL_ERROR;
    if (ret == SDR_OK) {
        HANDLE *handles[3] = {phKeyHandleD, phKeyHandleA, phKeyHandleE};
        ret = create_key_set(hSessionHandle, response->data, 3, handles);
    }
    free(buffer);
    return ret;
}

LONG SDF_GenerateKeywithEPK_IKE(
    HANDLE hSessionHandle, BYTE *pucSponsorNonce, ULONG uiSponsorNonceLength,
    BYTE *pucResponseNonce, ULONG uiResponseNonceLength,
    BYTE *pucSponsorCookie, ULONG uiSponsorCookieLength,
    BYTE *pucResponseCookie, ULONG uiResponseCookieLength, ULONG uiPrfAlgID,
    ULONG uiEccAlgID, ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucKeyD, ULONG uiKeyBitsD,
    ECCCipher *pucKeyA, ULONG uiKeyBitsA,
    ECCCipher *pucKeyE, ULONG uiKeyBitsE)
{
    if (uiEccAlgID != SGD_SM2_3) return SDR_ALGNOTSUPPORT;
    if (hSessionHandle == NULL || pucPublicKey == NULL ||
        pucKeyD == NULL || pucKeyA == NULL ||
        pucKeyE == NULL) return SDR_INARGERR;
    const BYTE *inputs[4] = {pucSponsorNonce, pucResponseNonce,
                             pucSponsorCookie, pucResponseCookie};
    uint32_t lengths[4] = {uiSponsorNonceLength, uiResponseNonceLength,
                           uiSponsorCookieLength, uiResponseCookieLength};
    uint32_t payload_len = 0;
    BYTE *payload = concat_inputs(pucPublicKey, inputs, lengths, &payload_len);
    if (payload == NULL) return SDR_INARGERR;
    uint32_t param[8] = {lengths[0], lengths[1], lengths[2], lengths[3],
                         uiKeyBitsD, uiKeyBitsA, uiKeyBitsE, 0};
    BYTE *buffer = NULL;
    LONG ret = sdf_extended_call_id(hSessionHandle, 0, SDFX_EXT_VPN_IKE_EPK,
        uiPrfAlgID, param, payload, payload_len, &buffer);
    free(payload);
    if (ret != SDR_OK) return ret;
    sdfx_extended_resp_t *response;
    uint32_t response_len;
    ret = vpn_response(buffer, &response, &response_len);
    uint32_t offset = 0;
    ECCCipher *outputs[3] = {pucKeyD, pucKeyA, pucKeyE};
    for (uint32_t i = 0; ret == SDR_OK && i < 3; ++i) {
        uint32_t length = sdfx_ntohl(response->param[i]);
        if (length > response_len - offset) ret = SDR_PROTOCOL_ERROR;
        else ret = copy_cipher_blob(outputs[i], response->data + offset,
                                    length);
        offset += length;
    }
    if (ret == SDR_OK && offset != response_len) ret = SDR_PROTOCOL_ERROR;
    free(buffer);
    return ret;
}

LONG SDF_GenerateKeywithIPSEC(
    HANDLE hSessionHandle, BYTE *pucProtocolID, ULONG uiProtocolIDLength,
    BYTE *pucSpi, ULONG uiSpiLength,
    BYTE *pucSponsorNonce, ULONG uiSponsorNonceLength,
    BYTE *pucResponseNonce, ULONG uiResponseNonceLength,
    HANDLE hKeyHandle, ULONG uiPrfAlgID,
    HANDLE *phKeyHandleEnc, ULONG uiKeyBitsEnc,
    HANDLE *phKeyHandleMac, ULONG uiKeyBitsMac,
    BYTE *pucSalt, ULONG uiSaltLength)
{
    if (hSessionHandle == NULL || hKeyHandle == NULL ||
        phKeyHandleEnc == NULL || (uiKeyBitsMac > 0 && phKeyHandleMac == NULL) ||
        (uiSaltLength > 0 && pucSalt == NULL)) return SDR_INARGERR;
    const BYTE *inputs[4] = {pucProtocolID, pucSpi, pucSponsorNonce,
                             pucResponseNonce};
    uint32_t lengths[4] = {uiProtocolIDLength, uiSpiLength,
                           uiSponsorNonceLength, uiResponseNonceLength};
    uint32_t payload_len = 0;
    BYTE *payload = concat_inputs(NULL, inputs, lengths, &payload_len);
    if (payload == NULL) return SDR_INARGERR;
    sdfx_remote_handle_t key_id;
    LONG ret = sdf_get_server_key_id(hKeyHandle, &key_id);
    uint32_t param[8] = {lengths[0], lengths[1], lengths[2], lengths[3],
                         uiKeyBitsEnc, uiKeyBitsMac, uiSaltLength, 0};
    BYTE *buffer = NULL;
    if (ret == SDR_OK)
        ret = sdf_extended_call_id(hSessionHandle, key_id,
            SDFX_EXT_VPN_IPSEC, uiPrfAlgID, param, payload, payload_len,
            &buffer);
    free(payload);
    if (ret != SDR_OK) return ret;
    sdfx_extended_resp_t *response;
    uint32_t response_len;
    ret = vpn_response(buffer, &response, &response_len);
    if (ret == SDR_OK &&
        response_len != 2 * sizeof(sdfx_remote_handle_t) + uiSaltLength)
        ret = SDR_PROTOCOL_ERROR;
    if (ret == SDR_OK) {
        sdfx_remote_handle_t wire_enc, wire_mac;
        memcpy(&wire_enc, response->data, sizeof(wire_enc));
        memcpy(&wire_mac, response->data + sizeof(wire_enc), sizeof(wire_mac));
        *phKeyHandleEnc = NULL;
        if (phKeyHandleMac != NULL) *phKeyHandleMac = NULL;
        ret = create_key_from_id(sdfx_ntohll(wire_enc), phKeyHandleEnc);
        if (ret == SDR_OK && uiKeyBitsMac > 0) {
            ret = create_key_from_id(sdfx_ntohll(wire_mac), phKeyHandleMac);
            if (ret != SDR_OK) {
                SDF_DestroyKey(hSessionHandle, *phKeyHandleEnc);
                *phKeyHandleEnc = NULL;
            }
        }
        if (ret == SDR_OK && uiSaltLength > 0)
            memcpy(pucSalt, response->data + 2 * sizeof(wire_enc),
                   uiSaltLength);
    }
    free(buffer);
    return ret;
}

LONG SDF_GenerateKeywithEPK_IPSEC(
    HANDLE hSessionHandle, BYTE *pucProtocolID, ULONG uiProtocolIDLength,
    BYTE *pucSpi, ULONG uiSpiLength,
    BYTE *pucSponsorNonce, ULONG uiSponsorNonceLength,
    BYTE *pucResponseNonce, ULONG uiResponseNonceLength,
    HANDLE hKeyHandle, ULONG uiPrfAlgID, ULONG uiEccAlgID,
    ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucKeyEnc, ULONG uiKeyBitsEnc,
    ECCCipher *pucKeyMac, ULONG uiKeyBitsMac,
    BYTE *pucSalt, ULONG uiSaltLength)
{
    if (uiEccAlgID != SGD_SM2_3) return SDR_ALGNOTSUPPORT;
    if (hSessionHandle == NULL || hKeyHandle == NULL ||
        pucPublicKey == NULL ||
        pucKeyEnc == NULL || (uiKeyBitsMac > 0 && pucKeyMac == NULL) ||
        (uiSaltLength > 0 && pucSalt == NULL)) return SDR_INARGERR;
    const BYTE *inputs[4] = {pucProtocolID, pucSpi, pucSponsorNonce,
                             pucResponseNonce};
    uint32_t lengths[4] = {uiProtocolIDLength, uiSpiLength,
                           uiSponsorNonceLength, uiResponseNonceLength};
    uint32_t payload_len = 0;
    BYTE *payload = concat_inputs(pucPublicKey, inputs, lengths, &payload_len);
    if (payload == NULL) return SDR_INARGERR;
    sdfx_remote_handle_t key_id;
    LONG ret = sdf_get_server_key_id(hKeyHandle, &key_id);
    uint32_t param[8] = {lengths[0], lengths[1], lengths[2], lengths[3],
                         uiKeyBitsEnc, uiKeyBitsMac, uiSaltLength, 0};
    BYTE *buffer = NULL;
    if (ret == SDR_OK)
        ret = sdf_extended_call_id(hSessionHandle, key_id,
            SDFX_EXT_VPN_IPSEC_EPK, uiPrfAlgID, param, payload, payload_len,
            &buffer);
    free(payload);
    if (ret != SDR_OK) return ret;
    sdfx_extended_resp_t *response;
    uint32_t response_len;
    ret = vpn_response(buffer, &response, &response_len);
    uint32_t enc_len = sdfx_ntohl(response->param[0]);
    uint32_t mac_len = sdfx_ntohl(response->param[1]);
    uint32_t salt_len = sdfx_ntohl(response->param[2]);
    if (ret == SDR_OK && enc_len + mac_len + salt_len != response_len)
        ret = SDR_PROTOCOL_ERROR;
    if (ret == SDR_OK)
        ret = copy_cipher_blob(pucKeyEnc, response->data, enc_len);
    if (ret == SDR_OK && mac_len > 0)
        ret = copy_cipher_blob(pucKeyMac, response->data + enc_len, mac_len);
    if (ret == SDR_OK && salt_len > 0)
        memcpy(pucSalt, response->data + enc_len + mac_len, salt_len);
    free(buffer);
    return ret;
}

static LONG ssl_common(HANDLE session, HANDLE pre_master,
                       BYTE *client_random, ULONG client_len,
                       BYTE *server_random, ULONG server_len,
                       ULONG prf_alg, const uint32_t bits[4],
                       ULONG client_iv_len, ULONG server_iv_len,
                       const ECCrefPublicKey *public_key,
                       BYTE **buffer)
{
    const BYTE *inputs[4] = {client_random, server_random, NULL, NULL};
    uint32_t lengths[4] = {client_len, server_len, 0, 0};
    uint32_t payload_len = 0;
    BYTE *payload = concat_inputs(public_key, inputs, lengths, &payload_len);
    if (payload == NULL) return SDR_INARGERR;
    sdfx_remote_handle_t key_id;
    LONG ret = sdf_get_server_key_id(pre_master, &key_id);
    uint32_t param[8] = {client_len, server_len, bits[0], bits[1],
                         bits[2], bits[3], client_iv_len, server_iv_len};
    if (ret == SDR_OK)
        ret = sdf_extended_call_id(session, key_id,
            public_key == NULL ? SDFX_EXT_VPN_SSL : SDFX_EXT_VPN_SSL_EPK,
            prf_alg, param, payload, payload_len, buffer);
    free(payload);
    return ret;
}

LONG SDF_GenerateKeywithSSL(
    HANDLE hSessionHandle, HANDLE hKeyHandlePreMaster,
    BYTE *pucClientRandom, ULONG uiClientRandomLength,
    BYTE *pucServerRandom, ULONG uiServerRandomLength, ULONG uiPrfAlgID,
    HANDLE *phKeyHandleClientMac, ULONG uiKeyBitsClientMac,
    HANDLE *phKeyHandleServerMac, ULONG uiKeyBitsServerMac,
    HANDLE *phKeyHandleClientEnc, ULONG uiKeyBitsClientEnc,
    HANDLE *phKeyHandleServerEnc, ULONG uiKeyBitsServerEnc,
    BYTE *pucClientIV, ULONG uiClientIVLength,
    BYTE *pucServerIV, ULONG uiServerIVLength)
{
    if (hSessionHandle == NULL || hKeyHandlePreMaster == NULL ||
        phKeyHandleClientMac == NULL || phKeyHandleServerMac == NULL ||
        phKeyHandleClientEnc == NULL || phKeyHandleServerEnc == NULL ||
        (uiClientIVLength > 0 && pucClientIV == NULL) ||
        (uiServerIVLength > 0 && pucServerIV == NULL)) return SDR_INARGERR;
    uint32_t bits[4] = {uiKeyBitsClientMac, uiKeyBitsServerMac,
                        uiKeyBitsClientEnc, uiKeyBitsServerEnc};
    BYTE *buffer = NULL;
    LONG ret = ssl_common(hSessionHandle, hKeyHandlePreMaster,
        pucClientRandom, uiClientRandomLength, pucServerRandom,
        uiServerRandomLength, uiPrfAlgID, bits, uiClientIVLength,
        uiServerIVLength, NULL, &buffer);
    if (ret != SDR_OK) return ret;
    sdfx_extended_resp_t *response;
    uint32_t response_len;
    ret = vpn_response(buffer, &response, &response_len);
    uint32_t expected = 4 * sizeof(sdfx_remote_handle_t) +
                        uiClientIVLength + uiServerIVLength;
    if (ret == SDR_OK && response_len != expected) ret = SDR_PROTOCOL_ERROR;
    if (ret == SDR_OK) {
        HANDLE *handles[4] = {phKeyHandleClientMac, phKeyHandleServerMac,
                              phKeyHandleClientEnc, phKeyHandleServerEnc};
        ret = create_key_set(hSessionHandle, response->data, 4, handles);
    }
    if (ret == SDR_OK) {
        const BYTE *iv = response->data + 4 * sizeof(sdfx_remote_handle_t);
        if (uiClientIVLength > 0) memcpy(pucClientIV, iv, uiClientIVLength);
        if (uiServerIVLength > 0)
            memcpy(pucServerIV, iv + uiClientIVLength, uiServerIVLength);
    }
    free(buffer);
    return ret;
}

LONG SDF_GenerateKeywithEPK_SSL(
    HANDLE hSessionHandle, HANDLE hKeyHandlePreMaster,
    BYTE *pucClientRandom, ULONG uiClientRandomLength,
    BYTE *pucServerRandom, ULONG uiServerRandomLength, ULONG uiPrfAlgID,
    ULONG uiEccAlgID, ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucKeyClientMac, ULONG uiKeyBitsClientMac,
    ECCCipher *pucKeyServerMac, ULONG uiKeyBitsServerMac,
    ECCCipher *pucKeyClientEnc, ULONG uiKeyBitsClientEnc,
    ECCCipher *pucKeyServerEnc, ULONG uiKeyBitsServerEnc,
    BYTE *pucClientIV, ULONG uiClientIVLength,
    BYTE *pucServerIV, ULONG uiServerIVLength)
{
    if (uiEccAlgID != SGD_SM2_3) return SDR_ALGNOTSUPPORT;
    if (hSessionHandle == NULL || hKeyHandlePreMaster == NULL ||
        pucPublicKey == NULL ||
        pucKeyClientMac == NULL || pucKeyServerMac == NULL ||
        pucKeyClientEnc == NULL || pucKeyServerEnc == NULL ||
        (uiClientIVLength > 0 && pucClientIV == NULL) ||
        (uiServerIVLength > 0 && pucServerIV == NULL)) return SDR_INARGERR;
    uint32_t bits[4] = {uiKeyBitsClientMac, uiKeyBitsServerMac,
                        uiKeyBitsClientEnc, uiKeyBitsServerEnc};
    BYTE *buffer = NULL;
    LONG ret = ssl_common(hSessionHandle, hKeyHandlePreMaster,
        pucClientRandom, uiClientRandomLength, pucServerRandom,
        uiServerRandomLength, uiPrfAlgID, bits, uiClientIVLength,
        uiServerIVLength, pucPublicKey, &buffer);
    if (ret != SDR_OK) return ret;
    sdfx_extended_resp_t *response;
    uint32_t response_len;
    ret = vpn_response(buffer, &response, &response_len);
    uint32_t offset = 0;
    ECCCipher *outputs[4] = {pucKeyClientMac, pucKeyServerMac,
                             pucKeyClientEnc, pucKeyServerEnc};
    for (uint32_t i = 0; ret == SDR_OK && i < 4; ++i) {
        uint32_t length = sdfx_ntohl(response->param[i]);
        if (length > response_len - offset) ret = SDR_PROTOCOL_ERROR;
        else ret = copy_cipher_blob(outputs[i], response->data + offset,
                                    length);
        offset += length;
    }
    if (ret == SDR_OK &&
        offset + uiClientIVLength + uiServerIVLength != response_len)
        ret = SDR_PROTOCOL_ERROR;
    if (ret == SDR_OK) {
        if (uiClientIVLength > 0)
            memcpy(pucClientIV, response->data + offset, uiClientIVLength);
        if (uiServerIVLength > 0)
            memcpy(pucServerIV, response->data + offset + uiClientIVLength,
                   uiServerIVLength);
    }
    free(buffer);
    return ret;
}
