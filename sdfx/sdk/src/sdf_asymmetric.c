/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file sdf_asymmetric.c
 * @brief SDF asymmetric cryptography algorithm module
 */

#include "sdf_internal.h"

/* Module Initialization */
LONG sdf_asymmetric_init(void)
{
    return SDR_OK;
}

/* Module Cleanup */
void sdf_asymmetric_cleanup(void)
{
    /* Clean up asymmetric encryption related resources */
}

LONG SDF_InternalSign_ECC(HANDLE hSessionHandle, ULONG uiISKIndex,
    BYTE *pucData, ULONG uiDataLength, ECCSignature *pucSignature)
{
    SDF_CHECK_PARAM(hSessionHandle != NULL && uiISKIndex > 0 &&
                    pucData != NULL && uiDataLength > 0 &&
                    uiDataLength <= SDFX_MAX_BLOB_LENGTH &&
                    pucSignature != NULL, SDR_INARGERR);
    sdfx_remote_handle_t session_id;
    SDF_CHECK_SESSION(hSessionHandle, session_id);

    size_t request_size = sizeof(sdfx_internal_sign_ecc_req_t) + uiDataLength;
    sdfx_internal_sign_ecc_req_t *request = malloc(request_size);
    if (request == NULL) {
        return SDR_NOBUFFER;
    }
    request->session_handle = sdfx_htonll(session_id);
    request->key_index = sdfx_htonl(uiISKIndex);
    request->data_length = sdfx_htonl(uiDataLength);
    memcpy(request->data, pucData, uiDataLength);

    BYTE response[sizeof(sdfx_message_header_t) + sizeof(sdfx_internal_sign_ecc_resp_t)];
    size_t response_len = 0;
    LONG ret = sdf_send_request(SDFX_CMD_INTERNAL_SIGN_ECC, request, request_size,
                                response, sizeof(response), &response_len);
    free(request);
    if (ret != SDR_OK) {
        return ret;
    }
    const sdfx_message_t *message = (const sdfx_message_t *)response;
    if (message->header.length < sizeof(sdfx_internal_sign_ecc_resp_t)) {
        return SDR_PROTOCOL_ERROR;
    }
    memcpy(pucSignature, message->data, sizeof(*pucSignature));
    return SDR_OK;
}

LONG SDF_InternalVerify_ECC(HANDLE hSessionHandle, ULONG uiISKIndex,
    BYTE *pucData, ULONG uiDataLength, ECCSignature *pucSignature)
{
    SDF_CHECK_PARAM(hSessionHandle != NULL && uiISKIndex > 0 &&
                    pucData != NULL && uiDataLength > 0 &&
                    uiDataLength <= SDFX_MAX_BLOB_LENGTH &&
                    pucSignature != NULL, SDR_INARGERR);
    sdfx_remote_handle_t session_id;
    SDF_CHECK_SESSION(hSessionHandle, session_id);

    size_t request_size = sizeof(sdfx_internal_verify_ecc_req_t) + uiDataLength;
    sdfx_internal_verify_ecc_req_t *request = malloc(request_size);
    if (request == NULL) {
        return SDR_NOBUFFER;
    }
    request->session_handle = sdfx_htonll(session_id);
    request->key_index = sdfx_htonl(uiISKIndex);
    request->data_length = sdfx_htonl(uiDataLength);
    memcpy(&request->signature, pucSignature, sizeof(*pucSignature));
    memcpy(request->data, pucData, uiDataLength);

    BYTE response[sizeof(sdfx_message_header_t)];
    size_t response_len = 0;
    LONG ret = sdf_send_request(SDFX_CMD_INTERNAL_VERIFY_ECC, request, request_size,
                                response, sizeof(response), &response_len);
    free(request);
    return ret;
}

LONG SDF_ExternalEncrypt_ECC(HANDLE hSessionHandle, ULONG uiAlgID,
    ECCrefPublicKey *pucPublicKey, BYTE *pucData, ULONG uiDataLength,
    ECCCipher *pucEncData)
{
    SDF_CHECK_PARAM(hSessionHandle != NULL && pucPublicKey != NULL &&
                    pucData != NULL && uiDataLength > 0 && uiDataLength <= 256 &&
                    pucEncData != NULL, SDR_INARGERR);
    if (uiAlgID != SGD_SM2_3) {
        return SDR_ALGNOTSUPPORT;
    }

    sdfx_remote_handle_t server_session_id;
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);

    size_t req_size = sizeof(sdfx_external_encrypt_ecc_req_t) + uiDataLength;
    sdfx_external_encrypt_ecc_req_t *req = malloc(req_size);
    if (req == NULL) {
        return SDR_MEMORY_ERROR;
    }
    req->session_handle = sdfx_htonll(server_session_id);
    req->alg_id = sdfx_htonl(uiAlgID);
    memcpy(&req->public_key, pucPublicKey, sizeof(ECCrefPublicKey));
    req->data_length = sdfx_htonl(uiDataLength);
    memcpy(req->data, pucData, uiDataLength);

    BYTE resp_buffer[1024];
    size_t resp_len = 0;
    LONG ret = sdf_send_request(SDFX_CMD_EXTERNAL_ENCRYPT_ECC, req, req_size,
                                resp_buffer, sizeof(resp_buffer), &resp_len);
    free(req);
    if (ret != SDR_OK) {
        return ret;
    }

    sdfx_message_t *resp_msg = (sdfx_message_t *)resp_buffer;
    if (resp_msg->header.length < sizeof(sdfx_external_encrypt_ecc_resp_t)) {
        return SDR_PROTOCOL_ERROR;
    }
    sdfx_external_encrypt_ecc_resp_t *resp =
        (sdfx_external_encrypt_ecc_resp_t *)resp_msg->data;
    ULONG cipher_len = sdfx_ntohl(resp->cipher.L);
    size_t cipher_size = sizeof(ECCCipher) + cipher_len - 1;
    if (cipher_len == 0 || cipher_len > 256 ||
        resp_msg->header.length < sizeof(sdfx_external_encrypt_ecc_resp_t) + cipher_len - 1) {
        return SDR_PROTOCOL_ERROR;
    }
    memcpy(pucEncData, &resp->cipher, cipher_size);
    pucEncData->L = cipher_len;
    return SDR_OK;
}
LONG SDF_ExternalDecrypt_ECC(HANDLE hSessionHandle, ULONG uiAlgID,
    ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData,
    BYTE *pucData, ULONG *puiDataLength)
{
    SDF_CHECK_PARAM(hSessionHandle != NULL && pucPrivateKey != NULL &&
                    pucEncData != NULL && pucData != NULL &&
                    puiDataLength != NULL && pucEncData->L > 0 && pucEncData->L <= 256,
                    SDR_INARGERR);
    if (uiAlgID != SGD_SM2_3) {
        return SDR_ALGNOTSUPPORT;
    }

    sdfx_remote_handle_t server_session_id;
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);

    ULONG cipher_len = pucEncData->L;
    size_t req_size = sizeof(sdfx_external_decrypt_ecc_req_t) + cipher_len - 1;
    sdfx_external_decrypt_ecc_req_t *req = malloc(req_size);
    if (req == NULL) {
        return SDR_MEMORY_ERROR;
    }
    req->session_handle = sdfx_htonll(server_session_id);
    req->alg_id = sdfx_htonl(uiAlgID);
    memcpy(&req->private_key, pucPrivateKey, sizeof(ECCrefPrivateKey));
    memcpy(&req->cipher, pucEncData, sizeof(ECCCipher) + cipher_len - 1);
    req->cipher.L = sdfx_htonl(cipher_len);

    BYTE resp_buffer[1024];
    size_t resp_len = 0;
    LONG ret = sdf_send_request(SDFX_CMD_EXTERNAL_DECRYPT_ECC, req, req_size,
                                resp_buffer, sizeof(resp_buffer), &resp_len);
    free(req);
    if (ret != SDR_OK) {
        return ret;
    }

    sdfx_message_t *resp_msg = (sdfx_message_t *)resp_buffer;
    if (resp_msg->header.length < sizeof(sdfx_external_decrypt_ecc_resp_t)) {
        return SDR_PROTOCOL_ERROR;
    }
    sdfx_external_decrypt_ecc_resp_t *resp =
        (sdfx_external_decrypt_ecc_resp_t *)resp_msg->data;
    ULONG plaintext_len = sdfx_ntohl(resp->data_length);
    if (resp_msg->header.length < sizeof(*resp) + plaintext_len) {
        return SDR_PROTOCOL_ERROR;
    }
    if (plaintext_len > *puiDataLength) {
        *puiDataLength = plaintext_len;
        return SDR_NOBUFFER;
    }
    memcpy(pucData, resp->data, plaintext_len);
    *puiDataLength = plaintext_len;
    return SDR_OK;
}
LONG SDF_GenerateKeyPair_ECC(HANDLE hSessionHandle, ULONG uiAlgID, ULONG uiKeyBits,
    ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
    SDF_CHECK_PARAM(hSessionHandle != NULL && pucPublicKey != NULL && 
                    pucPrivateKey != NULL && uiKeyBits == 256 &&
                    (uiAlgID == SGD_SM2 || uiAlgID == SGD_SM2_1 || uiAlgID == SGD_SM2_2 ||
                     uiAlgID == SGD_SM2_3), SDR_INARGERR);
    
    sdfx_remote_handle_t server_session_id;
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);
    
    sdfx_generate_keypair_ecc_req_t req;
    BYTE resp_buffer[1024];
    size_t resp_len;
    sdfx_message_t *resp_msg;
    LONG ret;
    
    req.session_handle = sdfx_htonll(server_session_id);
    req.alg_id = sdfx_htonl(uiAlgID);
    
    ret = sdf_send_request(SDFX_CMD_GENERATE_KEYPAIR_ECC, &req, sizeof(req),
                           resp_buffer, sizeof(resp_buffer), &resp_len);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Parse response */
    resp_msg = (sdfx_message_t*)resp_buffer;
    if (resp_msg->header.length >= sizeof(sdfx_generate_keypair_ecc_resp_t)) {
        sdfx_generate_keypair_ecc_resp_t *resp = (sdfx_generate_keypair_ecc_resp_t*)resp_msg->data;
        
        memcpy(pucPublicKey, &resp->public_key, sizeof(ECCrefPublicKey));
        memcpy(pucPrivateKey, &resp->private_key, sizeof(ECCrefPrivateKey));
        
        return SDR_OK;
    }
    
    return SDR_PROTOCOL_ERROR;
}

LONG SDF_ExternalSign_ECC(HANDLE hSessionHandle, ULONG uiAlgID,
    ECCrefPrivateKey *pucPrivateKey, BYTE *pucData, ULONG uiDataLength,
    ECCSignature *pucSignature)
{
    SDF_CHECK_PARAM(hSessionHandle != NULL && pucPrivateKey != NULL && 
                    pucData != NULL && uiDataLength == 32 &&
                    pucSignature != NULL, SDR_INARGERR);
    if (uiAlgID != SGD_SM2_1) {
        return SDR_ALGNOTSUPPORT;
    }
    
    sdfx_remote_handle_t server_session_id;
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);
    
    sdfx_external_sign_ecc_req_t *req;
    BYTE resp_buffer[1024];
    size_t req_size = sizeof(sdfx_external_sign_ecc_req_t) + uiDataLength;
    size_t resp_len;
    sdfx_message_t *resp_msg;
    LONG ret;
    
    req = malloc(req_size);
    if (req == NULL) {
        return SDR_MEMORY_ERROR;
    }
    
    req->session_handle = sdfx_htonll(server_session_id);
    req->alg_id = sdfx_htonl(uiAlgID);
    memcpy(&req->private_key, pucPrivateKey, sizeof(ECCrefPrivateKey));
    req->data_length = sdfx_htonl(uiDataLength);
    memcpy(req->data, pucData, uiDataLength);
    
    ret = sdf_send_request(SDFX_CMD_EXTERNAL_SIGN_ECC, req, req_size,
                           resp_buffer, sizeof(resp_buffer), &resp_len);
    
    if (ret == SDR_OK) {
        /* Parse response */
        resp_msg = (sdfx_message_t*)resp_buffer;
        if (resp_msg->header.length >= sizeof(sdfx_external_sign_ecc_resp_t)) {
            sdfx_external_sign_ecc_resp_t *resp = (sdfx_external_sign_ecc_resp_t*)resp_msg->data;
            ULONG sig_len = sdfx_ntohl(resp->signature_length);
            if (sig_len == 64) { /* SM2 signature format: r(32) + s(32) */
                memset(pucSignature, 0, sizeof(*pucSignature));
                memcpy(pucSignature->r + ECCref_MAX_LEN - 32, resp->signature, 32);
                memcpy(pucSignature->s + ECCref_MAX_LEN - 32, resp->signature + 32, 32);
            } else {
                ret = SDR_KEYERR;
            }
        } else {
            ret = SDR_PROTOCOL_ERROR;
        }
    }
    
    free(req);
    return ret;
}

LONG SDF_ExternalVerify_ECC(HANDLE hSessionHandle, ULONG uiAlgID,
    ECCrefPublicKey *pucPublicKey, BYTE *pucData, ULONG uiDataLength,
    ECCSignature *pucSignature)
{
    SDF_CHECK_PARAM(hSessionHandle != NULL && pucPublicKey != NULL && 
                    pucData != NULL && uiDataLength == 32 &&
                    pucSignature != NULL, SDR_INARGERR);
    if (uiAlgID != SGD_SM2_1) {
        return SDR_ALGNOTSUPPORT;
    }
    
    sdfx_remote_handle_t server_session_id;
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);
    
    sdfx_external_verify_ecc_req_t *req;
    BYTE resp_buffer[1024];
    size_t req_size = sizeof(sdfx_external_verify_ecc_req_t) + uiDataLength + 64;
    size_t resp_len;
    sdfx_message_t *resp_msg;
    LONG ret;
    
    req = malloc(req_size);
    if (req == NULL) {
        return SDR_MEMORY_ERROR;
    }
    
    req->session_handle = sdfx_htonll(server_session_id);
    req->alg_id = sdfx_htonl(uiAlgID);
    memcpy(&req->public_key, pucPublicKey, sizeof(ECCrefPublicKey));
    req->data_length = sdfx_htonl(uiDataLength);
    req->signature_length = sdfx_htonl(64); /* SM2 signature length */
    
    /* Copy data and signature */
    memcpy(req->payload, pucData, uiDataLength);
    memcpy(req->payload + uiDataLength,
           pucSignature->r + ECCref_MAX_LEN - 32, 32);
    memcpy(req->payload + uiDataLength + 32,
           pucSignature->s + ECCref_MAX_LEN - 32, 32);
    
    ret = sdf_send_request(SDFX_CMD_EXTERNAL_VERIFY_ECC, req, req_size,
                           resp_buffer, sizeof(resp_buffer), &resp_len);
    
    if (ret == SDR_OK) {
        /* Parse response */
        resp_msg = (sdfx_message_t*)resp_buffer;
        if (resp_msg->header.length >= sizeof(sdfx_external_verify_ecc_resp_t)) {
            sdfx_external_verify_ecc_resp_t *resp = (sdfx_external_verify_ecc_resp_t*)resp_msg->data;
            ULONG result = sdfx_ntohl(resp->result);
            ret = (result == 0) ? SDR_OK : SDR_VERIFYERR;
        } else {
            ret = SDR_PROTOCOL_ERROR;
        }
    }
    
    free(req);
    return ret;
}
