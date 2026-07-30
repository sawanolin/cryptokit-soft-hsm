/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file sdf_symmetric.c
 * @brief SDF symmetric encryption algorithm module
 */

#include "sdf_internal.h"

/* Module initialization */
LONG sdf_symmetric_init(void)
{
    return SDR_OK;
}

/* Module cleanup */
void sdf_symmetric_cleanup(void)
{
    /* Clean up symmetric encryption related resources */
}

/**
 * @brief Determine IV length based on algorithm ID
 */
static ULONG get_iv_length(ULONG uiAlgID)
{
    switch (uiAlgID) {
        case SGD_SM4_CBC:
        case SGD_SM4_CFB:
        case SGD_SM4_OFB:
        case SGD_SM4_CTR:
            return 16;  // SM4 block size
        case SGD_SM4_ECB:
            return 0;   // ECB doesn't use IV
        default:
            return 0;
    }
}

LONG SDF_Encrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID, 
    BYTE *pucIV, BYTE *pucData, ULONG uiDataLength, 
    BYTE *pucEncData, ULONG *puiEncDataLength)
{
    BYTE req_buffer[8192];  // A sufficiently large buffer for the request data
    BYTE resp_buffer[8192];
    size_t resp_len;
    sdfx_message_t *resp_msg;
    sdfx_remote_handle_t server_session_id;
    LONG ret;
    
    SDF_CHECK_PARAM(hSessionHandle != NULL && hKeyHandle != NULL && pucData != NULL && 
                    pucEncData != NULL && uiDataLength > 0 && 
                    puiEncDataLength != NULL, SDR_INARGERR);
    
    /* Validate session handle and get server session ID */
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);
    sdfx_remote_handle_t server_key_id;
    ret = sdf_get_server_key_id(hKeyHandle, &server_key_id);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Determine IV length */
    ULONG iv_length = 0;
    if (pucIV != NULL) {
        iv_length = get_iv_length(uiAlgID);
        if (iv_length == 0 && uiAlgID != SGD_SM4_ECB) {
            return SDR_ALGNOTSUPPORT;
        }
    }
    
    /* Construct request message */
    sdfx_encrypt_req_t *req = (sdfx_encrypt_req_t *)req_buffer;
    req->session_handle = sdfx_htonll(server_session_id);
    req->key_handle = sdfx_htonll(server_key_id);
    req->alg_id = sdfx_htonl(uiAlgID);
    req->iv_length = sdfx_htonl(iv_length);
    req->data_length = sdfx_htonl(uiDataLength);
    
    /* Copy IV and data */
    BYTE *payload = req->payload;
    if (iv_length > 0 && pucIV != NULL) {
        memcpy(payload, pucIV, iv_length);
        payload += iv_length;
    }
    memcpy(payload, pucData, uiDataLength);
    
    ULONG total_req_size = sizeof(sdfx_encrypt_req_t) + iv_length + uiDataLength;
    
    /* Send request and receive response */
    ret = sdf_send_request(SDFX_CMD_ENCRYPT, req, total_req_size,
                          resp_buffer, sizeof(resp_buffer), &resp_len);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Parse response */
    resp_msg = (sdfx_message_t*)resp_buffer;
    ULONG status = sdfx_ntohl(resp_msg->header.status);
    if (status != SDR_OK) {
        return status;
    }
    
    if (resp_msg->header.length >= sizeof(sdfx_encrypt_resp_t)) {
        sdfx_encrypt_resp_t *resp = (sdfx_encrypt_resp_t*)resp_msg->data;
        ULONG enc_data_length = sdfx_ntohl(resp->enc_data_length);
        
        if (*puiEncDataLength < enc_data_length) {
            *puiEncDataLength = enc_data_length;
            return SDR_NOBUFFER;
        }
        
        memcpy(pucEncData, resp->enc_data, enc_data_length);
        *puiEncDataLength = enc_data_length;
        return SDR_OK;
    }
    
    return SDR_PROTOCOL_ERROR;
}

LONG SDF_Decrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
    BYTE *pucIV, BYTE *pucEncData, ULONG uiEncDataLength,
    BYTE *pucData, ULONG *puiDataLength)
{
    BYTE req_buffer[8192];  // A sufficiently large buffer for the request data
    BYTE resp_buffer[8192];
    size_t resp_len;
    sdfx_message_t *resp_msg;
    sdfx_remote_handle_t server_session_id;
    LONG ret;
    
    SDF_CHECK_PARAM(hSessionHandle != NULL && hKeyHandle != NULL && pucEncData != NULL && 
                    pucData != NULL && uiEncDataLength > 0 && 
                    puiDataLength != NULL, SDR_INARGERR);
    
    /* Validate session handle and get server session ID */
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);
    sdfx_remote_handle_t server_key_id;
    ret = sdf_get_server_key_id(hKeyHandle, &server_key_id);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Determine IV length */
    ULONG iv_length = 0;
    if (pucIV != NULL) {
        iv_length = get_iv_length(uiAlgID);
        if (iv_length == 0 && uiAlgID != SGD_SM4_ECB) {
            return SDR_ALGNOTSUPPORT;
        }
    }
    
    /* Construct request message */
    sdfx_decrypt_req_t *req = (sdfx_decrypt_req_t *)req_buffer;
    req->session_handle = sdfx_htonll(server_session_id);
    req->key_handle = sdfx_htonll(server_key_id);
    req->alg_id = sdfx_htonl(uiAlgID);
    req->iv_length = sdfx_htonl(iv_length);
    req->enc_data_length = sdfx_htonl(uiEncDataLength);
    
    /* Copy IV and ciphertext data */
    BYTE *payload = req->payload;
    if (iv_length > 0 && pucIV != NULL) {
        memcpy(payload, pucIV, iv_length);
        payload += iv_length;
    }
    memcpy(payload, pucEncData, uiEncDataLength);
    
    ULONG total_req_size = sizeof(sdfx_decrypt_req_t) + iv_length + uiEncDataLength;
    
    /* Send request and receive response */
    ret = sdf_send_request(SDFX_CMD_DECRYPT, req, total_req_size,
                          resp_buffer, sizeof(resp_buffer), &resp_len);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Parse response */
    resp_msg = (sdfx_message_t*)resp_buffer;
    ULONG status = sdfx_ntohl(resp_msg->header.status);
    if (status != SDR_OK) {
        return status;
    }
    
    if (resp_msg->header.length >= sizeof(sdfx_decrypt_resp_t)) {
        sdfx_decrypt_resp_t *resp = (sdfx_decrypt_resp_t*)resp_msg->data;
        ULONG data_length = sdfx_ntohl(resp->data_length);
        
        if (*puiDataLength < data_length) {
            *puiDataLength = data_length;
            return SDR_NOBUFFER;
        }
        
        memcpy(pucData, resp->data, data_length);
        *puiDataLength = data_length;
        return SDR_OK;
    }
    
    return SDR_PROTOCOL_ERROR;
}