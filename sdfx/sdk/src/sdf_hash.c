/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file sdf_hash.c
 * @brief SDF hash algorithm module
 */

#include "sdf_internal.h"

/* Module Initialization */
LONG sdf_hash_init(void)
{
    return SDR_OK;
}

/* Module Cleanup */
void sdf_hash_cleanup(void)
{
    /* Clean up hash algorithm related resources */
}

LONG SDF_HashInit(HANDLE hSessionHandle, ULONG uiAlgID, 
    ECCrefPublicKey *pucPublicKey, BYTE *pucID, ULONG uiIDLength)
{
    BYTE req_buffer[512];  // A sufficiently large buffer for the request
    BYTE resp_buffer[256];
    size_t resp_len;
    sdfx_message_t *resp_msg;
    sdfx_remote_handle_t server_session_id;
    /* SM2 Z-value preprocessing requires both public key and identity handling.
     * It is not implemented by the current server and must not be ignored. */
    if (pucPublicKey != NULL || pucID != NULL || uiIDLength != 0) {
        return SDR_NOTSUPPORT;
    }
    LONG ret;
    
    SDF_CHECK_PARAM(hSessionHandle != NULL, SDR_INARGERR);
    
    /* Validate session handle and get server session ID */
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);
    
    /* Prepare request data */
    sdfx_hash_init_req_t *req = (sdfx_hash_init_req_t*)req_buffer;
    req->session_handle = sdfx_htonll(server_session_id);
    req->alg_id = sdfx_htonl(uiAlgID);
    req->id_length = sdfx_htonl(uiIDLength);
    
    /* Copy public key information (if provided) */
    if (pucPublicKey != NULL) {
        memcpy(&req->public_key, pucPublicKey, sizeof(ECCrefPublicKey));
    } else {
        memset(&req->public_key, 0, sizeof(ECCrefPublicKey));
    }
    
    /* Copy ID data (if provided) */
    size_t req_size = sizeof(sdfx_hash_init_req_t);
    if (pucID != NULL && uiIDLength > 0) {
        if (uiIDLength > 256) {  // Prevent buffer overflow
            return SDR_INARGERR;
        }
        memcpy(req->id_data, pucID, uiIDLength);
        req_size += uiIDLength;
    }
    
    /* Send request */
    ret = sdf_send_request(SDFX_CMD_HASH_INIT, req, req_size,
                          resp_buffer, sizeof(resp_buffer), &resp_len);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Validate response */
    resp_msg = (sdfx_message_t*)resp_buffer;
    return sdfx_ntohl(resp_msg->header.status);
}

LONG SDF_HashUpdate(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength)
{
    BYTE req_buffer[4096];  // A sufficiently large buffer for the data
    BYTE resp_buffer[256];
    size_t resp_len;
    sdfx_message_t *resp_msg;
    sdfx_remote_handle_t server_session_id;
    LONG ret;
    
    SDF_CHECK_PARAM(hSessionHandle != NULL && pucData != NULL && uiDataLength > 0, SDR_INARGERR);
    
    /* Validate session handle and get server session ID */
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);
    
    /* Check data length limit */
    if (uiDataLength > 3000) {  // Prevent buffer overflow
        return SDR_INARGERR;
    }
    
    /* Prepare request data */
    sdfx_hash_update_req_t *req = (sdfx_hash_update_req_t*)req_buffer;
    req->session_handle = sdfx_htonll(server_session_id);
    req->data_length = sdfx_htonl(uiDataLength);
    memcpy(req->data, pucData, uiDataLength);
    
    size_t req_size = sizeof(sdfx_hash_update_req_t) + uiDataLength;
    
    /* Send request */
    ret = sdf_send_request(SDFX_CMD_HASH_UPDATE, req, req_size,
                          resp_buffer, sizeof(resp_buffer), &resp_len);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Validate response */
    resp_msg = (sdfx_message_t*)resp_buffer;
    return sdfx_ntohl(resp_msg->header.status);
}

LONG SDF_HashFinal(HANDLE hSessionHandle, BYTE *pucHash, ULONG *puiHashLength)
{
    sdfx_hash_final_req_t req;
    BYTE resp_buffer[256];
    size_t resp_len;
    sdfx_message_t *resp_msg;
    sdfx_remote_handle_t server_session_id;
    LONG ret;
    
    SDF_CHECK_PARAM(hSessionHandle != NULL && pucHash != NULL && puiHashLength != NULL, SDR_INARGERR);
    
    /* Validate session handle and get server session ID */
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);
    
    /* Prepare request */
    req.session_handle = sdfx_htonll(server_session_id);
    
    /* Send request */
    ret = sdf_send_request(SDFX_CMD_HASH_FINAL, &req, sizeof(req),
                          resp_buffer, sizeof(resp_buffer), &resp_len);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Parse response */
    resp_msg = (sdfx_message_t*)resp_buffer;
    
    if (sdfx_ntohl(resp_msg->header.status) != SDR_OK) {
        return sdfx_ntohl(resp_msg->header.status);
    }
    
    if (resp_msg->header.length >= sizeof(sdfx_hash_final_resp_t)) {
        sdfx_hash_final_resp_t *resp = (sdfx_hash_final_resp_t*)resp_msg->data;
        ULONG hash_length = sdfx_ntohl(resp->hash_length);
        
        if (hash_length > *puiHashLength) {
            *puiHashLength = hash_length;
            return SDR_NOBUFFER;
        }
        
        *puiHashLength = hash_length;
        memcpy(pucHash, resp->hash_data, hash_length);
        return SDR_OK;
    }
    
    return SDR_PROTOCOL_ERROR;
}