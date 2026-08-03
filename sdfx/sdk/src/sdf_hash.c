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
    BYTE resp_buffer[256];
    size_t resp_len;
    sdfx_message_t *resp_msg;
    sdfx_remote_handle_t server_session_id;
    BYTE *req_buffer = NULL;
    LONG ret;
    
    SDF_CHECK_PARAM(hSessionHandle != NULL, SDR_INARGERR);
    
    /* Validate session handle and get server session ID */
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);

    /* GM/T 0018: a non-empty identity requests SM2 Z-value preprocessing. */
    if (uiIDLength > 0) {
        SDF_CHECK_PARAM(uiAlgID == SGD_SM3, SDR_ALGNOTSUPPORT);
        SDF_CHECK_PARAM(pucPublicKey != NULL && pucID != NULL, SDR_INARGERR);
        SDF_CHECK_PARAM(uiIDLength <= SDFX_MAX_SM2_ID_LENGTH, SDR_INARGERR);
    }

    size_t req_size = sizeof(sdfx_hash_init_req_t) + uiIDLength;
    req_buffer = (BYTE *)calloc(1, req_size);
    if (req_buffer == NULL) {
        return SDR_NOBUFFER;
    }
    
    /* Prepare request data */
    sdfx_hash_init_req_t *req = (sdfx_hash_init_req_t*)req_buffer;
    req->session_handle = sdfx_htonll(server_session_id);
    req->alg_id = sdfx_htonl(uiAlgID);
    req->id_length = sdfx_htonl(uiIDLength);
    
    /* Copy public key information (if provided) */
    if (pucPublicKey != NULL) {
        memcpy(&req->public_key, pucPublicKey, sizeof(ECCrefPublicKey));
    }
    
    if (uiIDLength > 0) {
        memcpy(req->id_data, pucID, uiIDLength);
    }
    
    ret = sdf_send_request(SDFX_CMD_HASH_INIT, req, req_size,
                           resp_buffer, sizeof(resp_buffer), &resp_len);
    free(req_buffer);
    if (ret != SDR_OK) {
        return ret;
    }
    
    resp_msg = (sdfx_message_t*)resp_buffer;
    return sdfx_ntohl(resp_msg->header.status);
}

LONG SDF_HashUpdate(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength)
{
    BYTE resp_buffer[256];
    size_t resp_len;
    sdfx_message_t *resp_msg;
    sdfx_remote_handle_t server_session_id;
    BYTE *req_buffer;
    LONG ret;

    SDF_CHECK_PARAM(hSessionHandle != NULL && pucData != NULL &&
                    uiDataLength > 0 &&
                    uiDataLength <= SDFX_MAX_BLOB_LENGTH, SDR_INARGERR);
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);

    size_t req_size = sizeof(sdfx_hash_update_req_t) + uiDataLength;
    req_buffer = (BYTE *)malloc(req_size);
    if (req_buffer == NULL) {
        return SDR_NOBUFFER;
    }

    sdfx_hash_update_req_t *req = (sdfx_hash_update_req_t *)req_buffer;
    req->session_handle = sdfx_htonll(server_session_id);
    req->data_length = sdfx_htonl(uiDataLength);
    memcpy(req->data, pucData, uiDataLength);

    ret = sdf_send_request(SDFX_CMD_HASH_UPDATE, req, req_size,
                           resp_buffer, sizeof(resp_buffer), &resp_len);
    free(req_buffer);
    if (ret != SDR_OK) {
        return ret;
    }

    resp_msg = (sdfx_message_t *)resp_buffer;
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
