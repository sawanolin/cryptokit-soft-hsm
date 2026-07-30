/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file sdf_random.c
 * @brief SDF random number generation module
 */

#include "sdf_internal.h"

/* Module initialization */
LONG sdf_random_init(void)
{
    return SDR_OK;
}

/* Module cleanup */
void sdf_random_cleanup(void)
{
    /* Clean up random number generation related resources */
}

LONG SDF_GenerateRandom(HANDLE hSessionHandle, ULONG uiLength, BYTE *pucRandom)
{
    sdfx_generate_random_req_t req;
    BYTE resp_buffer[8192];  // Enlarged buffer to support 4096-byte random number + message header
    size_t resp_len;
    sdfx_message_t *resp_msg;
    sdfx_remote_handle_t server_session_id;
    LONG ret;
    
    SDF_CHECK_PARAM(hSessionHandle != NULL && pucRandom != NULL && uiLength > 0, SDR_INARGERR);
    
    /* Check length limit */
    if (uiLength > SDFX_MAX_RANDOM_LENGTH) {
        return SDR_INARGERR;
    }
    
    /* Validate session handle and get server session ID */
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);
    
    /* Prepare request */
    req.session_handle = sdfx_htonll(server_session_id);
    req.length = sdfx_htonl(uiLength);
    
    /* Send request and receive response */
    ret = sdf_send_request(SDFX_CMD_GENERATE_RANDOM, &req, sizeof(req),
                          resp_buffer, sizeof(resp_buffer), &resp_len);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Parse response */
    resp_msg = (sdfx_message_t*)resp_buffer;
    if (resp_msg->header.length < sizeof(sdfx_generate_random_resp_t)) {
        return SDR_PROTOCOL_ERROR;
    }
    
    sdfx_generate_random_resp_t *resp = (sdfx_generate_random_resp_t*)resp_msg->data;
    ULONG returned_length = sdfx_ntohl(resp->length);
    
    if (returned_length != uiLength) {
        return SDR_PROTOCOL_ERROR;
    }
    
    /* Copy random number data */
    memcpy(pucRandom, resp->random_data, uiLength);
    
    return SDR_OK;
}