/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file sdf_device.c
 * @brief SDF device and session management module
 */

#include "sdf_internal.h"

/* Module initialization */
LONG sdf_device_init(void)
{
    return SDR_OK;
}

/* Module cleanup */
void sdf_device_cleanup(void)
{
    /* Clean up device management related resources */
}

LONG SDF_OpenDevice(HANDLE *phDeviceHandle)
{
    sdfx_open_device_req_t req;
    BYTE resp_buffer[1024];
    size_t resp_len;
    sdfx_message_t *resp_msg;
    LONG ret;
    
    SDF_CHECK_PARAM(phDeviceHandle != NULL, SDR_INARGERR);
    
    /* Prepare request */
    memset(&req, 0, sizeof(req));
    req.device_type = 1;  /* Software device */
    
    /* Send request and receive response */
    ret = sdf_send_request(SDFX_CMD_OPEN_DEVICE, &req, sizeof(req),
                          resp_buffer, sizeof(resp_buffer), &resp_len);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Parse response */
    resp_msg = (sdfx_message_t*)resp_buffer;
    if (resp_msg->header.length >= sizeof(sdfx_open_device_resp_t)) {
        sdfx_open_device_resp_t *resp = (sdfx_open_device_resp_t*)resp_msg->data;
        
        sdfx_remote_handle_t *server_device_id = malloc(sizeof(*server_device_id));
        if (server_device_id == NULL) {
            return SDR_MEMORY_ERROR;
        }
        *server_device_id = sdfx_ntohll(resp->device_handle);
        *phDeviceHandle = handle_manager_create_device_with_data(server_device_id);
        if (*phDeviceHandle == NULL) {
            free(server_device_id);
            return SDR_MEMORY_ERROR;
        }
        
        return SDR_OK;
    }
    
    return SDR_PROTOCOL_ERROR;
}

LONG SDF_CloseDevice(HANDLE hDeviceHandle)
{
    sdfx_close_device_req_t req;
    BYTE resp_buffer[1024];
    size_t resp_len;
    LONG ret;
    
    /* Validate handle */
    ret = handle_manager_validate_device(hDeviceHandle);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Prepare request */
    sdfx_remote_handle_t server_device_id;
    ret = sdf_get_server_device_id(hDeviceHandle, &server_device_id);
    if (ret != SDR_OK) {
        return ret;
    }

    req.device_handle = sdfx_htonll(server_device_id);
    
    /* Send request and receive response */
    ret = sdf_send_request(SDFX_CMD_CLOSE_DEVICE, &req, sizeof(req),
                          resp_buffer, sizeof(resp_buffer), &resp_len);
    
    /* Destroy local handle */
    handle_manager_destroy(hDeviceHandle);
    
    return ret;
}

LONG SDF_OpenSession(HANDLE hDeviceHandle, HANDLE *phSessionHandle)
{
    sdfx_open_session_req_t req;
    BYTE resp_buffer[1024];
    size_t resp_len;
    sdfx_message_t *resp_msg;
    LONG ret;
    
    SDF_CHECK_PARAM(hDeviceHandle != NULL && phSessionHandle != NULL, SDR_INARGERR);
    
    /* Validate device handle */
    sdfx_remote_handle_t server_device_id;
    ret = sdf_get_server_device_id(hDeviceHandle, &server_device_id);
    if (ret != SDR_OK) {
        return ret;
    }

    ret = handle_manager_validate_device(hDeviceHandle);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Prepare request */
    req.device_handle = sdfx_htonll(server_device_id);
    
    /* Send request and receive response */
    ret = sdf_send_request(SDFX_CMD_OPEN_SESSION, &req, sizeof(req),
                          resp_buffer, sizeof(resp_buffer), &resp_len);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Parse response */
    resp_msg = (sdfx_message_t*)resp_buffer;
    if (resp_msg->header.length >= sizeof(sdfx_open_session_resp_t)) {
        sdfx_open_session_resp_t *resp = (sdfx_open_session_resp_t*)resp_msg->data;
        
        /* Allocate memory for storing server session ID */
        sdfx_remote_handle_t *server_session_id = malloc(sizeof(*server_session_id));
        if (server_session_id == NULL) {
            return SDR_MEMORY_ERROR;
        }
        *server_session_id = sdfx_ntohll(resp->session_handle);
        
        /* Create local session handle, storing server session ID */
        *phSessionHandle = handle_manager_create_session_with_data(hDeviceHandle, server_session_id);
        if (*phSessionHandle == NULL) {
            free(server_session_id);
            return SDR_MEMORY_ERROR;
        }
        
        return SDR_OK;
    }
    
    return SDR_PROTOCOL_ERROR;
}

LONG SDF_CloseSession(HANDLE hSessionHandle)
{
    sdfx_close_session_req_t req;
    BYTE resp_buffer[1024];
    size_t resp_len;
    sdfx_remote_handle_t server_session_id;
    LONG ret;
    
    SDF_CHECK_PARAM(hSessionHandle != NULL, SDR_INARGERR);
    
    /* Validate session handle and get server session ID */
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);
    
    /* Prepare request */
    req.session_handle = sdfx_htonll(server_session_id);
    
    /* Send request and receive response */
    ret = sdf_send_request(SDFX_CMD_CLOSE_SESSION, &req, sizeof(req),
                          resp_buffer, sizeof(resp_buffer), &resp_len);
    
    /* Destroy local handle */
    handle_manager_destroy(hSessionHandle);
    
    return ret;
}

LONG SDF_GetDeviceInfo(HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo)
{
    sdfx_get_device_info_req_t req;
    BYTE resp_buffer[1024];
    size_t resp_len;
    sdfx_message_t *resp_msg;
    sdfx_remote_handle_t server_session_id;
    LONG ret;
    
    SDF_CHECK_PARAM(hSessionHandle != NULL && pstDeviceInfo != NULL, SDR_INARGERR);
    
    /* Validate session handle and get server session ID */
    SDF_CHECK_SESSION(hSessionHandle, server_session_id);
    
    /* Prepare request */
    req.session_handle = sdfx_htonll(server_session_id);
    
    /* Send request and receive response */
    ret = sdf_send_request(SDFX_CMD_GET_DEVICE_INFO, &req, sizeof(req),
                          resp_buffer, sizeof(resp_buffer), &resp_len);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Parse response */
    resp_msg = (sdfx_message_t*)resp_buffer;
    if (resp_msg->header.length >= sizeof(sdfx_get_device_info_resp_t)) {
        sdfx_get_device_info_resp_t *resp = (sdfx_get_device_info_resp_t*)resp_msg->data;
        
        /* Copy device information */
        memcpy(pstDeviceInfo, &resp->device_info, sizeof(DEVICEINFO));
        
        return SDR_OK;
    }
    
    return SDR_PROTOCOL_ERROR;
}