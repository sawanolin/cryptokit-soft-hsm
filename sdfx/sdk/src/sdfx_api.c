/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file sdfx_api.c
 * @brief SDF API main entry file - Library initialization and module coordination
 */

#include "sdf_internal.h"
#include <time.h>

/* Initialization flag */
static int g_sdf_initialized = 0;

/* Module registration table */
static sdf_module_t g_sdf_modules[] = {
    {"device", sdf_device_init, sdf_device_cleanup},
    {"random", sdf_random_init, sdf_random_cleanup},
    {"hash", sdf_hash_init, sdf_hash_cleanup},
    {"symmetric", sdf_symmetric_init, sdf_symmetric_cleanup},
    {"asymmetric", sdf_asymmetric_init, sdf_asymmetric_cleanup},
    {NULL, NULL, NULL}
};

/**
 * @brief Initialize SDF library
 */
static LONG sdf_init_once(void)
{
    if (g_sdf_initialized) {
        return SDR_OK;
    }
    
    /* Initialize random number seed */
    srand(time(NULL));
    
    /* Initialize client protocol */
    LONG ret = protocol_client_init();
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Initialize each module */
    for (int i = 0; g_sdf_modules[i].module_name != NULL; i++) {
        if (g_sdf_modules[i].init_func != NULL) {
            ret = g_sdf_modules[i].init_func();
            if (ret != SDR_OK) {
                /* Cleanup already initialized modules */
                for (int j = i - 1; j >= 0; j--) {
                    if (g_sdf_modules[j].cleanup_func != NULL) {
                        g_sdf_modules[j].cleanup_func();
                    }
                }
                return ret;
            }
        }
    }
    
    g_sdf_initialized = 1;
    return SDR_OK;
}

/**
 * @brief Cleanup SDF library
 */
void sdf_cleanup(void)
{
    if (!g_sdf_initialized) {
        return;
    }
    
    /* Cleanup each module */
    for (int i = 0; g_sdf_modules[i].module_name != NULL; i++) {
        if (g_sdf_modules[i].cleanup_func != NULL) {
            g_sdf_modules[i].cleanup_func();
        }
    }
    
    /* Cleanup client protocol */
    protocol_client_cleanup();
    
    g_sdf_initialized = 0;
}

/* =========================== General Helper Functions =========================== */

LONG sdf_send_request(ULONG cmd, const void *req_data, size_t req_size, 
                      void *resp_buffer, size_t resp_buffer_size, size_t *resp_len)
{
    sdfx_message_t *req_msg;
    ULONG msg_len;
    LONG ret;
    
    /* Ensure library is initialized */
    ret = sdf_init_once();
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Create request message */
    req_msg = sdfx_message_create(cmd, 0, req_data, req_size, &msg_len);
    if (req_msg == NULL) {
        return SDR_MEMORY_ERROR;
    }
    
    /* Send request and receive response */
    ret = protocol_client_send_recv(req_msg, msg_len, 
                                   resp_buffer, resp_buffer_size, resp_len);
    
    /* Cleanup request message */
    sdfx_message_destroy(req_msg);

    if (ret != SDR_OK) {
        return ret;
    }
    if (resp_len == NULL || *resp_len < sizeof(sdfx_message_header_t)) {
        return SDR_PROTOCOL_ERROR;
    }

    sdfx_message_t *resp_msg = (sdfx_message_t *)resp_buffer;
    if (sdfx_message_validate_header(&resp_msg->header) != SDR_OK ||
        resp_msg->header.cmd != cmd ||
        *resp_len != sizeof(sdfx_message_header_t) + resp_msg->header.length) {
        return SDR_PROTOCOL_ERROR;
    }

    return (LONG)resp_msg->header.status;
}

LONG sdf_get_server_session_id(HANDLE hSessionHandle, sdfx_remote_handle_t *server_session_id)
{
    sdfx_remote_handle_t *session_data = (sdfx_remote_handle_t*)handle_manager_get_private_data(hSessionHandle);
    if (session_data == NULL) {
        return SDR_INVALID_HANDLE;
    }
    
    *server_session_id = *session_data;
    return SDR_OK;
}

LONG sdf_get_server_device_id(HANDLE hDeviceHandle, sdfx_remote_handle_t *server_device_id)
{
    if (server_device_id == NULL || handle_manager_validate_device(hDeviceHandle) != SDR_OK) {
        return SDR_INVALID_HANDLE;
    }
    sdfx_remote_handle_t *device_data =
        (sdfx_remote_handle_t *)handle_manager_get_private_data(hDeviceHandle);
    if (device_data == NULL) {
        return SDR_INVALID_HANDLE;
    }
    *server_device_id = *device_data;
    return SDR_OK;
}

LONG sdf_get_server_agreement_id(HANDLE hAgreementHandle,
                                 sdfx_remote_handle_t *server_agreement_id)
{
    if (server_agreement_id == NULL ||
        handle_manager_validate_agreement(hAgreementHandle) != SDR_OK) {
        return SDR_INVALID_HANDLE;
    }
    sdfx_remote_handle_t *data =
        (sdfx_remote_handle_t *)handle_manager_get_private_data(hAgreementHandle);
    if (data == NULL) {
        return SDR_INVALID_HANDLE;
    }
    *server_agreement_id = *data;
    return SDR_OK;
}

LONG sdf_get_server_key_id(HANDLE hKeyHandle, sdfx_remote_handle_t *server_key_id)
{
    if (server_key_id == NULL || handle_manager_validate_key(hKeyHandle) != SDR_OK) {
        return SDR_INVALID_HANDLE;
    }
    sdfx_remote_handle_t *key_data =
        (sdfx_remote_handle_t *)handle_manager_get_private_data(hKeyHandle);
    if (key_data == NULL) {
        return SDR_INVALID_HANDLE;
    }
    *server_key_id = *key_data;
    return SDR_OK;
}

LONG sdf_validate_session_and_get_id(HANDLE hSessionHandle,
                                    sdfx_remote_handle_t *server_session_id)
{
    LONG ret;
    
    /* Validate session handle */
    ret = handle_manager_validate_session(hSessionHandle);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Get server session ID */
    return sdf_get_server_session_id(hSessionHandle, server_session_id);
}

/* =========================== Library Management API =========================== */

/**
 * @brief Initialize SDF library (Public Interface)
 * @return SDF error code
 */
LONG SDF_InitLibrary(void)
{
    return sdf_init_once();
}

/**
 * @brief Cleanup SDF library (Public Interface)
 */
void SDF_FinalizeLibrary(void)
{
    sdf_cleanup();
}

/**
 * @brief Get library version information
 * @param pstVersion Version information structure pointer
 * @return SDF error code
 */
LONG SDF_GetVersion(VERSION *pstVersion)
{
    if (pstVersion == NULL) {
        return SDR_INARGERR;
    }
    
    /* Set version information */
    pstVersion->major = 1;
    pstVersion->minor = 0;
    pstVersion->patch = 0;
    strncpy((char*)pstVersion->desc, "SDFX Pure Software SDF Implementation", 
            sizeof(pstVersion->desc) - 1);
    pstVersion->desc[sizeof(pstVersion->desc) - 1] = '\0';
    
    return SDR_OK;
}


/* =========================== API Implementation =========================== */

/* Note: Individual SDF API functions are implemented in their respective modules:
 * - Device management: sdf_device.c
 * - Random generation: sdf_random.c  
 * - Hash operations: sdf_hash.c
 * - Symmetric encryption: sdf_symmetric.c
 * - Asymmetric cryptography: sdf_asymmetric.c
 */