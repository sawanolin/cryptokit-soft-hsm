/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file sdf_internal.h
 * @brief SDF SDK internal shared definitions and common functions
 */

#ifndef SDF_INTERNAL_H
#define SDF_INTERNAL_H

#include "sdf.h"
#include "sdfx.h"
#include "protocol.h"
#include "protocol_client.h"
#include "handle_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief General request sending function
 * @param cmd Command type
 * @param req_data Request data
 * @param req_size Request data size
 * @param resp_buffer Response buffer
 * @param resp_buffer_size Response buffer size
 * @param resp_len Actual response length
 * @return SDF error code
 */
LONG sdf_send_request(ULONG cmd, const void *req_data, size_t req_size, 
                      void *resp_buffer, size_t resp_buffer_size, size_t *resp_len);

/**
 * @brief Get the server-side session ID
 * @param hSessionHandle Local session handle
 * @param server_session_id Output for the server-side session ID
 * @return SDF error code
 */
LONG sdf_get_server_session_id(HANDLE hSessionHandle, sdfx_remote_handle_t *server_session_id);
LONG sdf_get_server_device_id(HANDLE hDeviceHandle, sdfx_remote_handle_t *server_device_id);
LONG sdf_get_server_key_id(HANDLE hKeyHandle, sdfx_remote_handle_t *server_key_id);

/**
 * @brief Validate session handle and get server session ID
 * @param hSessionHandle Local session handle
 * @param server_session_id Output for the server-side session ID
 * @return SDF error code
 */
LONG sdf_validate_session_and_get_id(HANDLE hSessionHandle, sdfx_remote_handle_t *server_session_id);

/**
 * @brief Module initialization function type
 * @return SDF error code
 */
typedef LONG (*sdf_module_init_func_t)(void);

/**
 * @brief Module cleanup function type
 */
typedef void (*sdf_module_cleanup_func_t)(void);

/**
 * @brief SDF module description structure
 */
typedef struct {
    const char *module_name;
    sdf_module_init_func_t init_func;
    sdf_module_cleanup_func_t cleanup_func;
} sdf_module_t;

/* Module initialization and cleanup function declarations */
LONG sdf_device_init(void);
void sdf_device_cleanup(void);

LONG sdf_random_init(void);
void sdf_random_cleanup(void);

LONG sdf_hash_init(void);
void sdf_hash_cleanup(void);

LONG sdf_symmetric_init(void);
void sdf_symmetric_cleanup(void);

LONG sdf_asymmetric_init(void);
void sdf_asymmetric_cleanup(void);

/* Common macro definitions */
#define SDF_CHECK_PARAM(cond, retval) \
    do { if (!(cond)) return (retval); } while(0)

#define SDF_CHECK_SESSION(handle, server_id) \
    do { \
        LONG ret = sdf_validate_session_and_get_id((handle), &(server_id)); \
        if (ret != SDR_OK) return ret; \
    } while(0)

/* Device management function declarations */
LONG sdf_device_open(HANDLE *phDeviceHandle);
LONG sdf_device_close(HANDLE hDeviceHandle);
LONG sdf_device_open_session(HANDLE hDeviceHandle, HANDLE *phSessionHandle);
LONG sdf_device_close_session(HANDLE hSessionHandle);
LONG sdf_device_get_info(HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo);

#endif /* SDF_INTERNAL_H */