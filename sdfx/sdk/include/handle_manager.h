/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file handle_manager.h
 * @brief Handle manager interface definition
 */

#ifndef HANDLE_MANAGER_H
#define HANDLE_MANAGER_H

#include "sdf_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a device handle
 * @return Device handle, or NULL on failure
 */
HANDLE handle_manager_create_device(void);
HANDLE handle_manager_create_device_with_data(void *device_data);
HANDLE handle_manager_create_key_with_data(void *key_data);
int handle_manager_validate_key(HANDLE handle);

/**
 * @brief Create a session handle
 * @param device_handle The device handle
 * @return Session handle, or NULL on failure
 */
HANDLE handle_manager_create_session(HANDLE device_handle);

/**
 * @brief Create a session handle and store server-side session data
 * @param device_handle The device handle
 * @param session_data The server-side session data
 * @return Session handle, or NULL on failure
 */
HANDLE handle_manager_create_session_with_data(HANDLE device_handle, void *session_data);

/**
 * @brief Validate a device handle
 * @param handle The device handle
 * @return SDR_OK on success, or an error code on failure
 */
int handle_manager_validate_device(HANDLE handle);

/**
 * @brief Validate a session handle
 * @param handle The session handle
 * @return SDR_OK on success, or an error code on failure
 */
int handle_manager_validate_session(HANDLE handle);

/**
 * @brief Get the private data associated with a handle
 * @param handle The handle
 * @return Pointer to the private data
 */
void* handle_manager_get_private_data(HANDLE handle);

/**
 * @brief Destroy a handle
 * @param handle The handle to destroy
 * @return SDR_OK on success, or an error code on failure
 */
int handle_manager_destroy(HANDLE handle);

/**
 * @brief Clean up all handles
 */
void handle_manager_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* HANDLE_MANAGER_H */