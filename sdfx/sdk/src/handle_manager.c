/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file handle_manager.c
 * @brief Handle manager implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

#include "sdf.h"
#include "sdfx.h"

/* Handle type */
typedef enum {
    HANDLE_TYPE_DEVICE = 1,
    HANDLE_TYPE_SESSION = 2,
    HANDLE_TYPE_KEY = 3,
    HANDLE_TYPE_AGREEMENT = 4
} handle_type_t;

/* Handle information structure */
typedef struct handle_info {
    HANDLE handle;
    handle_type_t type;
    ULONG ref_count;
    void *private_data;
    struct handle_info *next;
} handle_info_t;

/* Global handle manager */
static handle_info_t *g_handle_list = NULL;
static pthread_mutex_t g_handle_mutex = PTHREAD_MUTEX_INITIALIZER;
static ULONG g_next_handle = 1;

/**
 * @brief Create a new handle
 */
HANDLE handle_manager_create(handle_type_t type, void *private_data)
{
    handle_info_t *info;
    HANDLE handle;
    
    info = (handle_info_t*)malloc(sizeof(handle_info_t));
    if (info == NULL) {
        return NULL;
    }
    
    pthread_mutex_lock(&g_handle_mutex);
    
    handle = (HANDLE)(uintptr_t)g_next_handle++;
    
    info->handle = handle;
    info->type = type;
    info->ref_count = 1;
    info->private_data = private_data;
    info->next = g_handle_list;
    g_handle_list = info;
    
    pthread_mutex_unlock(&g_handle_mutex);
    
    return handle;
}

/**
 * @brief Find handle information
 */
static handle_info_t* find_handle_info(HANDLE handle)
{
    handle_info_t *info = g_handle_list;
    
    while (info != NULL) {
        if (info->handle == handle) {
            return info;
        }
        info = info->next;
    }
    
    return NULL;
}

/**
 * @brief Validate a handle
 */
int handle_manager_validate(HANDLE handle, handle_type_t expected_type)
{
    handle_info_t *info;
    int ret = SDR_INVALID_HANDLE;
    
    if (handle == NULL) {
        return SDR_INARGERR;
    }
    
    pthread_mutex_lock(&g_handle_mutex);
    
    info = find_handle_info(handle);
    if (info != NULL && info->type == expected_type) {
        ret = SDR_OK;
    }
    
    pthread_mutex_unlock(&g_handle_mutex);
    
    return ret;
}

/**
 * @brief Get private data of a handle
 */
void* handle_manager_get_private_data(HANDLE handle)
{
    handle_info_t *info;
    void *data = NULL;
    
    if (handle == NULL) {
        return NULL;
    }
    
    pthread_mutex_lock(&g_handle_mutex);
    
    info = find_handle_info(handle);
    if (info != NULL) {
        data = info->private_data;
    }
    
    pthread_mutex_unlock(&g_handle_mutex);
    
    return data;
}

/**
 * @brief Destroy a handle
 */
int handle_manager_destroy(HANDLE handle)
{
    handle_info_t *info, *prev = NULL;
    int ret = SDR_INVALID_HANDLE;
    
    if (handle == NULL) {
        return SDR_INARGERR;
    }
    
    pthread_mutex_lock(&g_handle_mutex);
    
    info = g_handle_list;
    while (info != NULL) {
        if (info->handle == handle) {
            /* Remove from list */
            if (prev != NULL) {
                prev->next = info->next;
            } else {
                g_handle_list = info->next;
            }
            
            /* Free memory - for session handles, private_data is a pointer to the server session ID, which needs to be freed */
            if (info->private_data != NULL) {
                free(info->private_data);
            }
            free(info);
            
            ret = SDR_OK;
            break;
        }
        prev = info;
        info = info->next;
    }
    
    pthread_mutex_unlock(&g_handle_mutex);
    
    return ret;
}

/**
 * @brief Clean up all handles
 */
void handle_manager_cleanup(void)
{
    handle_info_t *info, *next;
    
    pthread_mutex_lock(&g_handle_mutex);
    
    info = g_handle_list;
    while (info != NULL) {
        next = info->next;
        
        if (info->private_data != NULL) {
            free(info->private_data);
        }
        free(info);
        
        info = next;
    }
    
    g_handle_list = NULL;
    g_next_handle = 1;
    
    pthread_mutex_unlock(&g_handle_mutex);
}

/**
 * @brief Create a device handle
 */
HANDLE handle_manager_create_device(void)
{
    return handle_manager_create(HANDLE_TYPE_DEVICE, NULL);
}

HANDLE handle_manager_create_device_with_data(void *device_data)
{
    return handle_manager_create(HANDLE_TYPE_DEVICE, device_data);
}

/**
 * @brief Create a session handle
 */
HANDLE handle_manager_create_session(HANDLE device_handle)
{
    /* Validate device handle */
    if (handle_manager_validate(device_handle, HANDLE_TYPE_DEVICE) != SDR_OK) {
        return NULL;
    }
    
    return handle_manager_create(HANDLE_TYPE_SESSION, device_handle);
}

/**
 * @brief Create a session handle and store the server session ID
 */
HANDLE handle_manager_create_session_with_data(HANDLE device_handle, void *session_data)
{
    /* Validate device handle */
    if (handle_manager_validate(device_handle, HANDLE_TYPE_DEVICE) != SDR_OK) {
        return NULL;
    }
    
    return handle_manager_create(HANDLE_TYPE_SESSION, session_data);
}

/**
 * @brief Validate a device handle
 */
int handle_manager_validate_device(HANDLE handle)
{
    return handle_manager_validate(handle, HANDLE_TYPE_DEVICE);
}

/**
 * @brief Validate a session handle
 */
int handle_manager_validate_session(HANDLE handle)
{
    return handle_manager_validate(handle, HANDLE_TYPE_SESSION);
}

HANDLE handle_manager_create_key_with_data(void *key_data)
{
    return handle_manager_create(HANDLE_TYPE_KEY, key_data);
}

int handle_manager_validate_key(HANDLE handle)
{
    return handle_manager_validate(handle, HANDLE_TYPE_KEY);
}

HANDLE handle_manager_create_agreement_with_data(void *agreement_data)
{
    return handle_manager_create(HANDLE_TYPE_AGREEMENT, agreement_data);
}

int handle_manager_validate_agreement(HANDLE handle)
{
    return handle_manager_validate(handle, HANDLE_TYPE_AGREEMENT);
}
