/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file transport.h
 * @brief SDFX transport layer abstract interface definitions
 */

#ifndef SDFX_TRANSPORT_H
#define SDFX_TRANSPORT_H

#include "sdf_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Transport layer configuration structure */
typedef struct transport_config {
    const char *address;        /* Connection address */
    int port;                   /* Port number (for TCP) */
    int timeout_ms;             /* Timeout in milliseconds */
    int buffer_size;            /* buffer size */
} transport_config_t;

/* Transport layer handle */
typedef struct transport_handle {
    int fd;                     /* File descriptor */
    transport_config_t config;  /* Configuration information */
    void *private_data;         /* Private data */
} transport_handle_t;

/* Transport layer operations interface */
typedef struct transport_ops {
    /**
     * @brief Initialize transport layer
     * @param config Configuration information
     * @return 0 for success, others for failure
     */
    int (*init)(transport_config_t *config);
    
    /**
     * @brief Connect to the server
     * @param handle Transport layer handle
     * @param address Server address
     * @return 0 for success, others for failure
     */
    int (*connect)(transport_handle_t *handle, const char *address);
    
    /**
     * @brief Send data
     * @param handle Transport layer handle
     * @param data Data buffer
     * @param len Data length
     * @return Actual number of bytes sent, -1 on failure
     */
    ssize_t (*send)(transport_handle_t *handle, const void *data, size_t len);
    
    /**
     * @brief Receive data
     * @param handle Transport layer handle
     * @param data Data buffer
     * @param len buffer size
     * @param recv_len Actual received length
     * @return 0 for success, others for failure
     */
    int (*recv)(transport_handle_t *handle, void *data, size_t len, size_t *recv_len);
    
    /**
     * @brief Close the connection
     * @param handle Transport layer handle
     * @return 0 for success, others for failure
     */
    int (*close)(transport_handle_t *handle);
    
    /**
     * @brief Cleanup transport layer
     */
    void (*cleanup)(void);
} transport_ops_t;

/**
 * @brief Get current transport layer operations interface
 * @return Pointer to the transport layer operations interface
 */
transport_ops_t* transport_get_ops(void);

/**
 * @brief Register transport layer operations interface
 * @param ops Transport layer operations interface
 * @return 0 for success, others for failure
 */
int transport_register_ops(transport_ops_t *ops);

/**
 * @brief Initialize transport layer manager
 * @return 0 for success, others for failure
 */
int transport_manager_init(void);

/**
 * @brief Cleanup transport layer manager
 */
void transport_manager_cleanup(void);

/**
 * @brief Initialize transport layer
 * @param config Configuration information
 * @return 0 for success, others for failure
 */
int transport_init(transport_config_t *config);

/**
 * @brief Connect to the server
 * @param handle Transport layer handle
 * @param address Server address
 * @return 0 for success, others for failure
 */
int transport_connect(transport_handle_t *handle, const char *address);

/**
 * @brief Send data
 * @param handle Transport layer handle
 * @param data Data buffer
 * @param len Data length
 * @return Actual number of bytes sent, -1 on failure
 */
ssize_t transport_send(transport_handle_t *handle, const void *data, size_t len);

/**
 * @brief Receive data
 * @param handle Transport layer handle
 * @param data Data buffer
 * @param len buffer size
 * @param recv_len Actual received length
 * @return 0 for success, others for failure
 */
int transport_recv(transport_handle_t *handle, void *data, size_t len, size_t *recv_len);

/**
 * @brief Close the connection
 * @param handle Transport layer handle
 * @return 0 for success, others for failure
 */
int transport_close(transport_handle_t *handle);

/**
 * @brief Cleanup transport layer
 */
void transport_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* SDFX_TRANSPORT_H */