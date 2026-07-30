/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file transport_interface.h
 * @brief Unified transport layer interface definitions - compile-time transport selection
 */

#ifndef TRANSPORT_INTERFACE_H
#define TRANSPORT_INTERFACE_H

#include <stdint.h>
#include <stddef.h>
#ifdef _WIN32
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Transport layer configuration structure */
typedef struct {
    const char *address;    /* Address: Unix path or IP address */
    uint16_t port;         /* Port number (for TCP) */
    uint32_t permissions;  /* Permissions (for Unix Socket) */
    int timeout_ms;        /* Timeout in milliseconds */
    int backlog;           /* Listen queue length */
    void *user_data;       /* User-defined data (for custom transport) */
} transport_config_t;

/**
 * @brief Initialize transport layer with configuration
 * @param config Transport configuration
 * @return 0 for success, others for failure
 */
int transport_init_with_config(const transport_config_t *config);

/* Client connection information */
typedef struct {
    intptr_t fd;           /* Socket value or POSIX file descriptor */
    char client_info[256]; /* Client information string (for logging) */
    void *transport_data;  /* Transport layer private data */
} transport_client_t;

/**
 * Unified transport layer interface functions
 */

/**
 * Initialize transport layer
 * @param config Transport configuration
 * @return 0 for success, negative for failure
 */
int transport_init(const transport_config_t *config);

/**
 * Start listening for connections (server-side only)
 * @return 0 for success, negative for failure
 */
int transport_listen(void);

/**
 * Connect to the server (client-side only)
 * @param address Server address
 * @return 0 for success, negative for failure
 */
int transport_connect(const char *address);

/**
 * Accept a client connection (server-side only)
 * @param client Output for client connection information
 * @return 0 for success, negative for failure, positive indicates retry needed
 */
int transport_accept(transport_client_t *client);

/**
 * Send data
 * @param client Client connection (server use) or NULL (client use)
 * @param data The data to send
 * @param len The length of the data
 * @return Number of bytes sent, or a negative value on failure
 */
ssize_t transport_send(const transport_client_t *client, const void *data, size_t len);

/**
 * Receive data
 * @param client Client connection (server use) or NULL (client use)
 * @param buffer Receive buffer
 * @param len Buffer size
 * @return Number of bytes received, 0 for connection closed, negative for failure
 */
ssize_t transport_recv(const transport_client_t *client, void *buffer, size_t len);

/**
 * Securely receive a complete SDFX protocol message
 * This function first reads the message header to determine the message size,
 * then reads the complete message data with bounds checking.
 * @param client Client connection (server use) or NULL (client use)
 * @param buffer Receive buffer (must be at least SDFX_MAX_MESSAGE_SIZE bytes)
 * @param buffer_size Size of the receive buffer
 * @param received_size Output parameter for actual received message size
 * @return 0 for success, 2 for a clean EOF before a message, negative for failure
 */
int transport_recv_message(const transport_client_t *client, void *buffer, 
                          size_t buffer_size, size_t *received_size);

/**
 * Close a client connection
 * @param client The client connection
 */
void transport_close_client(transport_client_t *client);

/**
 * Close the connection (client-side)
 */
void transport_close(void);

/**
 * Cleanup transport layer resources
 */
void transport_cleanup(void);

/**
 * Get transport type name (for logging)
 * @return Transport type string
 */
const char* transport_get_type(void);

#ifdef __cplusplus
}
#endif

#endif /* TRANSPORT_INTERFACE_H */