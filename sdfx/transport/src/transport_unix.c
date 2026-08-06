/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file transport_unix.c
 * @brief Unix Domain Socket transport implementation - supports server and client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "transport_interface.h"
#include "protocol.h"
#include "config.h"
#include "log.h"

/* Default configuration */
#define DEFAULT_UNIX_SOCKET_PATH "/tmp/sdfxd.sock"
#define DEFAULT_BACKLOG 10

/* Use log macros with module prefix */
#define UNIX_LOG_INFO(fmt, ...)  LOG_MODULE_INFO("Unix Transport", fmt, ##__VA_ARGS__)
#define UNIX_LOG_ERROR(fmt, ...) LOG_MODULE_ERROR("Unix Transport", fmt, ##__VA_ARGS__)
#define UNIX_LOG_DEBUG(fmt, ...) LOG_MODULE_DEBUG("Unix Transport", fmt, ##__VA_ARGS__)

/* Global status */
static int g_server_fd = -1;           /* Server listening socket */
static int g_client_fd = -1;           /* Client connection socket */
static char g_socket_path[256] = {0};   /* Socket path */

int transport_init(const transport_config_t *config)
{
    if (config == NULL) {
        UNIX_LOG_ERROR("transport_init: NULL config");
        return -1;
    }
    
    /* Set socket path with bounds checking */
    const char *socket_path = config->address ? config->address : DEFAULT_UNIX_SOCKET_PATH;
    strncpy(g_socket_path, socket_path, sizeof(g_socket_path) - 1);
    g_socket_path[sizeof(g_socket_path) - 1] = '\0';  /* Ensure null termination */
    
    UNIX_LOG_INFO("initialized with socket path: %s", g_socket_path);
    return 0;
}

int transport_listen(void)
{
    struct sockaddr_un addr;
    int opt = 1;
    
    UNIX_LOG_INFO("starting Unix domain socket server on '%s'", g_socket_path);
    
    /* Create Unix socket */
    g_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_server_fd < 0) {
        UNIX_LOG_ERROR("failed to create Unix socket: %s", strerror(errno));
        return -1;
    }
    
    /* Set socket option */
    setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    /* Delete possibly existing old socket file */
    unlink(g_socket_path);
    
    /* Bind Unix socket address with bounds checking */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_socket_path, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';  /* Ensure null termination */
    
    if (bind(g_server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        UNIX_LOG_ERROR("failed to bind Unix socket: %s", strerror(errno));
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }
    
    /* Set socket file permissions */
    chmod(g_socket_path, 0666);
    
    /* Start listening */
    if (listen(g_server_fd, DEFAULT_BACKLOG) < 0) {
        UNIX_LOG_ERROR("failed to listen on Unix socket: %s", strerror(errno));
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }
    
    UNIX_LOG_INFO("Unix domain socket server listening on '%s'", g_socket_path);
    printf("[DAEMON] Daemon is now listening on Unix socket %s\n", g_socket_path);
    fflush(stdout);
    
    return 0;
}

int transport_connect(const char *address)
{
    struct sockaddr_un addr;
    const char *socket_path = address ? address : g_socket_path;
    
    UNIX_LOG_INFO("connecting to Unix socket: %s", socket_path);
    
    /* Create client socket */
    g_client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_client_fd < 0) {
        UNIX_LOG_ERROR("failed to create client socket: %s", strerror(errno));
        return -1;
    }
    
    /* Set server address with bounds checking */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';  /* Ensure null termination */
    
    /* Connect to server */
    if (connect(g_client_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        UNIX_LOG_ERROR("failed to connect to Unix socket: %s", strerror(errno));
        close(g_client_fd);
        g_client_fd = -1;
        return -1;
    }
    
    UNIX_LOG_INFO("connected to Unix socket: %s", socket_path);
    return 0;
}

int transport_accept(transport_client_t *client)
{
    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    if (client == NULL) {
        UNIX_LOG_ERROR("transport_accept: NULL client");
        return -1;
    }
    
    if (g_server_fd < 0) {
        UNIX_LOG_ERROR("transport_accept: server not initialized");
        return -1;
    }
    
    /* Accept client connection */
    client->fd = accept(g_server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client->fd < 0) {
        UNIX_LOG_ERROR("accept failed: %s", strerror(errno));
        return -1;
    }
    
    /* Set client information */
    snprintf(client->client_info, sizeof(client->client_info), 
             "unix_client_fd_%d", client->fd);
    client->transport_data = NULL;
    
    UNIX_LOG_INFO("new client connection: %s", client->client_info);
    printf("[DAEMON] New client connection: %s\n", client->client_info);
    fflush(stdout);
    
    return 0;
}

ssize_t transport_send(const transport_client_t *client, const void *data, size_t len)
{
    int fd;
    const char *cursor = (const char *)data;
    size_t total = 0;
    
    if (data == NULL || len == 0) {
        UNIX_LOG_ERROR("transport_send: invalid parameters");
        return -1;
    }
    
    if (client != NULL) {
        fd = client->fd;
    } else {
        fd = g_client_fd;
        if (fd < 0) {
            UNIX_LOG_ERROR("transport_send: client not connected");
            return -1;
        }
    }

    while (total < len) {
        ssize_t ret = send(fd, cursor + total, len - total, MSG_NOSIGNAL);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            UNIX_LOG_ERROR("send failed: %s", strerror(errno));
            return -1;
        }
        if (ret == 0) {
            UNIX_LOG_ERROR("connection closed during send");
            return -1;
        }
        total += (size_t)ret;
    }

    return (ssize_t)total;
}

ssize_t transport_recv(const transport_client_t *client, void *buffer, size_t len)
{
    int fd;
    ssize_t ret;
    
    if (buffer == NULL || len == 0) {
        UNIX_LOG_ERROR("transport_recv: invalid parameters");
        return -1;
    }
    
    /* Determine server or client mode based on client parameter */
    if (client != NULL) {
        /* Server mode: receive from specified client */
        fd = client->fd;
    } else {
        /* Client mode: receive from server */
        fd = g_client_fd;
        if (fd < 0) {
            UNIX_LOG_ERROR("transport_recv: client not connected");
            return -1;
        }
    }
    
    ret = recv(fd, buffer, len, 0);
    if (ret < 0) {
        UNIX_LOG_ERROR("recv failed: %s", strerror(errno));
    } else if (ret == 0) {

    }
    
    return ret;
}

int transport_recv_message(const transport_client_t *client, void *buffer, 
                          size_t buffer_size, size_t *received_size)
{
    int fd;
    ssize_t ret;
    
    if (buffer == NULL || buffer_size == 0 || received_size == NULL) {
        UNIX_LOG_ERROR("transport_recv_message: invalid parameters");
        return -1;
    }
    
    if (buffer_size < sizeof(sdfx_message_header_t)) {
        UNIX_LOG_ERROR("transport_recv_message: buffer too small for header");
        return -1;
    }
    
    /* Determine server or client mode based on client parameter */
    if (client != NULL) {
        /* Server mode: receive from specified client */
        fd = client->fd;
    } else {
        /* Client mode: receive from server */
        fd = g_client_fd;
        if (fd < 0) {
            UNIX_LOG_ERROR("transport_recv_message: client not connected");
            return -1;
        }
    }
    
    /* Step 1: Receive message header first */
    ssize_t header_received = 0;
    char *buf_ptr = (char *)buffer;
    
    while (header_received < sizeof(sdfx_message_header_t)) {
        ret = recv(fd, buf_ptr + header_received, 
                  sizeof(sdfx_message_header_t) - header_received, 0);
        if (ret <= 0) {
            if (ret == 0) {

            } else {
                UNIX_LOG_ERROR("failed to receive header: %s", strerror(errno));
            }
            return ret == 0 && header_received == 0 ? 2 : -1;
        }
        header_received += ret;
    }
    
    /* Step 2: Parse header and validate message size */
    sdfx_message_t *msg = (sdfx_message_t *)buffer;
    
    /* Validate magic number */
    if (sdfx_ntohl(msg->header.magic) != SDFX_MAGIC) {
        UNIX_LOG_ERROR("invalid magic number: 0x%lx", 
                      (unsigned long)sdfx_ntohl(msg->header.magic));
        return -1;
    }
    
    /* Get and validate data length */
    ULONG data_length = sdfx_ntohl(msg->header.length);
    size_t total_message_size = sizeof(sdfx_message_header_t) + data_length;
    
    /* Validate total message size */
    if (total_message_size > SDFX_MAX_MESSAGE_SIZE) {
        UNIX_LOG_ERROR("message too large: %zu bytes (max: %d)", 
                      total_message_size, SDFX_MAX_MESSAGE_SIZE);
        return -1;
    }
    
    if (total_message_size > buffer_size) {
        UNIX_LOG_ERROR("message size %zu exceeds buffer size %zu", 
                      total_message_size, buffer_size);
        return -1;
    }
    
    /* Step 3: Receive remaining data if any */
    size_t total_received = header_received;
    
    if (data_length > 0) {
        while (total_received < total_message_size) {
            ret = recv(fd, buf_ptr + total_received, 
                      total_message_size - total_received, 0);
            if (ret <= 0) {
                if (ret == 0) {

                } else {
                    UNIX_LOG_ERROR("failed to receive data: %s", strerror(errno));
                }
                return ret == 0 ? -1 : (int)ret;
            }
            total_received += ret;
        }
    }
    
    *received_size = total_received;

    
    return 0;
}

void transport_close_client(transport_client_t *client)
{
    if (client == NULL || client->fd < 0) {
        return;
    }

    close(client->fd);
    client->fd = -1;
}

void transport_close(void)
{
    if (g_client_fd >= 0) {

        close(g_client_fd);
        g_client_fd = -1;
    }
}

void transport_cleanup(void)
{
    UNIX_LOG_INFO("cleaning up Unix transport");
    
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
    
    if (g_client_fd >= 0) {
        close(g_client_fd);
        g_client_fd = -1;
    }
    
    /* Delete socket file */
    if (strlen(g_socket_path) > 0) {
        unlink(g_socket_path);
    }
    
    UNIX_LOG_INFO("cleanup completed");
}

const char* transport_get_type(void)
{
    return "Unix Domain Socket";
}