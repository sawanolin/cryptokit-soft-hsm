/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file transport_tcp.c
 * @brief TCP Socket transport implementation - supports server and client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "transport_interface.h"
#include "protocol.h"
#include "log.h"
#include "sdfx_defaults.h"

/* Default configuration - using unified defaults */
#define DEFAULT_BACKLOG 10

/* Global status */
static int g_server_fd = -1;           /* Server listening socket */
static int g_client_fd = -1;           /* Client connection socket */
static char g_server_host[256] = {0};  /* Server address */
static int g_server_port = 0;          /* Server port */

/* Log macros - use unified logging system */
#define TCP_LOG_INFO(fmt, ...)  LOG_MODULE_INFO("TCP", fmt, ##__VA_ARGS__)
#define TCP_LOG_ERROR(fmt, ...) LOG_MODULE_ERROR("TCP", fmt, ##__VA_ARGS__)
#define TCP_LOG_DEBUG(fmt, ...) LOG_MODULE_DEBUG("TCP", fmt, ##__VA_ARGS__)

int transport_init_with_config(const transport_config_t *config)
{
    if (config == NULL) {
        TCP_LOG_ERROR("transport_init_with_config: NULL config");
        return -1;
    }
    
    /* Set host and port with bounds checking */
    const char *host = config->address ? config->address : SDFX_DEFAULT_TCP_HOST;
    strncpy(g_server_host, host, sizeof(g_server_host) - 1);
    g_server_host[sizeof(g_server_host) - 1] = '\0';  /* Ensure null termination */
    g_server_port = config->port ? config->port : SDFX_DEFAULT_TCP_PORT;
    
    TCP_LOG_INFO("initialized with host: %s, port: %d", g_server_host, g_server_port);
    return 0;
}

int transport_init(const transport_config_t *config)
{
    if (config == NULL) {
        TCP_LOG_ERROR("transport_init: NULL config");
        return -1;
    }
    
    /* Set port with bounds checking */
    g_server_port = config->port ? config->port : SDFX_DEFAULT_TCP_PORT;
    strncpy(g_server_host, SDFX_DEFAULT_TCP_HOST, sizeof(g_server_host) - 1);
    g_server_host[sizeof(g_server_host) - 1] = '\0';  /* Ensure null termination */
    
    TCP_LOG_INFO("initialized with port: %d", g_server_port);
    return 0;
}

int transport_listen(void)
{
    struct sockaddr_in addr;
    int opt = 1;
    
    const char *bind_host = strlen(g_server_host) > 0 ? g_server_host : "0.0.0.0";
    TCP_LOG_INFO("starting TCP server on %s:%d", bind_host, g_server_port);
    
    /* Create TCP socket */
    g_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_fd < 0) {
        TCP_LOG_ERROR("failed to create TCP socket: %s", strerror(errno));
        return -1;
    }
    
    /* Set socket option */
    setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    /* Bind TCP address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_server_port);
    
    if (strcmp(bind_host, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, bind_host, &addr.sin_addr) <= 0) {
        TCP_LOG_ERROR("invalid bind address: %s", bind_host);
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }
    
    if (bind(g_server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        TCP_LOG_ERROR("failed to bind TCP socket: %s", strerror(errno));
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }
    
    /* Start listening */
    if (listen(g_server_fd, DEFAULT_BACKLOG) < 0) {
        TCP_LOG_ERROR("failed to listen on TCP socket: %s", strerror(errno));
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }
    
    TCP_LOG_INFO("TCP server listening on %s:%d", bind_host, g_server_port);
    printf("[DAEMON] Daemon is now listening on TCP %s:%d\n", bind_host, g_server_port);
    fflush(stdout);
    
    return 0;
}

int transport_connect(const char *address)
{
    struct sockaddr_in addr;
    const char *host = "127.0.0.1";  /* Default connect to local */
    int port = g_server_port;
    
    /* Parse address: if address provided, try to parse host:port format */
    if (address) {
        char *colon = strchr(address, ':');
        if (colon) {
            /* host:port format */
            static char host_buf[256];
            int host_len = colon - address;
            if (host_len > 0 && host_len < sizeof(host_buf)) {
                strncpy(host_buf, address, host_len);
                host_buf[host_len] = '\0';
                host = host_buf;
                port = atoi(colon + 1);
            }
        } else {
            /* Only port number */
            port = atoi(address);
        }
    }
    
    TCP_LOG_INFO("connecting to TCP server: %s:%d", host, port);
    
    /* Create client socket */
    g_client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_client_fd < 0) {
        TCP_LOG_ERROR("failed to create client socket: %s", strerror(errno));
        return -1;
    }
    
    /* Set server address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        struct hostent *resolved = gethostbyname(host);
        if (resolved == NULL || resolved->h_addrtype != AF_INET ||
            resolved->h_length != sizeof(addr.sin_addr) ||
            resolved->h_addr_list == NULL || resolved->h_addr_list[0] == NULL) {
            TCP_LOG_ERROR("cannot resolve address: %s", host);
            close(g_client_fd);
            g_client_fd = -1;
            return -1;
        }
        memcpy(&addr.sin_addr, resolved->h_addr_list[0], sizeof(addr.sin_addr));
    }
    
    /* Connect to server */
    if (connect(g_client_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        TCP_LOG_ERROR("failed to connect to TCP server: %s", strerror(errno));
        close(g_client_fd);
        g_client_fd = -1;
        return -1;
    }
    
    TCP_LOG_INFO("connected to TCP server: %s:%d", host, port);
    return 0;
}

int transport_accept(transport_client_t *client)
{
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    if (client == NULL) {
        TCP_LOG_ERROR("transport_accept: NULL client");
        return -1;
    }
    
    if (g_server_fd < 0) {
        TCP_LOG_ERROR("transport_accept: server not initialized");
        return -1;
    }
    
    /* Accept client connection */
    client->fd = accept(g_server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client->fd < 0) {
        TCP_LOG_ERROR("accept failed: %s", strerror(errno));
        return -1;
    }
    
    /* Set client information */
    snprintf(client->client_info, sizeof(client->client_info), 
             "tcp_client_%s:%d_fd_%d", 
             inet_ntoa(client_addr.sin_addr), 
             ntohs(client_addr.sin_port), 
             client->fd);
    client->transport_data = NULL;
    
    TCP_LOG_INFO("new client connection: %s", client->client_info);
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
        TCP_LOG_ERROR("transport_send: invalid parameters");
        return -1;
    }
    
    if (client != NULL) {
        fd = client->fd;
    } else {
        fd = g_client_fd;
        if (fd < 0) {
            TCP_LOG_ERROR("transport_send: client not connected");
            return -1;
        }
    }

    while (total < len) {
        ssize_t ret = send(fd, cursor + total, len - total, MSG_NOSIGNAL);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            TCP_LOG_ERROR("send failed: %s", strerror(errno));
            return -1;
        }
        if (ret == 0) {
            TCP_LOG_ERROR("connection closed during send");
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
        TCP_LOG_ERROR("transport_recv: invalid parameters");
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
            TCP_LOG_ERROR("transport_recv: client not connected");
            return -1;
        }
    }
    
    ret = recv(fd, buffer, len, 0);
    if (ret < 0) {
        TCP_LOG_ERROR("recv failed: %s", strerror(errno));
    } else if (ret == 0) {
        TCP_LOG_DEBUG("connection closed");
    }
    
    return ret;
}

int transport_recv_message(const transport_client_t *client, void *buffer, 
                          size_t buffer_size, size_t *received_size)
{
    int fd;
    ssize_t ret;
    
    if (buffer == NULL || buffer_size == 0 || received_size == NULL) {
        TCP_LOG_ERROR("transport_recv_message: invalid parameters");
        return -1;
    }
    
    if (buffer_size < sizeof(sdfx_message_header_t)) {
        TCP_LOG_ERROR("transport_recv_message: buffer too small for header");
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
            TCP_LOG_ERROR("transport_recv_message: client not connected");
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
                TCP_LOG_DEBUG("connection closed during header receive");
            } else {
                TCP_LOG_ERROR("failed to receive header: %s", strerror(errno));
            }
            return ret == 0 && header_received == 0 ? 2 : -1;
        }
        header_received += ret;
    }
    
    /* Step 2: Parse header and validate message size */
    sdfx_message_t *msg = (sdfx_message_t *)buffer;
    
    /* Validate magic number */
    if (sdfx_ntohl(msg->header.magic) != SDFX_MAGIC) {
        TCP_LOG_ERROR("invalid magic number: 0x%lx", 
                     (unsigned long)sdfx_ntohl(msg->header.magic));
        return -1;
    }
    
    /* Get and validate data length */
    ULONG data_length = sdfx_ntohl(msg->header.length);
    size_t total_message_size = sizeof(sdfx_message_header_t) + data_length;
    
    /* Validate total message size */
    if (total_message_size > SDFX_MAX_MESSAGE_SIZE) {
        TCP_LOG_ERROR("message too large: %zu bytes (max: %d)", 
                     total_message_size, SDFX_MAX_MESSAGE_SIZE);
        return -1;
    }
    
    if (total_message_size > buffer_size) {
        TCP_LOG_ERROR("message size %zu exceeds buffer size %zu", 
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
                    TCP_LOG_DEBUG("connection closed during data receive");
                } else {
                    TCP_LOG_ERROR("failed to receive data: %s", strerror(errno));
                }
                return ret == 0 ? -1 : (int)ret;
            }
            total_received += ret;
        }
    }
    
    *received_size = total_received;
    TCP_LOG_DEBUG("securely received complete message: %zu bytes", total_received);
    
    return 0;
}

void transport_close_client(transport_client_t *client)
{
    if (client == NULL || client->fd < 0) {
        return;
    }
    
    TCP_LOG_DEBUG("closing client connection: %s", client->client_info);
    close(client->fd);
    client->fd = -1;
}

void transport_close(void)
{
    if (g_client_fd >= 0) {
        TCP_LOG_DEBUG("closing client connection");
        close(g_client_fd);
        g_client_fd = -1;
    }
}

void transport_cleanup(void)
{
    TCP_LOG_INFO("cleaning up TCP transport");
    
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
    
    if (g_client_fd >= 0) {
        close(g_client_fd);
        g_client_fd = -1;
    }
    
    TCP_LOG_INFO("cleanup completed");
}

const char* transport_get_type(void)
{
    return "TCP Socket";
}