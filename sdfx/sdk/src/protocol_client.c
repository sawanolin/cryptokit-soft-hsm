/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file protocol_client.c
 * @brief Protocol client implementation - using unified transport interface
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "sdf.h"
#include "sdfx.h"
#include "transport_interface.h"
#include "protocol.h"
#include "config.h"

static pthread_mutex_t g_transport_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_client_initialized = 0;

static int protocol_recv_all(BYTE *buffer, size_t length)
{
    size_t total = 0;
    while (total < length) {
        ssize_t received = transport_recv(NULL, buffer + total, length - total);
        if (received <= 0) {
            return SDR_TRANSMIT_ERROR;
        }
        total += (size_t)received;
    }
    return SDR_OK;
}

static int protocol_discard(size_t length)
{
    BYTE discard[1024];
    while (length > 0) {
        size_t chunk = length < sizeof(discard) ? length : sizeof(discard);
        int ret = protocol_recv_all(discard, chunk);
        if (ret != SDR_OK) {
            return ret;
        }
        length -= chunk;
    }
    return SDR_OK;
}

/**
 * @brief Initialize client connection
 */
int protocol_client_init(void)
{
    transport_config_t config = {0};
    int ret;
    sdfx_config_t sdfx_config;
    
    pthread_mutex_lock(&g_transport_mutex);
    
    if (g_client_initialized) {
        pthread_mutex_unlock(&g_transport_mutex);
        return SDR_OK;
    }
    
    /* Try to load configuration file */
    const char* config_files[] = {
#ifdef _WIN32
        "./sdfapi.ini",
        "./config/sdfapi.ini",
#endif
        "./sdfx.conf",
        "../config/sdfx.conf", 
        "/etc/sdfx/sdfx.conf",
        NULL
    };
    
    bool config_loaded = false;
    for (int i = 0; config_files[i] != NULL; i++) {
        if (access(config_files[i], R_OK) == 0) {
            if (sdfx_config_load_from_file(&sdfx_config, config_files[i]) == 0) {
                config_loaded = true;
                printf("[INFO] Client loaded configuration from: %s\n", config_files[i]);
                break;
            }
        }
    }
    
    if (!config_loaded) {
        /* Use default configuration */
        sdfx_config_init_default(&sdfx_config);
        printf("[INFO] Client using default configuration\n");
    }
    
    /* Initialize transport configuration */
#ifdef SDFX_TRANSPORT_TCP
    config.address = sdfx_config.transport.tcp_host;
    config.port = sdfx_config.transport.tcp_port;
#elif defined(SDFX_TRANSPORT_UNIX)
    config.address = sdfx_config.transport.unix_path;
    config.permissions = sdfx_config.transport.unix_permissions;
#elif defined(SDFX_TRANSPORT_SHM)
    config.address = sdfx_config.transport.shm_name;
#elif defined(SDFX_TRANSPORT_CUSTOM)
    config.user_data = (void*)sdfx_config.transport.custom_lib_path;
#else
    /* Default to Unix socket */
    config.address = sdfx_config.transport.unix_path;
#endif
    
    /* Initialize transport layer */
    ret = transport_init(&config);
    if (ret != SDR_OK) {
        pthread_mutex_unlock(&g_transport_mutex);
        return ret;
    }
    
    /* Connect to server */
#ifdef SDFX_TRANSPORT_TCP
    /* TCP transport: supports IP:port format or port only */
    if (config.address && strchr(config.address, ':')) {
        /* If address contains colon, use address directly */
        ret = transport_connect(config.address);
    } else {
        /* Otherwise construct host:port format */
        char addr_str[256];
        snprintf(addr_str, sizeof(addr_str), "%s:%d", 
                config.address ? config.address : "127.0.0.1", config.port);
        ret = transport_connect(addr_str);
    }
#else
    /* Other transports: pass address information */
    ret = transport_connect(config.address);
#endif
    if (ret != SDR_OK) {
        pthread_mutex_unlock(&g_transport_mutex);
        return ret;
    }
    
    g_client_initialized = 1;
    pthread_mutex_unlock(&g_transport_mutex);
    
    return SDR_OK;
}

/**
 * @brief Cleanup client connection
 */
void protocol_client_cleanup(void)
{
    pthread_mutex_lock(&g_transport_mutex);
    
    if (g_client_initialized) {
        transport_close();
        transport_cleanup();
        g_client_initialized = 0;
    }
    
    pthread_mutex_unlock(&g_transport_mutex);
}

/**
 * @brief Send request and receive response
 */
int protocol_client_request(const BYTE *req_msg, size_t req_len, 
                           BYTE *resp_msg, size_t resp_buf_len, size_t *resp_len)
{
    ssize_t sent;
    sdfx_message_header_t *header;
    size_t expected_len, remaining_len;
    int ret = SDR_OK;
    
    if (req_msg == NULL || resp_msg == NULL || resp_len == NULL) {
        return SDR_INARGERR;
    }
    
    pthread_mutex_lock(&g_transport_mutex);
    
    if (!g_client_initialized) {
        pthread_mutex_unlock(&g_transport_mutex);
        return SDR_STEPERR;
    }
    
    /* Send request */
    sent = transport_send(NULL, req_msg, req_len);
    if (sent != (ssize_t)req_len) {
        pthread_mutex_unlock(&g_transport_mutex);
        return SDR_TRANSMIT_ERROR;
    }
    
    /* Receive a complete response header even when the stream is fragmented. */
    if (protocol_recv_all(resp_msg, sizeof(sdfx_message_header_t)) != SDR_OK) {
        pthread_mutex_unlock(&g_transport_mutex);
        return SDR_TRANSMIT_ERROR;
    }
    
    /* Parse message length - header.length only contains data length, not header */
    header = (sdfx_message_header_t*)resp_msg;
    sdfx_message_header_from_network(header);  /* Convert byte order */
    
    ULONG data_len = header->length;           /* Data length (excluding header) */
    if (header->magic != SDFX_MAGIC ||
        header->version != SDFX_PROTOCOL_VERSION ||
        data_len > SDFX_MAX_MESSAGE_SIZE - sizeof(sdfx_message_header_t)) {
        pthread_mutex_unlock(&g_transport_mutex);
        return SDR_PROTOCOL_ERROR;
    }

    expected_len = sizeof(sdfx_message_header_t) + data_len;  /* Total length */
    
    if (expected_len > resp_buf_len) {
        int discard_ret = protocol_discard(data_len);
        pthread_mutex_unlock(&g_transport_mutex);
        return discard_ret == SDR_OK ? SDR_NOBUFFER : discard_ret;
    }
    
    remaining_len = data_len;
    if (remaining_len > 0 &&
        protocol_recv_all(resp_msg + sizeof(sdfx_message_header_t),
                          remaining_len) != SDR_OK) {
        pthread_mutex_unlock(&g_transport_mutex);
        return SDR_TRANSMIT_ERROR;
    }
    
    *resp_len = expected_len;
    pthread_mutex_unlock(&g_transport_mutex);
    
    return SDR_OK;
}

/**
 * @brief Send request and receive response (compatible interface)
 */
LONG protocol_client_send_recv(const void *req_msg, size_t req_len,
                              void *resp_msg, size_t resp_len,
                              size_t *actual_len)
{
    return protocol_client_request((const BYTE*)req_msg, req_len,
                                  (BYTE*)resp_msg, resp_len, actual_len);
}