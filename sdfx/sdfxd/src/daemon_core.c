/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file daemon_core.c
 * @brief SDFX daemon core implementation - decoupled from transport layer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include "daemon_internal.h"
#include "transport_interface.h" 
#include "config.h"

static daemon_context_t g_daemon_ctx;

/* Client processing task argument */
typedef struct client_task_arg {
    daemon_context_t *ctx;
    transport_client_t client;
} client_task_arg_t;

/* Client handler task function */
static void client_handler_task(void *arg)
{
    client_task_arg_t *task_arg = (client_task_arg_t *)arg;
    daemon_context_t *ctx = task_arg->ctx;
    transport_client_t client = task_arg->client;
    
    LOG_INFO("Processing client connection: %s", client.client_info);
    
    BYTE buffer[SDFX_MAX_MESSAGE_SIZE];
    
    while (ctx->running) {
        /* Use secure message reception with bounds checking */
        size_t received_size = 0;
        int recv_result = transport_recv_message(&client, buffer, sizeof(buffer), &received_size);
        
        if (recv_result == 2) {
            LOG_DEBUG("Client closed connection");
            break;
        } else if (recv_result < 0) {
            LOG_ERROR("Failed to receive message from client");
            break;
        } else if (recv_result > 0) {
            LOG_WARN("Incomplete message received, continuing");
            continue;
        }
        
        LOG_DEBUG("Securely received %zu bytes from client", received_size);
        
        sdfx_message_t *request = (sdfx_message_t *)buffer;
        
        /* Process message.  Log metadata only; cryptographic payloads and secrets
         * are deliberately never written to logs. */
        sdfx_message_t *response = NULL;
        size_t response_size = 0;
        struct timespec started_at, finished_at;
        clock_gettime(CLOCK_MONOTONIC, &started_at);
        uint32_t command = sdfx_ntohl(request->header.cmd);
        uint32_t session_id = sdfx_ntohl(request->header.session_id);
        int ret = protocol_handler_process_message(ctx, request, &response, &response_size);
        clock_gettime(CLOCK_MONOTONIC, &finished_at);
        long long elapsed_us = (finished_at.tv_sec - started_at.tv_sec) * 1000000LL +
            (finished_at.tv_nsec - started_at.tv_nsec) / 1000LL;
        LOG_MODULE_INFO("access",
            "client=%s command=0x%04x session=%u request_bytes=%zu response_bytes=%zu status=0x%08x elapsed_us=%lld",
            client.client_info, command, session_id, received_size,
            response_size, (unsigned int)ret, elapsed_us);
        
        if (response != NULL) {
            /* Send response */
            ssize_t sent_size = transport_send(&client, response, response_size);
            if (sent_size != (ssize_t)response_size) {
                LOG_ERROR("Failed to send response: sent %zd/%zu bytes", sent_size, response_size);
            }
            free(response);
        }
    }
    
    /* Close client connection and clean up */
    transport_close_client(&client);
    free(task_arg);
    
    LOG_DEBUG("Client handler task completed");
}

static void* accept_thread(void *arg)
{
    daemon_context_t *ctx = (daemon_context_t *)arg;
    
    LOG_INFO("Accept thread started");
    LOG_INFO("Using %s transport", transport_get_type());
    
    while (ctx->running) {
        transport_client_t client;
        
        int ret = transport_accept(&client);
        if (ret < 0) {
            if (ctx->running) {
                LOG_ERROR("accept failed");
                sleep(1);
            }
            continue;
        } else if (ret > 0) {
            /* Retry needed */
            usleep(10000);  /* 10ms */
            continue;
        }
        
        /* Create client handler task with NULL check */
        client_task_arg_t *task_arg = malloc(sizeof(client_task_arg_t));
        if (task_arg == NULL) {
            LOG_ERROR("Failed to allocate task argument: %s", strerror(errno));
            transport_close_client(&client);
            continue;
        }
        
        task_arg->ctx = ctx;
        task_arg->client = client;
        
        /* Submit task to thread pool */
        if (thread_pool_submit(client_handler_task, task_arg) != 0) {
            LOG_ERROR("Failed to submit client task to thread pool");
            transport_close_client(&client);
            free(task_arg);
            continue;
        }
        
        LOG_DEBUG("Client task submitted to thread pool");
    }
    
    LOG_INFO("Accept thread exiting");
    return NULL;
}

int daemon_core_init_with_config(daemon_context_t *ctx, const void *config)
{
    const sdfx_config_t *sdfx_config = (const sdfx_config_t *)config;
    
    if (ctx == NULL) {
        return SDR_INARGERR;
    }
    
    memset(ctx, 0, sizeof(daemon_context_t));
    ctx->running = true;
    
    LOG_INFO("Initializing daemon core with configuration");
    
    /* Initialize transport layer with configuration */
    transport_config_t transport_config = {0};
    
#ifdef SDFX_TRANSPORT_TCP
    if (sdfx_config) {
        transport_config.address = sdfx_config->transport.tcp_host;
        transport_config.port = sdfx_config->transport.tcp_port;
    } else {
        transport_config.port = SDFX_DEFAULT_PORT;
    }
    
    int ret = transport_init_with_config(&transport_config);
    if (ret != 0) {
        LOG_ERROR("Failed to initialize transport layer with config: %d", ret);
        return SDR_NOBUFFER;
    }
    
#elif defined(SDFX_TRANSPORT_UNIX)
    if (sdfx_config) {
        transport_config.address = sdfx_config->transport.unix_path;
        transport_config.permissions = sdfx_config->transport.unix_permissions;
    } else {
        transport_config.address = "/tmp/sdfxd.sock";
        transport_config.permissions = 0666;
    }
    
    int ret = transport_init(&transport_config);
    if (ret != 0) {
        LOG_ERROR("Failed to initialize transport layer: %d", ret);
        return SDR_NOBUFFER;
    }
    
#else
    /* Other transport methods */
    transport_config.address = "/tmp/sdfxd.sock";
    int ret = transport_init(&transport_config);
    if (ret != 0) {
        LOG_ERROR("Failed to initialize transport layer: %d", ret);
        return SDR_NOBUFFER;
    }
#endif
    
    /* Initialize thread pool */
    int thread_count = sdfx_config ? sdfx_config->worker_threads : 8;
    if (thread_pool_create(thread_count) != 0) {
        LOG_ERROR("Failed to create thread pool");
        transport_cleanup();
        return SDR_NOBUFFER;
    }
    LOG_INFO("Thread pool created with %d worker threads", thread_count);
    
    /* Initialize session manager */
    ret = session_manager_init(ctx);
    if (ret != SDR_OK) {
        LOG_ERROR("Failed to initialize session manager: %d", ret);
        thread_pool_destroy();
        transport_cleanup();
        return ret;
    }
    LOG_INFO("Session manager initialized");
    
    /* Initialize protocol handler */
    ret = protocol_handler_init(ctx);
    if (ret != SDR_OK) {
        LOG_ERROR("Failed to initialize protocol handler: %d", ret);
        session_manager_cleanup(ctx);
        thread_pool_destroy();
        transport_cleanup();
        return ret;
    }
    LOG_INFO("Protocol handler initialized");
    
    LOG_INFO("Daemon core initialized successfully");
    return SDR_OK;
}

int daemon_core_init(daemon_context_t *ctx)
{
    if (ctx == NULL) {
        return SDR_INARGERR;
    }
    
    memset(ctx, 0, sizeof(daemon_context_t));
    ctx->running = true;
    
    /* Initialize transport layer */
    transport_config_t transport_config = {0};
    
#ifdef SDFX_TRANSPORT_TCP
    transport_config.port = SDFX_DEFAULT_PORT;
#elif defined(SDFX_TRANSPORT_UNIX)
    transport_config.address = "/tmp/sdfxd.sock";
#elif defined(SDFX_TRANSPORT_SHM)
    transport_config.address = "/tmp/sdfxd_shm";
#elif defined(SDFX_TRANSPORT_CUSTOM)
    /* Custom transport library path must be specified at compile or run time */
    transport_config.user_data = (void*)CUSTOM_TRANSPORT_LIB_PATH;
#else
    /* Default to using Unix socket */
    transport_config.address = "/tmp/sdfxd.sock";
#endif
    
    int ret = transport_init(&transport_config);
    if (ret != 0) {
        LOG_ERROR("Failed to initialize transport layer: %d", ret);
        return SDR_NOBUFFER;
    }
    
    /* Initialize thread pool (8 worker threads) */
    if (thread_pool_create(8) != 0) {
        LOG_ERROR("Failed to create thread pool");
        transport_cleanup();
        return SDR_NOBUFFER;
    }
    
    /* Initialize session manager */
    ret = session_manager_init(ctx);
    if (ret != SDR_OK) {
        LOG_ERROR("Failed to initialize session manager: %d", ret);
        thread_pool_destroy();
        transport_cleanup();
        return ret;
    }
    
    /* Initialize protocol handler */
    ret = protocol_handler_init(ctx);
    if (ret != SDR_OK) {
        LOG_ERROR("Failed to initialize protocol handler: %d", ret);
        session_manager_cleanup(ctx);
        thread_pool_destroy();
        transport_cleanup();
        return ret;
    }
    
    LOG_INFO("Daemon core initialized successfully");
    return SDR_OK;
}

void daemon_core_cleanup(daemon_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    ctx->running = false;
    
    /* Cleanup protocol handler */
    protocol_handler_cleanup(ctx);
    
    /* Cleanup session manager */
    session_manager_cleanup(ctx);
    
    /* Cleanup crypto engine */
    crypto_engine_cleanup();
    
    /* Destroy thread pool */
    thread_pool_destroy();
    
    /* Cleanup transport layer */
    transport_cleanup();
    
    LOG_INFO("Daemon core cleanup completed");
}

int daemon_core_run(daemon_context_t *ctx)
{
    if (ctx == NULL) {
        return SDR_INARGERR;
    }
    
    LOG_INFO("Starting daemon core with thread pool");
    
    /* Start transport layer listening */
    int ret = transport_listen();
    if (ret != 0) {
        LOG_ERROR("Failed to start transport listening: %d", ret);
        return SDR_NOBUFFER;
    }
    
    /* Display thread pool status */
    int thread_count, queue_size;
    if (thread_pool_get_stats(&thread_count, &queue_size) == 0) {
        LOG_INFO("Thread pool: %d workers, %d queued tasks", thread_count, queue_size);
    }
    
    /* Create accept connection thread */
    pthread_t accept_tid;
    ret = pthread_create(&accept_tid, NULL, accept_thread, ctx);
    if (ret != 0) {
        LOG_ERROR("Failed to create accept thread: %d", ret);
        return SDR_NOBUFFER;
    }
    
    LOG_INFO("Daemon is running, waiting for connections...");
    
    /* Main loop - wait for accept thread to complete */
    pthread_join(accept_tid, NULL);
    
    LOG_INFO("Daemon core stopped");
    return SDR_OK;
}

daemon_context_t* daemon_get_context(void)
{
    return &g_daemon_ctx;
}
