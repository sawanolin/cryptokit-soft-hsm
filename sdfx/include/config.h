/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file config.h
 * @brief SDFX simplified configuration manager
 */

#ifndef SDFX_CONFIG_H
#define SDFX_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include "sdfx_defaults.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Transport configuration structure */
typedef struct {
    /* TCPconfiguration */
    char tcp_host[256];
    uint16_t tcp_port;
    
    /* Unix Socketconfiguration */
    char unix_path[512];
    uint32_t unix_permissions;
    
    /* Other transport configuration reserved */
    char shm_name[256];
    size_t shm_size;
    char custom_lib_path[512];
} sdfx_transport_config_t;

/* Complete configuration structure */
typedef struct {
    sdfx_transport_config_t transport;
    
    /* Daemonconfiguration */
    uint32_t worker_threads;
    uint32_t max_clients;
    uint32_t session_timeout;
    
    /* clientconfiguration */
    uint32_t connect_timeout;
    uint32_t request_timeout;
    uint32_t retry_count;
} sdfx_config_t;

/**
 * @brief Initialize configuration with default values
 * @param config Configuration structure pointer
 */
void sdfx_config_init_default(sdfx_config_t *config);

/**
 * @brief Load configuration from specified file
 * @param config Configuration structure pointer
 * @param config_file Configuration file path
 * @return 0 success, -1 failure
 */
int sdfx_config_load_from_file(sdfx_config_t *config, const char *config_file);

/**
 * @brief Verify configuration validity
 * @param config Configuration structure pointer
 * @return 0 valid, -1 invalid
 */
int sdfx_config_validate(const sdfx_config_t *config);

/**
 * @brief Print configuration information
 * @param config Configuration structure pointer
 */
void sdfx_config_print(const sdfx_config_t *config);

/* Default value definitions moved to common/include/sdfx_defaults.h for centralized management */
/* All default values are now defined in common/include/sdfx_defaults.h */

#ifdef __cplusplus
}
#endif

#endif /* SDFX_CONFIG_H */
