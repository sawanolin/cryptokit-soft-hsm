/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file config.c
 * @brief SDFX simplified configuration manager implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#endif

#include "config.h"

/* Internal helper function implementations */
static char* trim_whitespace(char *str);
static int parse_config_line(sdfx_config_t *config, const char *section, const char *key, const char *value);

void sdfx_config_init_default(sdfx_config_t *config)
{
    if (!config) return;
    
    memset(config, 0, sizeof(sdfx_config_t));
    
    /* Default transport configuration */
    strncpy(config->transport.tcp_host, SDFX_DEFAULT_TCP_HOST, sizeof(config->transport.tcp_host) - 1);
    config->transport.tcp_port = SDFX_DEFAULT_TCP_PORT;
    strncpy(config->transport.unix_path, SDFX_DEFAULT_UNIX_PATH, sizeof(config->transport.unix_path) - 1);
    config->transport.unix_permissions = SDFX_DEFAULT_UNIX_PERM;
    
    /* Default daemon configuration */
    config->worker_threads = SDFX_DEFAULT_WORKER_THREADS;
    config->max_clients = SDFX_DEFAULT_MAX_CLIENTS;
    config->session_timeout = SDFX_DEFAULT_SESSION_TIMEOUT;
    
    /* Default client configuration */
    config->connect_timeout = SDFX_DEFAULT_CONNECT_TIMEOUT;
    config->request_timeout = SDFX_DEFAULT_REQUEST_TIMEOUT;
    config->retry_count = SDFX_DEFAULT_RETRY_COUNT;
}

int sdfx_config_load_from_file(sdfx_config_t *config, const char *config_file)
{
    FILE *fp;
    char line[1024];
    char section[64] = "";
    char *key, *value, *comment;
    int line_num = 0;
    
    if (!config || !config_file) return -1;
    
    /* First, initialize to default values */
    sdfx_config_init_default(config);
    
    fp = fopen(config_file, "r");
    if (!fp) {
        printf("[ERROR] Failed to open config file %s: %s\n", config_file, strerror(errno));
        return -1;
    }
    
    printf("[INFO] Loading configuration from: %s\n", config_file);
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        
        /* Remove comments */
        comment = strchr(line, '#');
        if (comment) *comment = '\0';
        
        /* Trim leading and trailing whitespace */
        char *trimmed = trim_whitespace(line);
        if (strlen(trimmed) == 0) continue;
        
        /* Parse section */
        if (trimmed[0] == '[' && trimmed[strlen(trimmed)-1] == ']') {
            trimmed[strlen(trimmed)-1] = '\0';
            strncpy(section, trimmed + 1, sizeof(section) - 1);
            continue;
        }
        
        /* Parse key=value */
        key = trimmed;
        value = strchr(trimmed, '=');
        if (!value) {
            printf("[WARN] Invalid config line %d: %s\n", line_num, trimmed);
            continue;
        }
        
        *value = '\0';
        value++;
        
        key = trim_whitespace(key);
        value = trim_whitespace(value);
        
        /* Parse configuration item */
        if (parse_config_line(config, section, key, value) != 0) {
            printf("[WARN] Unknown config item [%s].%s = %s\n", section, key, value);
        }
    }
    
    fclose(fp);
    printf("[INFO] Configuration loaded successfully\n");
    return 0;
}

int sdfx_config_validate(const sdfx_config_t *config)
{
    if (!config) return -1;
    
    /* Validate TCP configuration */
    if (config->transport.tcp_port == 0 || config->transport.tcp_port > 65535) {
        printf("[ERROR] Invalid TCP port: %d\n", config->transport.tcp_port);
        return -1;
    }
    
    if (strlen(config->transport.tcp_host) == 0) {
        printf("[ERROR] Empty TCP host\n");
        return -1;
    }
    
    if (strlen(config->transport.unix_path) == 0) {
        printf("[ERROR] Empty Unix socket path\n");
        return -1;
    }
    
    /* Validate daemon configuration */
    if (config->worker_threads == 0 || config->worker_threads > 256) {
        printf("[ERROR] Invalid worker threads: %d\n", config->worker_threads);
        return -1;
    }
    
    if (config->max_clients == 0 || config->max_clients > 10000) {
        printf("[ERROR] Invalid max clients: %d\n", config->max_clients);
        return -1;
    }
    
    return 0;
}

void sdfx_config_print(const sdfx_config_t *config)
{
    if (!config) return;
    
    printf("SDFX Configuration:\n");
    printf("==================\n");
    printf("Transport:\n");
    printf("  TCP Host: %s\n", config->transport.tcp_host);
    printf("  TCP Port: %d\n", config->transport.tcp_port);
    printf("  Unix Path: %s\n", config->transport.unix_path);
    printf("  Unix Permissions: 0%o\n", config->transport.unix_permissions);
    printf("Daemon:\n");
    printf("  Worker Threads: %d\n", config->worker_threads);
    printf("  Max Clients: %d\n", config->max_clients);
    printf("  Session Timeout: %d seconds\n", config->session_timeout);
    printf("Client:\n");
    printf("  Connect Timeout: %d ms\n", config->connect_timeout);
    printf("  Request Timeout: %d ms\n", config->request_timeout);
    printf("  Retry Count: %d\n", config->retry_count);
}

/* Internal helper function implementations */
static char* trim_whitespace(char *str)
{
    char *end;
    
    /* Trim leading whitespace */
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == 0) return str;
    
    /* Trim trailing whitespace */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    return str;
}

static int parse_config_line(sdfx_config_t *config, const char *section, const char *key, const char *value)
{
    /* [transport] section */
    if (strcasecmp(section, "transport") == 0) {
        if (strcasecmp(key, "tcp_host") == 0) {
            strncpy(config->transport.tcp_host, value, sizeof(config->transport.tcp_host) - 1);
            return 0;
        }
        if (strcasecmp(key, "tcp_port") == 0) {
            config->transport.tcp_port = (uint16_t)atoi(value);
            return 0;
        }
        if (strcasecmp(key, "unix_path") == 0) {
            strncpy(config->transport.unix_path, value, sizeof(config->transport.unix_path) - 1);
            return 0;
        }
        if (strcasecmp(key, "unix_permissions") == 0) {
            config->transport.unix_permissions = (uint32_t)strtol(value, NULL, 8);
            return 0;
        }
    }
    
    /* [daemon] section */
    if (strcasecmp(section, "daemon") == 0) {
        if (strcasecmp(key, "worker_threads") == 0) {
            config->worker_threads = (uint32_t)atoi(value);
            return 0;
        }
        if (strcasecmp(key, "max_clients") == 0) {
            config->max_clients = (uint32_t)atoi(value);
            return 0;
        }
        if (strcasecmp(key, "session_timeout") == 0) {
            config->session_timeout = (uint32_t)atoi(value);
            return 0;
        }
    }
    
    /* [client] section */
    if (strcasecmp(section, "client") == 0) {
        if (strcasecmp(key, "connect_timeout") == 0) {
            config->connect_timeout = (uint32_t)atoi(value);
            return 0;
        }
        if (strcasecmp(key, "request_timeout") == 0) {
            config->request_timeout = (uint32_t)atoi(value);
            return 0;
        }
        if (strcasecmp(key, "retry_count") == 0) {
            config->retry_count = (uint32_t)atoi(value);
            return 0;
        }
    }
    
    return -1;  /* Unknown configuration item */
}