/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file main.c
 * @brief SDFX daemon main program
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#include "daemon_internal.h"
#include "config.h"
#include "hitls_init.h"

static daemon_context_t *g_daemon_ctx = NULL;
static sdfx_config_t g_config;

static void signal_handler(int sig)
{
    printf("Received signal %d, shutting down...\n", sig);
    
    if (g_daemon_ctx != NULL) {
        g_daemon_ctx->running = false;
    }
}

static void print_usage(const char *program_name)
{
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Options:\n");
    printf("  -c, --config FILE     Use configuration file (default: use built-in defaults)\n");
    printf("  -h, --help           Show this help message\n");
    printf("  -v, --version        Show version information\n");
    printf("  -d, --daemon         Run in daemon mode (no change in behavior, for compatibility)\n");
    printf("\nExamples:\n");
    printf("  %s                          # Use default configuration\n", program_name);
    printf("  %s -c /etc/sdfx.conf        # Use custom config file\n", program_name);
    printf("  %s --config tcp_remote.conf # Use TCP remote config\n", program_name);
}

int main(int argc, char *argv[])
{
    const char *config_file = NULL;
    int opt;
    int ret;
    
    /* Command line option definitions */
    static struct option long_options[] = {
        {"config",  required_argument, 0, 'c'},
        {"help",    no_argument,       0, 'h'},
        {"version", no_argument,       0, 'v'},
        {"daemon",  no_argument,       0, 'd'},
        {0, 0, 0, 0}
    };
    
    printf("SDFX Daemon v1.1.2\n");
    
    /* Parse command line arguments */
    while ((opt = getopt_long(argc, argv, "c:hvd", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                printf("SDFX Daemon version 1.1.2\n");
                printf("Built with openHiTLS cryptographic library\n");
                return 0;
            case 'd':
                /* Compatibility option, no actual effect */
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    printf("Starting SDFX daemon...\n");
    
    /* Load configuration */
    if (config_file) {
        printf("Loading configuration from: %s\n", config_file);
        if (sdfx_config_load_from_file(&g_config, config_file) != 0) {
            fprintf(stderr, "Failed to load configuration file: %s\n", config_file);
            return 1;
        }
        
        if (sdfx_config_validate(&g_config) != 0) {
            fprintf(stderr, "Invalid configuration\n");
            return 1;
        }
        
        printf("Configuration loaded and validated successfully\n");
        sdfx_config_print(&g_config);
        printf("\n");
    } else {
        printf("Using default configuration (no config file specified)\n");
        sdfx_config_init_default(&g_config);
    }
    
    /* Initialize openHiTLS library */
    printf("Initializing openHiTLS cryptographic library...\n");
    if (sdfx_hitls_init() != SDR_OK) {
        fprintf(stderr, "Failed to initialize openHiTLS library\n");
        return 1;
    }
    printf("openHiTLS library initialized successfully\n");
    
    /* Register signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Get daemon context */
    g_daemon_ctx = daemon_get_context();
    if (g_daemon_ctx == NULL) {
        fprintf(stderr, "Failed to get daemon context\n");
        return 1;
    }
    
    /* Initialize daemon core */
    if (config_file) {
        /* Initialize with configuration file */
        ret = daemon_core_init_with_config(g_daemon_ctx, &g_config);
    } else {
        /* Initialize with default configuration */
        ret = daemon_core_init(g_daemon_ctx);
    }
    
    if (ret != SDR_OK) {
        fprintf(stderr, "Failed to initialize daemon core: %d\n", ret);
        return 1;
    }
    
    printf("SDFX daemon initialized successfully\n");
    
    /* Run daemon */
    ret = daemon_core_run(g_daemon_ctx);
    
    printf("SDFX daemon shutting down...\n");
    
    /* Cleanup resources */
    daemon_core_cleanup(g_daemon_ctx);
    
    /* Cleanup openHiTLS library */
    printf("Cleaning up openHiTLS library...\n");
    sdfx_hitls_cleanup();
    
    printf("SDFX daemon stopped\n");
    return (ret == SDR_OK) ? 0 : 1;
}
