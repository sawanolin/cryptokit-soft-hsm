/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file sdfx_defaults.h
 * @brief SDFX Project Unified Default Configuration Values Definition
 * 
 * This file centrally defines default configuration values used by all modules
 * in the SDFX project, ensuring configuration consistency and maintainability.
 * This is an internal shared header file and is not exposed to external users.
 */

#ifndef SDFX_DEFAULTS_H
#define SDFX_DEFAULTS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Transport Layer Defaults */
#define SDFX_DEFAULT_TCP_PORT       18081
#define SDFX_DEFAULT_TCP_HOST       "127.0.0.1"
#define SDFX_DEFAULT_UNIX_PATH      "/tmp/sdfxd.sock"
#define SDFX_DEFAULT_UNIX_PERM      0666

/* Daemon Defaults */
#define SDFX_DEFAULT_WORKER_THREADS 8
#define SDFX_DEFAULT_MAX_CLIENTS    100
#define SDFX_DEFAULT_SESSION_TIMEOUT 300

/* Client Defaults */
#define SDFX_DEFAULT_CONNECT_TIMEOUT 5000
#define SDFX_DEFAULT_REQUEST_TIMEOUT 30000
#define SDFX_DEFAULT_RETRY_COUNT    3

/* Protocol Defaults - For backward compatibility */
#define SDFX_DEFAULT_PORT           SDFX_DEFAULT_TCP_PORT

#ifdef __cplusplus
}
#endif

#endif /* SDFX_DEFAULTS_H */