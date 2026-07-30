/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/**
 * @file sdfx.h
 * @brief SDFX Extended Definitions - Non-standard extensions to GM/T 0018-2023 SDF
 * @details This file contains SDFX-specific extensions that are not part of the
 *          GM/T 0018-2023 standard. Include this file when using SDFX SDK features.
 */

#ifndef SDFX_H
#define SDFX_H

/* Include standard SDF headers */
#include "sdf.h"

#ifdef __cplusplus
extern "C" {
#endif

/************************************************************************
 * SDFX Extended Error Codes
 ************************************************************************/

/* SDFX extended error codes base */
#define SDR_SDFX_BASE              0x02000000   /* Base address for SDFX error codes */

/* SDFX daemon and connection errors */
#define SDR_DAEMON_NOTRUNNING       (SDR_SDFX_BASE + 0x00000001)   /* Daemon is not running */
#define SDR_DAEMON_CONNFAIL         (SDR_SDFX_BASE + 0x00000002)   /* Failed to connect to daemon */
#define SDR_PROTOCOL_ERROR          (SDR_SDFX_BASE + 0x00000003)   /* Protocol error */
#define SDR_TIMEOUT                 (SDR_SDFX_BASE + 0x00000004)   /* Operation timed out */
#define SDR_INVALID_HANDLE          (SDR_SDFX_BASE + 0x00000005)   /* Invalid handle */
#define SDR_MEMORY_ERROR            (SDR_SDFX_BASE + 0x00000006)   /* Memory error */
#define SDR_CONFIG_ERROR            (SDR_SDFX_BASE + 0x00000007)   /* Configuration error */
#define SDR_TRANSPORT_CLOSED        (SDR_SDFX_BASE + 0x00000008)   /* Transport connection is closed */
#define SDR_SESSION_NOT_EXIST       (SDR_SDFX_BASE + 0x00000009)   /* Session does not exist */
#define SDR_TRANSMIT_ERROR          (SDR_SDFX_BASE + 0x0000000A)   /* Transmit error */

/************************************************************************
 * SDFX Extended Data Types
 ************************************************************************/

/* Version information structure */
typedef struct VERSION_st {
    unsigned int major;                     /* major version number */
    unsigned int minor;                     /* minor version number */
    unsigned int patch;                     /* patch version number */
    unsigned char desc[64];                 /* version description */
} VERSION;

/************************************************************************
 * SDFX Helper Functions
 ************************************************************************/

/**
 * @brief Get error description string
 * @param errorCode The error code
 * @return The error description string
 */
const char* SDFX_GetErrorString(int errorCode);

#ifdef __cplusplus
}
#endif

#endif /* SDFX_H */
