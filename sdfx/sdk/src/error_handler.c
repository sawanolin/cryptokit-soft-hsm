/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file error_handler.c
 * @brief Error processing implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdf.h"
#include "sdfx.h"

const char* SDFX_GetErrorString(int errorCode)
{
    switch (errorCode) {
        case SDR_OK:
            return "Success";
        case SDR_UNKNOWERR:
            return "Unknown error";
        case SDR_NOTSUPPORT:
            return "Not supported";
        case SDR_COMMFAIL:
            return "Communication failure";
        case SDR_HARDFAIL:
            return "Hardware failure";
        case SDR_OPENDEVICE:
            return "Open device failed";
        case SDR_OPENSESSION:
            return "Open session failed";
        case SDR_INARGERR:
            return "Invalid input parameter";
        case SDR_OUTARGERR:
            return "Invalid output parameter";
        case SDR_DAEMON_NOTRUNNING:
            return "Daemon not running";
        case SDR_DAEMON_CONNFAIL:
            return "Connection to daemon failed";
        case SDR_PROTOCOL_ERROR:
            return "Protocol error";
        case SDR_TIMEOUT:
            return "Operation timeout";
        case SDR_INVALID_HANDLE:
            return "Invalid handle";
        case SDR_MEMORY_ERROR:
            return "Memory error";
        case SDR_CONFIG_ERROR:
            return "Configuration error";
        default:
            return "Unknown error code";
    }
}