/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file test_basic.c
 * @brief Basic functionality test
 */

#include <stdio.h>
#include <stdlib.h>

#include "sdfx.h"
#include "sdf.h"

int main()
{
    printf("SDFX Basic Test\n");
    
    HANDLE device_handle = NULL;
    HANDLE session_handle = NULL;
    DEVICEINFO device_info;
    LONG ret;
    
    /* Test device opening */
    ret = SDF_OpenDevice(&device_handle);
    if (ret != SDR_OK) {
        printf("SDF_OpenDevice failed: %s (error code: 0x%08X)\n", SDFX_GetErrorString(ret), (unsigned int)ret);
        return 1;
    }
    printf("Device opened successfully\n");
    
    /* Test session opening */
    ret = SDF_OpenSession(device_handle, &session_handle);
    if (ret != SDR_OK) {
        printf("SDF_OpenSession failed: %s\n", SDFX_GetErrorString(ret));
        SDF_CloseDevice(device_handle);
        return 1;
    }
    printf("Session opened successfully\n");
    
    /* Test getting device information */
    ret = SDF_GetDeviceInfo(session_handle, &device_info);
    if (ret != SDR_OK) {
        printf("SDF_GetDeviceInfo failed: %s\n", SDFX_GetErrorString(ret));
    } else {
        printf("Device Info:\n");
        printf("  Issuer: %s\n", device_info.IssuerName);
        printf("  Name: %s\n", device_info.DeviceName);
        printf("  Serial: %s\n", device_info.DeviceSerial);
        printf("  Version: 0x%08x\n", device_info.DeviceVersion);
    }
    
    /* Cleanup */
    SDF_CloseSession(session_handle);
    SDF_CloseDevice(device_handle);
    
    printf("Test completed successfully\n");
    return 0;
}