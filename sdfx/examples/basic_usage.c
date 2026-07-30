/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file basic_usage.c
 * @brief SDFX Basic Usage Example
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdf.h"

int main()
{
    printf("SDFX Basic Usage Example\n");
    printf("========================\n");
    
    HANDLE device_handle = NULL;
    HANDLE session_handle = NULL;
    DEVICEINFO device_info;
    BYTE random_data[32];
    LONG ret;
    
    /* Step 1: Open device */
    printf("1. Opening device...\n");
    ret = SDF_OpenDevice(&device_handle);
    if (ret != SDR_OK) {
        printf("   Failed: %s\n", SDFX_GetErrorString(ret));
        return 1;
    }
    printf("   Success: Device handle = %p\n", device_handle);
    
    /* Step 2: Open session */
    printf("2. Opening session...\n");
    ret = SDF_OpenSession(device_handle, &session_handle);
    if (ret != SDR_OK) {
        printf("   Failed: %s\n", SDFX_GetErrorString(ret));
        SDF_CloseDevice(device_handle);
        return 1;
    }
    printf("   Success: Session handle = %p\n", session_handle);
    
    /* Step 3: Get device information */
    printf("3. Getting device information...\n");
    ret = SDF_GetDeviceInfo(session_handle, &device_info);
    if (ret != SDR_OK) {
        printf("   Failed: %s\n", SDFX_GetErrorString(ret));
    } else {
        printf("   Device Information:\n");
        printf("     Issuer: %s\n", device_info.IssuerName);
        printf("     Name: %s\n", device_info.DeviceName);
        printf("     Serial: %s\n", device_info.DeviceSerial);
        printf("     Version: 0x%08x\n", device_info.DeviceVersion);
        printf("     Standard: 0x%08x\n", device_info.StandardVersion);
    }
    
    /* Step 4: Generate random number */
    printf("4. Generating random data...\n");
    ret = SDF_GenerateRandom(session_handle, sizeof(random_data), random_data);
    if (ret != SDR_OK) {
        printf("   Failed: %s\n", SDFX_GetErrorString(ret));
    } else {
        printf("   Random data: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", random_data[i]);
        }
        printf("...\n");
    }
    
    /* Step 5: Cleanup resources */
    printf("5. Cleaning up...\n");
    SDF_CloseSession(session_handle);
    printf("   Session closed\n");
    
    SDF_CloseDevice(device_handle);
    printf("   Device closed\n");
    
    printf("\nBasic usage example completed successfully!\n");
    return 0;
}
