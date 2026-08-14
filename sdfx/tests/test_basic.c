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

    if (SGD_SM2 != 0x00020100 || SGD_SM2_1 != 0x00020200 ||
        SGD_SM2_2 != 0x00020400 || SGD_SM2_3 != 0x00020800 ||
        SGD_SM4_XTS != 0x01000400 || SGD_SM3_HMAC != 0x00000008 ||
        SGD_SHA256_HMAC != 0x00000010) {
        fprintf(stderr, "GM/T 0006-2023 algorithm identifier check failed\n");
        return 1;
    }
    
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
        ULONG expected_hash_ability = SGD_SM3 | SGD_SHA256 |
                                      SGD_SM3_HMAC | SGD_SHA256_HMAC;
        printf("Device Info:\n");
        printf("  Issuer: %s\n", device_info.IssuerName);
        printf("  Name: %s\n", device_info.DeviceName);
        printf("  Serial: %s\n", device_info.DeviceSerial);
        printf("  Version: 0x%08x\n", device_info.DeviceVersion);
        if ((device_info.HashAlgAbility & expected_hash_ability) !=
            expected_hash_ability) {
            fprintf(stderr, "Device hash ability omits GM/T 0006-2023 algorithms\n");
            SDF_CloseSession(session_handle);
            SDF_CloseDevice(device_handle);
            return 1;
        }
    }
    
    /* Cleanup */
    SDF_CloseSession(session_handle);
    SDF_CloseDevice(device_handle);
    
    printf("Test completed successfully\n");
    return 0;
}
