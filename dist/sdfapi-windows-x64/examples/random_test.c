/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file test_random.c
 * @brief Random number generation function test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdfx.h"
#include "sdf.h"

static void print_hex(const char *label, const BYTE *data, ULONG len)
{
    printf("%s (%lu bytes): ", label, len);
    for (ULONG i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
            if (i + 1 < len) printf("    ");
        } else if ((i + 1) % 8 == 0) {
            printf(" ");
        }
    }
    if (len % 16 != 0) printf("\n");
}

static int test_basic_random(HANDLE session_handle)
{
    printf("\n=== Basic random number generation test ===\n");
    
    // Test random numbers of different lengths
    ULONG test_lengths[] = {1, 8, 16, 32, 64, 128, 256};
    int num_tests = sizeof(test_lengths) / sizeof(test_lengths[0]);
    
    for (int i = 0; i < num_tests; i++) {
        ULONG len = test_lengths[i];
        BYTE *random_data = malloc(len);
        if (!random_data) {
            printf("❌ Memory allocation failed (length: %lu)\n", len);
            return -1;
        }
        
        printf("\nTesting %lu byte random number generation...\n", len);
        LONG ret = SDF_GenerateRandom(session_handle, len, random_data);
        
        if (ret != SDR_OK) {
            printf("❌ SDF_GenerateRandom failed: %s (length: %lu)\n", 
                   SDFX_GetErrorString(ret), len);
            free(random_data);
            return -1;
        }
        
        printf("✅ Successfully generated %lu byte random number\n", len);
        // print_hex("Random number", random_data, len);
        
        free(random_data);
    }
    
    return 0;
}

static int test_random_quality(HANDLE session_handle)
{
    printf("\n=== Random number quality test ===\n");
    
    const ULONG test_len = 1000;
    BYTE *random_data = malloc(test_len);
    if (!random_data) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    printf("Generating %lu byte random number for quality analysis...\n", test_len);
    LONG ret = SDF_GenerateRandom(session_handle, test_len, random_data);
    
    if (ret != SDR_OK) {
        printf("❌ SDF_GenerateRandom failed: %s\n", SDFX_GetErrorString(ret));
        free(random_data);
        return -1;
    }
    
    // Simple statistical analysis
    int byte_counts[256] = {0};
    for (ULONG i = 0; i < test_len; i++) {
        byte_counts[random_data[i]]++;
    }
    
    // Calculate minimum, maximum and average frequency
    int min_count = byte_counts[0], max_count = byte_counts[0];
    double sum = 0;
    for (int i = 0; i < 256; i++) {
        if (byte_counts[i] < min_count) min_count = byte_counts[i];
        if (byte_counts[i] > max_count) max_count = byte_counts[i];
        sum += byte_counts[i];
    }
    double avg_count = sum / 256.0;
    
    printf("Byte distribution statistics:\n");
    printf("  Average frequency: %.2f\n", avg_count);
    printf("  Minimum frequency: %d\n", min_count);
    printf("  Maximum frequency: %d\n", max_count);
    printf("  Frequency ratio: %.2f (ideal value close to 1.0)\n", (double)max_count / min_count);
    
    // Simple continuity detection
    int consecutive_count = 0;
    int max_consecutive = 0;
    BYTE prev_byte = random_data[0];
    
    for (ULONG i = 1; i < test_len; i++) {
        if (random_data[i] == prev_byte) {
            consecutive_count++;
        } else {
            if (consecutive_count > max_consecutive) {
                max_consecutive = consecutive_count;
            }
            consecutive_count = 0;
        }
        prev_byte = random_data[i];
    }
    
    printf("Continuity analysis:\n");
    printf("  Maximum consecutive identical bytes: %d\n", max_consecutive + 1);
    
    free(random_data);
    
    if (max_consecutive > 10) {
        printf("⚠️  Warning: Detected long sequence of consecutive identical bytes\n");
    } else {
        printf("✅ Continuity test passed\n");
    }
    
    return 0;
}

static int test_random_uniqueness(HANDLE session_handle)
{
    printf("\n=== Random number uniqueness test ===\n");
    
    const int num_generations = 10;
    const ULONG random_len = 32;
    
    printf("Generating %d sets of %lu byte random numbers, checking uniqueness...\n", num_generations, random_len);
    
    BYTE random_arrays[10][32];  // Up to 10 sets of 32 bytes
    
    for (int i = 0; i < num_generations; i++) {
        LONG ret = SDF_GenerateRandom(session_handle, random_len, random_arrays[i]);
        if (ret != SDR_OK) {
            printf("❌ Generation #%d failed: %s\n", i+1, SDFX_GetErrorString(ret));
            return -1;
        }
        
        printf("Random number #%d: ", i+1);
        for (ULONG j = 0; j < 16; j++) {  // Only show first 16 bytes
            printf("%02x", random_arrays[i][j]);
        }
        printf("...\n");
    }
    
    // Check for duplicates
    int duplicates = 0;
    for (int i = 0; i < num_generations; i++) {
        for (int j = i + 1; j < num_generations; j++) {
            if (memcmp(random_arrays[i], random_arrays[j], random_len) == 0) {
                printf("❌ Found duplicate: random number #%d and #%d are identical\n", i+1, j+1);
                duplicates++;
            }
        }
    }
    
    if (duplicates == 0) {
        printf("✅ All random numbers are unique\n");
    } else {
        printf("❌ Found %d duplicates\n", duplicates);
    }
    
    return duplicates;
}

static int test_edge_cases(HANDLE session_handle)
{
    printf("\n=== Edge case testing ===\n");
    
    // Test minimum length
    printf("Testing minimum length (1 byte)...");
    BYTE single_byte;
    LONG ret = SDF_GenerateRandom(session_handle, 1, &single_byte);
    if (ret != SDR_OK) {
        printf("❌ 1-byte random number generation failed: %s\n", SDFX_GetErrorString(ret));
        return -1;
    }
    printf("✅ 1-byte random number: 0x%02x\n", single_byte);
    
    // Test larger length
    printf("\nTesting larger length (4096 bytes)...");
    BYTE *large_buffer = malloc(4096);
    if (!large_buffer) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    ret = SDF_GenerateRandom(session_handle, 4096, large_buffer);
    if (ret != SDR_OK) {
        printf("❌ 4096-byte random number generation failed: %s (error code: %ld, 0x%lx)\n", SDFX_GetErrorString(ret), ret, ret);
        free(large_buffer);
        return -1;
    }
    printf("✅ Successfully generated 4096-byte random number\n");
    
    // Show first 32 bytes and last 32 bytes
    // print_hex("First 32 bytes", large_buffer, 32);
    // print_hex("Last 32 bytes", large_buffer + 4096 - 32, 32);
    
    free(large_buffer);
    
    // Test invalid parameters
    printf("\nTesting invalid parameters...\n");
    ret = SDF_GenerateRandom(session_handle, 0, &single_byte);
    if (ret != SDR_OK) {
        printf("✅ Zero length correctly returned error: %s\n", SDFX_GetErrorString(ret));
    } else {
        printf("❌ Zero length should return error\n");
        return -1;
    }
    
    ret = SDF_GenerateRandom(session_handle, 1, NULL);
    if (ret != SDR_OK) {
        printf("✅ Null pointer correctly returned error: %s\n", SDFX_GetErrorString(ret));
    } else {
        printf("❌ Null pointer should return error\n");
        return -1;
    }
    
    return 0;
}

int main()
{
    printf("SDFX random number generation test\n");
    printf("=====================\n");
    
    HANDLE device_handle = NULL;
    HANDLE session_handle = NULL;
    LONG ret;
    
    // Open device
    ret = SDF_OpenDevice(&device_handle);
    if (ret != SDR_OK) {
        printf("❌ SDF_OpenDevice failed: %s\n", SDFX_GetErrorString(ret));
        return 1;
    }
    printf("✅ Device opened successfully\n");
    
    // Open session
    ret = SDF_OpenSession(device_handle, &session_handle);
    if (ret != SDR_OK) {
        printf("❌ SDF_OpenSession failed: %s\n", SDFX_GetErrorString(ret));
        SDF_CloseDevice(device_handle);
        return 1;
    }
    printf("✅ Session opened successfully\n");
    
    // Run tests
    int failed_tests = 0;
    
    if (test_basic_random(session_handle) != 0) {
        failed_tests++;
    }
    
    if (test_random_quality(session_handle) != 0) {
        failed_tests++;
    }
    
    if (test_random_uniqueness(session_handle) != 0) {
        failed_tests++;
    }
    
    if (test_edge_cases(session_handle) != 0) {
        failed_tests++;
    }
    
    // Cleanup
    SDF_CloseSession(session_handle);
    SDF_CloseDevice(device_handle);
    
    printf("\n=== Test summary ===\n");
    if (failed_tests == 0) {
        printf("🎉 All random number tests passed!\n");
        return 0;
    } else {
        printf("❌ %d tests failed\n", failed_tests);
        return 1;
    }
}