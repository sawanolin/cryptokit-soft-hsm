/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file test_hash.c
 * @brief SDFX hash algorithm test program
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sdf.h"

#define MAX_HASH_LEN 64
#define TEST_DATA_SIZE 4096

/* Test data */
static const BYTE test_data[] = "The quick brown fox jumps over the lazy dog";
static const size_t test_data_len = sizeof(test_data) - 1;

/* Expected result - SHA256 */
static const BYTE expected_sha256[] = {
    0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 
    0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f,
    0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 
    0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92
};

static void print_hex(const char *label, const BYTE *data, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) {
            printf("\n    ");
        } else if (i < len - 1) {
            printf(" ");
        }
    }
    printf("\n");
}

static int test_hash_algorithm(HANDLE device_handle, HANDLE session_handle, 
                              ULONG alg_id, const char *alg_name, 
                              const BYTE *expected, size_t expected_len)
{
    printf("\n=== Testing %s hash algorithm ===\n", alg_name);
    
    BYTE hash_result[MAX_HASH_LEN];
    ULONG hash_len = MAX_HASH_LEN;
    
    /* Test 1: Single-shot hash calculation */
    printf("Testing single-shot hash calculation...\n");
    LONG ret = SDF_HashInit(session_handle, alg_id, NULL, NULL, 0);
    if (ret != SDR_OK) {
        printf("❌ SDF_HashInit failed: 0x%lx\n", ret);
        return -1;
    }
    
    ret = SDF_HashUpdate(session_handle, (BYTE*)test_data, test_data_len);
    if (ret != SDR_OK) {
        printf("❌ SDF_HashUpdate failed: 0x%lx\n", ret);
        return -1;
    }
    
    ret = SDF_HashFinal(session_handle, hash_result, &hash_len);
    if (ret != SDR_OK) {
        printf("❌ SDF_HashFinal failed: 0x%lx\n", ret);
        return -1;
    }
    
    printf("✅ Hash calculation successful\n");
    print_hex("Calculated result", hash_result, hash_len);
    
    /* Verify result (only for SHA256) */
    if (expected != NULL && expected_len > 0) {
        if (hash_len == expected_len && memcmp(hash_result, expected, hash_len) == 0) {
            printf("✅ Hash result verification correct\n");
        } else {
            printf("❌ Hash result verification failed\n");
            print_hex("Expected result", expected, expected_len);
            return -1;
        }
    }
    
    /* Test 2: Multi-part hash calculation */
    printf("Testing multi-part hash calculation...\n");
    hash_len = MAX_HASH_LEN;
    memset(hash_result, 0, sizeof(hash_result));
    
    ret = SDF_HashInit(session_handle, alg_id, NULL, NULL, 0);
    if (ret != SDR_OK) {
        printf("❌ SDF_HashInit failed: 0x%lx\n", ret);
        return -1;
    }
    
    /* Process data in chunks */
    size_t chunk_size = test_data_len / 3;
    ret = SDF_HashUpdate(session_handle, (BYTE*)test_data, chunk_size);
    if (ret != SDR_OK) {
        printf("❌ SDF_HashUpdate (chunk 1) failed: 0x%lx\n", ret);
        return -1;
    }
    
    ret = SDF_HashUpdate(session_handle, (BYTE*)test_data + chunk_size, chunk_size);
    if (ret != SDR_OK) {
        printf("❌ SDF_HashUpdate (chunk 2) failed: 0x%lx\n", ret);
        return -1;
    }
    
    ret = SDF_HashUpdate(session_handle, (BYTE*)test_data + 2 * chunk_size, 
                        test_data_len - 2 * chunk_size);
    if (ret != SDR_OK) {
        printf("❌ SDF_HashUpdate (chunk 3) failed: 0x%lx\n", ret);
        return -1;
    }
    
    ret = SDF_HashFinal(session_handle, hash_result, &hash_len);
    if (ret != SDR_OK) {
        printf("❌ SDF_HashFinal failed: 0x%lx\n", ret);
        return -1;
    }
    
    printf("✅ Multi-part hash calculation successful\n");
    print_hex("Multi-part calculated result", hash_result, hash_len);
    
    /* Verify multi-part result is same as single-shot result */
    if (expected != NULL && expected_len > 0) {
        if (hash_len == expected_len && memcmp(hash_result, expected, hash_len) == 0) {
            printf("✅ Multi-part hash result verification correct\n");
        } else {
            printf("❌ Multi-part hash result verification failed\n");
            return -1;
        }
    }
    
    return 0;
}

static int test_large_data_hash(HANDLE device_handle, HANDLE session_handle)
{
    printf("\n=== Testing large data hash processing ===\n");
    
    /* Generate large amount of test data */
    BYTE *large_data = malloc(TEST_DATA_SIZE);
    if (large_data == NULL) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    /* Fill test data */
    for (int i = 0; i < TEST_DATA_SIZE; i++) {
        large_data[i] = (BYTE)(i & 0xFF);
    }
    
    BYTE hash_result[MAX_HASH_LEN];
    ULONG hash_len = MAX_HASH_LEN;
    
    LONG ret = SDF_HashInit(session_handle, SGD_SHA256, NULL, NULL, 0);
    if (ret != SDR_OK) {
        printf("❌ SDF_HashInit failed: 0x%lx\n", ret);
        free(large_data);
        return -1;
    }
    
    /* Process large data in chunks */
    size_t processed = 0;
    size_t chunk_size = TEST_DATA_SIZE;
    
    printf("Processing %d bytes of data, chunk size: %zu bytes\n", TEST_DATA_SIZE, chunk_size);
    
    while (processed < TEST_DATA_SIZE) {
        size_t current_chunk = (processed + chunk_size <= TEST_DATA_SIZE) ? 
                              chunk_size : (TEST_DATA_SIZE - processed);
        
        ret = SDF_HashUpdate(session_handle, large_data + processed, current_chunk);
        if (ret != SDR_OK) {
            printf("❌ SDF_HashUpdate failed (offset %zu): 0x%lx\n", processed, ret);
            free(large_data);
            return -1;
        }
        
        processed += current_chunk;
        
        if (processed % 512 == 0) {
            printf("Processed: %zu/%d bytes\n", processed, TEST_DATA_SIZE);
        }
    }
    
    ret = SDF_HashFinal(session_handle, hash_result, &hash_len);
    if (ret != SDR_OK) {
        printf("❌ SDF_HashFinal failed: 0x%lx\n", ret);
        free(large_data);
        return -1;
    }
    
    printf("✅ Large data hash calculation successful\n");
    print_hex("Large data hash result", hash_result, hash_len);
    
    free(large_data);
    return 0;
}

static int test_sm2_message_preprocess(HANDLE session_handle)
{
    static const BYTE public_x[32] = {
        0x09,0xf9,0xdf,0x31,0x1e,0x54,0x21,0xa1,0x50,0xdd,0x7d,0x16,0x1e,0x4b,0xc5,0xc6,
        0x72,0x17,0x9f,0xad,0x18,0x33,0xfc,0x07,0x6b,0xb0,0x8f,0xf3,0x56,0xf3,0x50,0x20
    };
    static const BYTE public_y[32] = {
        0xcc,0xea,0x49,0x0c,0xe2,0x67,0x75,0xa5,0x2d,0xc6,0xea,0x71,0x8c,0xc1,0xaa,0x60,
        0x0a,0xed,0x05,0xfb,0xf3,0x5e,0x08,0x4a,0x66,0x32,0xf6,0x07,0x2d,0xa9,0xad,0x13
    };
    static const BYTE expected_digest[32] = {
        0xf0,0xb4,0x3e,0x94,0xba,0x45,0xac,0xca,0xac,0xe6,0x92,0xed,0x53,0x43,0x82,0xeb,
        0x17,0xe6,0xab,0x5a,0x19,0xce,0x7b,0x31,0xf4,0x48,0x6f,0xdf,0xc0,0xd2,0x86,0x40
    };
    static BYTE identity[] = "1234567812345678";
    static BYTE message[] = "message digest";
    ECCrefPublicKey public_key;
    BYTE digest[MAX_HASH_LEN];
    ULONG digest_len = sizeof(digest);
    LONG ret;

    printf("\n=== Testing SM2 message signature preprocessing ===\n");
    memset(&public_key, 0, sizeof(public_key));
    public_key.bits = 256;
    memcpy(public_key.x + ECCref_MAX_LEN - sizeof(public_x), public_x, sizeof(public_x));
    memcpy(public_key.y + ECCref_MAX_LEN - sizeof(public_y), public_y, sizeof(public_y));

    ret = SDF_HashInit(session_handle, SGD_SM3, &public_key,
                       identity, sizeof(identity) - 1);
    if (ret != SDR_OK) {
        printf("SM2 preprocessing init failed: 0x%lx\n", ret);
        return -1;
    }
    ret = SDF_HashUpdate(session_handle, message, sizeof(message) - 1);
    if (ret != SDR_OK) {
        printf("SM2 preprocessing update failed: 0x%lx\n", ret);
        return -1;
    }
    ret = SDF_HashFinal(session_handle, digest, &digest_len);
    if (ret != SDR_OK || digest_len != sizeof(expected_digest) ||
        memcmp(digest, expected_digest, sizeof(expected_digest)) != 0) {
        printf("SM2 preprocessing vector mismatch: 0x%lx\n", ret);
        print_hex("Calculated result", digest, digest_len);
        print_hex("Expected result", expected_digest, sizeof(expected_digest));
        return -1;
    }

    if (SDF_HashInit(session_handle, SGD_SHA256, &public_key,
                     identity, sizeof(identity) - 1) != SDR_ALGNOTSUPPORT ||
        SDF_HashInit(session_handle, SGD_SM3, NULL,
                     identity, sizeof(identity) - 1) != SDR_INARGERR ||
        SDF_HashInit(session_handle, SGD_SM3, &public_key,
                     NULL, sizeof(identity) - 1) != SDR_INARGERR) {
        printf("SM2 preprocessing argument validation failed\n");
        return -1;
    }

    printf("SM2 preprocessing standard vector and error cases passed\n");
    return 0;
}
int main()
{
    printf("SDFX hash algorithm test\n");
    printf("==================\n");
    
    HANDLE device_handle = NULL;
    HANDLE session_handle = NULL;
    LONG ret;
    
    /* Open device */
    ret = SDF_OpenDevice(&device_handle);
    if (ret != SDR_OK) {
        printf("❌ Device open failed: 0x%lx\n", ret);
        return 1;
    }
    printf("✅ Device opened successfully\n");
    
    /* Open session */
    ret = SDF_OpenSession(device_handle, &session_handle);
    if (ret != SDR_OK) {
        printf("❌ Session open failed: 0x%lx\n", ret);
        SDF_CloseDevice(device_handle);
        return 1;
    }
    printf("✅ Session opened successfully\n");
    
    /* Test various hash algorithms */
    int test_result = 0;
    
    /* Test SHA256 (with expected result verification) */
    if (test_hash_algorithm(device_handle, session_handle, SGD_SHA256, "SHA256", 
                           expected_sha256, sizeof(expected_sha256)) != 0) {
        test_result = 1;
    }
    
    /* Test SHA1 */
    if (test_hash_algorithm(device_handle, session_handle, SGD_SHA1, "SHA1", 
                           NULL, 0) != 0) {
        test_result = 1;
    }
    
    /* Test SHA224 */
    if (test_hash_algorithm(device_handle, session_handle, SGD_SHA224, "SHA224", 
                           NULL, 0) != 0) {
        test_result = 1;
    }
    
    /* Test SHA384 */
    if (test_hash_algorithm(device_handle, session_handle, SGD_SHA384, "SHA384", 
                           NULL, 0) != 0) {
        test_result = 1;
    }
    
    /* Test SHA512 */
    if (test_hash_algorithm(device_handle, session_handle, SGD_SHA512, "SHA512", 
                           NULL, 0) != 0) {
        test_result = 1;
    }
    
    /* Test SM3 */
    if (test_hash_algorithm(device_handle, session_handle, SGD_SM3, "SM3", 
                           NULL, 0) != 0) {
        test_result = 1;
    }
    
    /* Test large data processing */
    if (test_large_data_hash(device_handle, session_handle) != 0) {
        test_result = 1;
    }
    /* Test SM2 message signature preprocessing (ZA || message). */
    if (test_sm2_message_preprocess(session_handle) != 0) {
        test_result = 1;
    }
    
    /* Cleanup resources */
    SDF_CloseSession(session_handle);
    SDF_CloseDevice(device_handle);
    
    printf("\n=== Test Summary ===\n");
    if (test_result == 0) {
        printf("🎉 All hash algorithm tests passed!\n");
    } else {
        printf("❌ Some hash algorithm tests failed!\n");
    }
    
    return test_result;
}