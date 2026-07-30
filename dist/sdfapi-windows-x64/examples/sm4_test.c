/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file test_symmetric.c
 * @brief SDFX symmetric encryption algorithm test program
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sdf.h"

#define MAX_BUFFER_SIZE 8192
#define TEST_DATA_SIZE 1024
#define SM4_KEY_SIZE 16
#define SM4_IV_SIZE 16

/* Test key - all zero key (consistent with openHiTLS demo) */
static const BYTE test_key[SM4_KEY_SIZE] = {0};

/* Test vector data - from openHiTLS demo */
static const BYTE test_data[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x1c, 0x14};
static const size_t test_data_len = sizeof(test_data);

/* Test IV - all zero IV (consistent with openHiTLS demo) */
static const BYTE test_iv[SM4_IV_SIZE] = {0};

/* Test data of different sizes */
static const char *test_strings[] = {
    "Hello, World!",
    "The quick brown fox jumps over the lazy dog",
    "SM4 is a block cipher algorithm published as a Chinese National Standard",
    "This is a longer test string to verify that the SM4 implementation can handle variable-length data with proper padding mechanisms."
};

static const size_t num_test_strings = sizeof(test_strings) / sizeof(test_strings[0]);

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

static int test_sm4_mode(HANDLE device_handle, HANDLE session_handle, 
                        ULONG alg_id, const char *mode_name, 
                        const BYTE *test_key, const BYTE *test_iv)
{
    printf("\n=== Testing SM4-%s mode ===\n", mode_name);
    
    BYTE encrypted_data[MAX_BUFFER_SIZE];
    BYTE decrypted_data[MAX_BUFFER_SIZE];
    ULONG encrypted_len, decrypted_len;
    LONG ret;
    int test_passed = 0;
    int total_tests = 0;
    
    for (size_t i = 0; i < num_test_strings; i++) {
        total_tests++;
        printf("\n--- Test string %zu: \"%s\" ---", i + 1, test_strings[i]);
        
        const BYTE *plaintext = (const BYTE*)test_strings[i];
        ULONG plaintext_len = strlen(test_strings[i]);
        
        print_hex("Original data", plaintext, plaintext_len);
        
        /* Encryption test */
        encrypted_len = sizeof(encrypted_data);
        ret = SDF_Encrypt(session_handle, NULL, alg_id, 
                         (BYTE*)test_iv, (BYTE*)plaintext, plaintext_len,
                         encrypted_data, &encrypted_len);
        
        if (ret != SDR_OK) {
            printf("❌ SDF_Encrypt failed: 0x%lx\n", ret);
            continue;
        }
        
        printf("✅ Encryption successful\n");
        print_hex("Ciphertext data", encrypted_data, encrypted_len);
        
        /* Decryption test */
        decrypted_len = sizeof(decrypted_data);
        ret = SDF_Decrypt(session_handle, NULL, alg_id,
                         (BYTE*)test_iv, encrypted_data, encrypted_len,
                         decrypted_data, &decrypted_len);
        
        if (ret != SDR_OK) {
            printf("❌ SDF_Decrypt failed: 0x%lx\n", ret);
            continue;
        }
        
        printf("✅ Decryption successful\n");
        print_hex("Decrypted data", decrypted_data, decrypted_len);
        
        /* Verify decryption result */
        if (decrypted_len == plaintext_len && 
            memcmp(decrypted_data, plaintext, plaintext_len) == 0) {
            printf("✅ Encryption/decryption verification correct\n");
            test_passed++;
        } else {
            printf("❌ Encryption/decryption verification failed\n");
            printf("Expected length: %lu, actual length: %lu\n", plaintext_len, decrypted_len);
        }
    }
    
    printf("\nSM4-%s mode test result: %d/%d passed\n", mode_name, test_passed, total_tests);
    return (test_passed == total_tests) ? 0 : -1;
}

static int test_sm4_demo_vector(HANDLE device_handle, HANDLE session_handle)
{
    printf("\n=== Testing openHiTLS Demo vectors ===\n");
    
    BYTE encrypted_data[MAX_BUFFER_SIZE];
    BYTE decrypted_data[MAX_BUFFER_SIZE];
    ULONG encrypted_len = sizeof(encrypted_data);
    ULONG decrypted_len = sizeof(decrypted_data);
    LONG ret;
    
    print_hex("Demo original data", test_data, test_data_len);
    print_hex("Demo key", test_key, SM4_KEY_SIZE);
    print_hex("Demo IV", test_iv, SM4_IV_SIZE);
    
    /* Use SM4-CBC mode to encrypt demo data */
    ret = SDF_Encrypt(session_handle, NULL, SGD_SM4_CBC,
                     (BYTE*)test_iv, (BYTE*)test_data, test_data_len,
                     encrypted_data, &encrypted_len);
    
    if (ret != SDR_OK) {
        printf("❌ Demo vector encryption failed: 0x%lx\n", ret);
        return -1;
    }
    
    printf("✅ Demo vector encryption successful\n");
    print_hex("Demo ciphertext", encrypted_data, encrypted_len);
    
    /* Decrypt and verify */
    ret = SDF_Decrypt(session_handle, NULL, SGD_SM4_CBC,
                     (BYTE*)test_iv, encrypted_data, encrypted_len,
                     decrypted_data, &decrypted_len);
    
    if (ret != SDR_OK) {
        printf("❌ Demo vector decryption failed: 0x%lx\n", ret);
        return -1;
    }
    
    printf("✅ Demo vector decryption successful\n");
    print_hex("Demo decrypted result", decrypted_data, decrypted_len);
    
    /* Verify result */
    if (decrypted_len == test_data_len &&
        memcmp(decrypted_data, test_data, test_data_len) == 0) {
        printf("✅ Demo vector verification correct\n");
        return 0;
    } else {
        printf("❌ Demo vector verification failed\n");
        return -1;
    }
}

static int test_large_data_encryption(HANDLE device_handle, HANDLE session_handle)
{
    printf("\n=== Testing large data encryption process ===\n");
    
    /* Generate large test data */
    BYTE *large_data = malloc(TEST_DATA_SIZE);
    if (large_data == NULL) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    /* Fill test data */
    for (int i = 0; i < TEST_DATA_SIZE; i++) {
        large_data[i] = (BYTE)(i & 0xFF);
    }
    
    BYTE *encrypted_data = malloc(TEST_DATA_SIZE + 64); // Reserve padding space
    BYTE *decrypted_data = malloc(TEST_DATA_SIZE + 64);
    
    if (encrypted_data == NULL || decrypted_data == NULL) {
        printf("❌ Memory allocation failed\n");
        free(large_data);
        if (encrypted_data) free(encrypted_data);
        if (decrypted_data) free(decrypted_data);
        return -1;
    }
    
    ULONG encrypted_len = TEST_DATA_SIZE + 64;
    ULONG decrypted_len = TEST_DATA_SIZE + 64;
    
    printf("Processing %d bytes of data\n", TEST_DATA_SIZE);
    
    /* Encrypt large data */
    LONG ret = SDF_Encrypt(session_handle, NULL, SGD_SM4_CBC,
                          (BYTE*)test_iv, large_data, TEST_DATA_SIZE,
                          encrypted_data, &encrypted_len);
    
    if (ret != SDR_OK) {
        printf("❌ Large data encryption failed: 0x%lx\n", ret);
        goto cleanup;
    }
    
    printf("✅ Large data encryption successful, ciphertext length: %lu bytes\n", encrypted_len);
    
    /* Decrypt and verify */
    ret = SDF_Decrypt(session_handle, NULL, SGD_SM4_CBC,
                     (BYTE*)test_iv, encrypted_data, encrypted_len,
                     decrypted_data, &decrypted_len);
    
    if (ret != SDR_OK) {
        printf("❌ Large data decryption failed: 0x%lx\n", ret);
        goto cleanup;
    }
    
    printf("✅ Large data decryption successful, plaintext length: %lu bytes\n", decrypted_len);
    
    /* Verify result */
    if (decrypted_len == TEST_DATA_SIZE &&
        memcmp(decrypted_data, large_data, TEST_DATA_SIZE) == 0) {
        printf("✅ Large data encryption/decryption verification correct\n");
        ret = 0;
    } else {
        printf("❌ Large data encryption/decryption verification failed\n");
        printf("Expected length: %d, actual length: %lu\n", TEST_DATA_SIZE, decrypted_len);
        ret = -1;
    }
    
cleanup:
    free(large_data);
    free(encrypted_data);
    free(decrypted_data);
    return ret;
}

static int test_edge_cases(HANDLE device_handle, HANDLE session_handle)
{
    printf("\n=== Testing boundary conditions ===\n");
    
    BYTE encrypted_data[MAX_BUFFER_SIZE];
    BYTE decrypted_data[MAX_BUFFER_SIZE];
    ULONG encrypted_len, decrypted_len;
    LONG ret;
    int tests_passed = 0;
    int total_tests = 0;
    
    /* Test 1: Single byte data */
    total_tests++;
    printf("\n--- Testing single byte data ---");
    BYTE single_byte = 0x42;
    
    encrypted_len = sizeof(encrypted_data);
    ret = SDF_Encrypt(session_handle, NULL, SGD_SM4_CBC,
                     (BYTE*)test_iv, &single_byte, 1,
                     encrypted_data, &encrypted_len);
    
    if (ret == SDR_OK) {
        decrypted_len = sizeof(decrypted_data);
        ret = SDF_Decrypt(session_handle, NULL, SGD_SM4_CBC,
                         (BYTE*)test_iv, encrypted_data, encrypted_len,
                         decrypted_data, &decrypted_len);
        
        if (ret == SDR_OK && decrypted_len == 1 && decrypted_data[0] == single_byte) {
            printf("✅ Single byte data test passed\n");
            tests_passed++;
        } else {
            printf("❌ Single byte data decryption verification failed\n");
        }
    } else {
        printf("❌ Single byte data encryption failed: 0x%lx\n", ret);
    }
    
    /* Test 2: Block size aligned data (16 bytes) */
    total_tests++;
    printf("\n--- Testing block size aligned data ---");
    BYTE block_data[16];
    for (int i = 0; i < 16; i++) {
        block_data[i] = (BYTE)i;
    }
    
    encrypted_len = sizeof(encrypted_data);
    ret = SDF_Encrypt(session_handle, NULL, SGD_SM4_CBC,
                     (BYTE*)test_iv, block_data, 16,
                     encrypted_data, &encrypted_len);
    
    if (ret == SDR_OK) {
        decrypted_len = sizeof(decrypted_data);
        ret = SDF_Decrypt(session_handle, NULL, SGD_SM4_CBC,
                         (BYTE*)test_iv, encrypted_data, encrypted_len,
                         decrypted_data, &decrypted_len);
        
        if (ret == SDR_OK && decrypted_len == 16 && 
            memcmp(decrypted_data, block_data, 16) == 0) {
            printf("✅ Block size aligned data test passed\n");
            tests_passed++;
        } else {
            printf("❌ Block size aligned data decryption verification failed\n");
        }
    } else {
        printf("❌ Block size aligned data encryption failed: 0x%lx\n", ret);
    }
    
    /* Test 3: ECB mode (no IV) */
    total_tests++;
    printf("\n--- Testing ECB mode (no IV) ---");
    const char *ecb_test = "ECB mode test data!";
    
    encrypted_len = sizeof(encrypted_data);
    ret = SDF_Encrypt(session_handle, NULL, SGD_SM4_ECB,
                     NULL, (BYTE*)ecb_test, strlen(ecb_test),
                     encrypted_data, &encrypted_len);
    
    if (ret == SDR_OK) {
        decrypted_len = sizeof(decrypted_data);
        ret = SDF_Decrypt(session_handle, NULL, SGD_SM4_ECB,
                         NULL, encrypted_data, encrypted_len,
                         decrypted_data, &decrypted_len);
        
        if (ret == SDR_OK && decrypted_len == strlen(ecb_test) &&
            memcmp(decrypted_data, ecb_test, strlen(ecb_test)) == 0) {
            printf("✅ ECB mode test passed\n");
            tests_passed++;
        } else {
            printf("❌ ECB mode decryption verification failed\n");
        }
    } else {
        printf("❌ ECB mode encryption failed: 0x%lx\n", ret);
    }
    
    printf("\nBoundary condition test result: %d/%d passed\n", tests_passed, total_tests);
    return (tests_passed == total_tests) ? 0 : -1;
}

int main()
{
    printf("SDFX symmetric encryption algorithm test\n");
    printf("====================\n");
    
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
    
    /* Run tests */
    int test_result = 0;
    
    /* Test openHiTLS demo vectors */
    if (test_sm4_demo_vector(device_handle, session_handle) != 0) {
        test_result = 1;
    }
    
    /* Test various SM4 modes */
    struct {
        ULONG alg_id;
        const char *name;
        int requires_iv;
    } sm4_modes[] = {
        {SGD_SM4_ECB, "ECB", 0},
        {SGD_SM4_CBC, "CBC", 1},
        {SGD_SM4_CFB, "CFB", 1},
        {SGD_SM4_OFB, "OFB", 1},
        {SGD_SM4_CTR, "CTR", 1}
    };
    
    for (size_t i = 0; i < sizeof(sm4_modes) / sizeof(sm4_modes[0]); i++) {
        const BYTE *iv = sm4_modes[i].requires_iv ? test_iv : NULL;
        if (test_sm4_mode(device_handle, session_handle, 
                         sm4_modes[i].alg_id, sm4_modes[i].name,
                         test_key, iv) != 0) {
            test_result = 1;
        }
    }
    
    /* Test large data processing */
    if (test_large_data_encryption(device_handle, session_handle) != 0) {
        test_result = 1;
    }
    
    /* Test boundary conditions */
    if (test_edge_cases(device_handle, session_handle) != 0) {
        test_result = 1;
    }
    
    /* Cleanup resources */
    SDF_CloseSession(session_handle);
    SDF_CloseDevice(device_handle);
    
    printf("\n=== Test summary ===\n");
    if (test_result == 0) {
        printf("🎉 All symmetric encryption algorithm tests passed!\n");
    } else {
        printf("❌ Some symmetric encryption algorithm tests failed!\n");
    }
    
    return test_result;
}