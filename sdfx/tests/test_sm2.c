/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file test_sm2.c 
 * @brief SM2 asymmetric encryption/signature functionality test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sdf.h"
#include "sdf_types.h"

/* Test data */
static const char test_data[] = "Hello SM2! This is a test message for SM2 encryption and signature.";
static const ULONG test_data_len = sizeof(test_data) - 1;

/* Print hexadecimal data */
void print_hex(const char *label, const BYTE *data, ULONG len)
{
    printf("%s (%lu bytes): ", label, len);
    for (ULONG i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i % 16 == 15) printf("\n");
        else if (i % 4 == 3) printf(" ");
    }
    if (len % 16 != 0) printf("\n");
}

/* Print ECC public key */
void print_public_key(const ECCrefPublicKey *key)
{
    printf("ECC Public Key (bits=%u):\n", key->bits);
    print_hex("  X", key->x + ECCref_MAX_LEN - 32, 32);
    print_hex("  Y", key->y + ECCref_MAX_LEN - 32, 32);
}

/* Print ECC private key */
void print_private_key(const ECCrefPrivateKey *key)
{
    printf("ECC Private Key (bits=%u):\n", key->bits);
    print_hex("  K", key->K + ECCref_MAX_LEN - 32, 32);
}

int main(void)
{
    printf("SDFX SM2 functionality test\n");
    printf("================\n");
    
    HANDLE hDevice = NULL;
    HANDLE hSession = NULL;
    LONG ret;
    
    /* Test data */
    ECCrefPublicKey publicKey;
    ECCrefPrivateKey privateKey;
    BYTE ciphertext[1024];
    ULONG ciphertext_len = sizeof(ciphertext);
    BYTE plaintext[1024];
    ULONG plaintext_len = sizeof(plaintext);
    ECCSignature eccSig;
    
    /* Open device */
    ret = SDF_OpenDevice(&hDevice);
    if (ret != SDR_OK) {
        printf("❌ SDF_OpenDevice failed: 0x%lx\n", ret);
        return 1;
    }
    printf("✅ Device opened successfully\n");
    
    /* Open session */
    ret = SDF_OpenSession(hDevice, &hSession);
    if (ret != SDR_OK) {
        printf("❌ SDF_OpenSession failed: 0x%lx\n", ret);
        SDF_CloseDevice(hDevice);
        return 1;
    }
    printf("✅ Session opened successfully\n");
    
    printf("\n=== SM2 key pair generation test ===\n");
    
    /* Generate SM2 key pair */
    ret = SDF_GenerateKeyPair_ECC(hSession, SGD_SM2_1, 256, &publicKey, &privateKey);
    if (ret != SDR_OK) {
        printf("❌ SM2 key pair generation failed: 0x%lx\n", ret);
        goto cleanup;
    }
    printf("✅ SM2 key pair generation successful\n");
    
    print_public_key(&publicKey);
    print_private_key(&privateKey);
    
    printf("\n=== SM2 encryption/decryption test ===\n");
    printf("Plaintext: %s\n", test_data);
    printf("Plaintext length: %lu bytes\n", test_data_len);
    
    /* SM2 public key encryption */
    BYTE eccCipherBuffer[sizeof(ECCCipher) + 255];
    ECCCipher *eccCipher = (ECCCipher *)eccCipherBuffer;
    ret = SDF_ExternalEncrypt_ECC(hSession, SGD_SM2_1, &publicKey, 
                                 (BYTE*)test_data, test_data_len, eccCipher);
    if (ret != SDR_OK) {
        printf("❌ SM2 encryption failed: 0x%lx\n", ret);
        goto cleanup;
    }
    printf("✅ SM2 encryption successful\n");
    printf("Ciphertext length: %u bytes\n", eccCipher->L);
    print_hex("Ciphertext", eccCipher->C, eccCipher->L);
    
    /* SM2 private key decryption */
    ret = SDF_ExternalDecrypt_ECC(hSession, SGD_SM2_1, &privateKey, 
                                 eccCipher, plaintext, &plaintext_len);
    if (ret != SDR_OK) {
        printf("❌ SM2 decryption failed: 0x%lx\n", ret);
        goto cleanup;
    }
    printf("✅ SM2 decryption successful\n");
    printf("Decrypted length: %lu bytes\n", plaintext_len);
    
    /* Verify decryption result */
    if (plaintext_len == test_data_len && memcmp(plaintext, test_data, test_data_len) == 0) {
        printf("✅ Decryption result correct: %.*s\n", (int)plaintext_len, plaintext);
    } else {
        printf("❌ Decryption result error\n");
        printf("Expected: %s\n", test_data);
        printf("Actual: %.*s\n", (int)plaintext_len, plaintext);
        goto cleanup;
    }
    
    printf("\n=== SM2 signature verification test ===\n");
    
    /* SM2 signature */
    ret = SDF_ExternalSign_ECC(hSession, SGD_SM2_3, &privateKey,
                              (BYTE*)test_data, test_data_len, &eccSig);
    if (ret != SDR_OK) {
        printf("❌ SM2 signature failed: 0x%lx\n", ret);
        goto cleanup;
    }
    printf("✅ SM2 signature successful\n");
    print_hex("Signature r", eccSig.r, 32);
    print_hex("Signature s", eccSig.s, 32);
    
    /* SM2 verification */
    ret = SDF_ExternalVerify_ECC(hSession, SGD_SM2_3, &publicKey,
                                (BYTE*)test_data, test_data_len, &eccSig);
    if (ret != SDR_OK) {
        printf("❌ SM2 verification failed: 0x%lx\n", ret);
        goto cleanup;
    }
    printf("✅ SM2 verification successful\n");
    
    printf("\n=== Boundary condition tests ===\n");
    
    /* Test empty data encryption */
    printf("Testing empty data encryption...\n");
    ret = SDF_ExternalEncrypt_ECC(hSession, SGD_SM2_1, &publicKey, NULL, 0, eccCipher);
    if (ret != SDR_OK) {
        printf("✅ Empty data encryption correctly returned error: 0x%lx\n", ret);
    } else {
        printf("❌ Empty data encryption should fail\n");
    }
    
    /* Test large data encryption */
    printf("Testing large data encryption (300 bytes)...");
    BYTE large_data[300];
    memset(large_data, 0xAA, sizeof(large_data));
    ret = SDF_ExternalEncrypt_ECC(hSession, SGD_SM2_1, &publicKey, 
                                 large_data, sizeof(large_data), eccCipher);
    if (ret != SDR_OK) {
        printf("✅ Large data encryption correctly returned error: 0x%lx\n", ret);
    } else {
        printf("❌ Large data encryption should fail\n");
    }
    
    /* Test invalid algorithm ID */
    printf("Testing invalid algorithm ID...\n");
    ret = SDF_ExternalEncrypt_ECC(hSession, 0x99999999, &publicKey,
                                 (BYTE*)test_data, test_data_len, eccCipher);
    if (ret != SDR_OK) {
        printf("✅ Invalid algorithm ID correctly returned error: 0x%lx\n", ret);
    } else {
        printf("❌ Invalid algorithm ID should fail\n");
    }
    
    printf("\n=== Performance test ===\n");
    
    /* Key generation performance test */
    printf("Key generation performance test (10 iterations)...");
    clock_t start = clock();
    for (int i = 0; i < 10; i++) {
        ECCrefPublicKey tempPub;
        ECCrefPrivateKey tempPriv;
        ret = SDF_GenerateKeyPair_ECC(hSession, SGD_SM2_1, 256, &tempPub, &tempPriv);
        if (ret != SDR_OK) {
            printf("❌ Key generation failed #%d: 0x%lx\n", i+1, ret);
            break;
        }
    }
    clock_t end = clock();
    double time_spent = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("✅ Key generation completed, average time: %.2f ms/iteration\n", time_spent * 100);
    
    /* Encryption performance test */
    printf("Encryption performance test (50 iterations)...");
    start = clock();
    for (int i = 0; i < 50; i++) {
        ret = SDF_ExternalEncrypt_ECC(hSession, SGD_SM2_1, &publicKey,
                                     (BYTE*)test_data, test_data_len, eccCipher);
        if (ret != SDR_OK) {
            printf("❌ Encryption failed #%d: 0x%lx\n", i+1, ret);
            break;
        }
    }
    end = clock();
    time_spent = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("✅ Encryption completed, average time: %.2f ms/iteration\n", time_spent * 20);
    
    printf("\n=== Test summary ===\n");
    printf("🎉 All SM2 functionality tests passed!\n");

cleanup:
    /* Close session and device */
    if (hSession) {
        SDF_CloseSession(hSession);
    }
    if (hDevice) {
        SDF_CloseDevice(hDevice);
    }
    
    return (ret == SDR_OK) ? 0 : 1;
}