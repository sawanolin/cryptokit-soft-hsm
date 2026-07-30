/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file crypto_symmetric.c
 * @brief Symmetric encryption implementation using openHiTLS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon_internal.h"
#include "hitls/crypto/crypt_eal_cipher.h"
#include "hitls/crypto/crypt_algid.h"
#include "hitls/crypto/crypt_errno.h"
#include "hitls/bsl/bsl_sal.h"
#include "hitls/bsl/bsl_err.h"

/* Global crypto engine initialization status */
static bool g_crypto_engine_initialized = false;

/**
 * @brief Standard memory allocation function
 */
void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

/**
 * @brief Print the last error
 */
void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    LOG_ERROR("openHiTLS error at %s:%u", file ? file : "unknown", line);
}

/**
 * @brief Initialize crypto engine
 */
int crypto_engine_init(void) {
    if (g_crypto_engine_initialized) {
        return 0; // Already initialized
    }

    // Initialize error code module
    BSL_ERR_Init();

    // Register memory management functions
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);

    g_crypto_engine_initialized = true;
    LOG_INFO("Crypto engine initialized successfully");
    return 0;
}

/**
 * @brief Cleanup crypto engine
 */
void crypto_engine_cleanup(void) {
    if (g_crypto_engine_initialized) {
        BSL_ERR_DeInit();
        g_crypto_engine_initialized = false;
        LOG_INFO("Crypto engine cleaned up");
    }
}

/**
 * @brief SDF algorithm ID to openHiTLS algorithm ID mapping
 */
static CRYPT_CIPHER_AlgId sdf_to_hitls_cipher_alg(ULONG sdf_alg_id)
{
    switch (sdf_alg_id) {
        case SGD_SM4_ECB:
            return CRYPT_CIPHER_SM4_ECB;
        case SGD_SM4_CBC:
            return CRYPT_CIPHER_SM4_CBC;
        case SGD_SM4_CFB:
            return CRYPT_CIPHER_SM4_CFB;
        case SGD_SM4_OFB:
            return CRYPT_CIPHER_SM4_OFB;
        case SGD_SM4_CTR:
            return CRYPT_CIPHER_SM4_CTR;
        case SGD_SM4_GCM:
            return CRYPT_CIPHER_SM4_GCM;
        default:
            return CRYPT_CIPHER_MAX;
    }
}

/**
 * @brief Symmetric encryption
 */
int crypto_symmetric_encrypt(ULONG alg_id, const BYTE *key, ULONG key_len,
                            const BYTE *iv, ULONG iv_len,
                            const BYTE *plaintext, ULONG plaintext_len,
                            BYTE *ciphertext, ULONG *ciphertext_len)
{
    if (key == NULL || plaintext == NULL || ciphertext == NULL || ciphertext_len == NULL) {
        return SDR_INARGERR;
    }
    
    if (key_len != 16 ||
        ((alg_id == SGD_SM4_ECB || alg_id == SGD_SM4_CBC) && (plaintext_len % 16) != 0)) {
        return SDR_INARGERR;
    }
    /* Ensure crypto engine is initialized */
    if (!g_crypto_engine_initialized) {
        int ret = crypto_engine_init();
        if (ret != 0) {
            LOG_ERROR("Failed to initialize crypto engine");
            return SDR_SYMOPERR;
        }
    }
    
    /* Map algorithm ID */
    CRYPT_CIPHER_AlgId hitls_alg = sdf_to_hitls_cipher_alg(alg_id);
    if (hitls_alg == CRYPT_CIPHER_MAX) {
        LOG_ERROR("Unsupported cipher algorithm: 0x%lx", (unsigned long)alg_id);
        return SDR_ALGNOTSUPPORT;
    }
    
    /* Create encryption context */
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(hitls_alg);
    if (ctx == NULL) {
        LOG_ERROR("Failed to create cipher context");
        PrintLastError();
        return SDR_NOBUFFER;
    }
    
    /* Initialize encryption context */
    int32_t ret = CRYPT_EAL_CipherInit(ctx, key, key_len, iv, iv_len, true); /* true for encryption */
    if (ret != CRYPT_SUCCESS) {
        LOG_ERROR("Failed to initialize cipher context: %d", ret);
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return SDR_SYMOPERR;
    }
    
    
    /* Perform encryption */
    uint32_t output_len = *ciphertext_len;
    uint32_t final_len = 0;
    
    ret = CRYPT_EAL_CipherUpdate(ctx, plaintext, plaintext_len, ciphertext, &output_len);
    if (ret != CRYPT_SUCCESS) {
        LOG_ERROR("Failed to encrypt data: %d", ret);
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return SDR_SYMOPERR;
    }
    
    /* Finalize encryption */
    if (*ciphertext_len >= output_len) {
        final_len = *ciphertext_len - output_len;
        ret = CRYPT_EAL_CipherFinal(ctx, ciphertext + output_len, &final_len);
        if (ret != CRYPT_SUCCESS) {
            LOG_ERROR("Failed to finalize encryption: %d", ret);
            PrintLastError();
            CRYPT_EAL_CipherFreeCtx(ctx);
            return SDR_SYMOPERR;
        }
    }
    
    *ciphertext_len = output_len + final_len;
    
    /* Cleanup context */
    CRYPT_EAL_CipherFreeCtx(ctx);
    
    LOG_DEBUG("Symmetric encryption completed, algorithm: 0x%lx, input: %lu bytes, output: %lu bytes",
             (unsigned long)alg_id, (unsigned long)plaintext_len, (unsigned long)*ciphertext_len);
    return SDR_OK;
}

/**
 * @brief Symmetric decryption
 */
int crypto_symmetric_decrypt(ULONG alg_id, const BYTE *key, ULONG key_len,
                            const BYTE *iv, ULONG iv_len,
                            const BYTE *ciphertext, ULONG ciphertext_len,
                            BYTE *plaintext, ULONG *plaintext_len)
{
    if (key == NULL || ciphertext == NULL || plaintext == NULL || plaintext_len == NULL) {
        return SDR_INARGERR;
    }
    if (key_len != 16 ||
        ((alg_id == SGD_SM4_ECB || alg_id == SGD_SM4_CBC) && (ciphertext_len % 16) != 0)) {
        return SDR_INARGERR;
    }
    
    /* Ensure crypto engine is initialized */
    if (!g_crypto_engine_initialized) {
        int ret = crypto_engine_init();
        if (ret != 0) {
            LOG_ERROR("Failed to initialize crypto engine");
            return SDR_SYMOPERR;
        }
    }
    
    /* Map algorithm ID */
    CRYPT_CIPHER_AlgId hitls_alg = sdf_to_hitls_cipher_alg(alg_id);
    if (hitls_alg == CRYPT_CIPHER_MAX) {
        LOG_ERROR("Unsupported cipher algorithm: 0x%lx", (unsigned long)alg_id);
        return SDR_ALGNOTSUPPORT;
    }
    
    /* Create decryption context */
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(hitls_alg);
    if (ctx == NULL) {
        LOG_ERROR("Failed to create cipher context");
        PrintLastError();
        return SDR_NOBUFFER;
    }
    
    /* Initialize decryption context */
    int32_t ret = CRYPT_EAL_CipherInit(ctx, key, key_len, iv, iv_len, false); /* false for decryption */
    if (ret != CRYPT_SUCCESS) {
        LOG_ERROR("Failed to initialize cipher context: %d", ret);
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return SDR_SYMOPERR;
    }
    
    
    /* Perform decryption */
    uint32_t output_len = *plaintext_len;
    uint32_t final_len = 0;
    
    ret = CRYPT_EAL_CipherUpdate(ctx, ciphertext, ciphertext_len, plaintext, &output_len);
    if (ret != CRYPT_SUCCESS) {
        LOG_ERROR("Failed to decrypt data: %d", ret);
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return SDR_SYMOPERR;
    }
    
    /* Finalize decryption */
    if (*plaintext_len >= output_len) {
        final_len = *plaintext_len - output_len;
        ret = CRYPT_EAL_CipherFinal(ctx, plaintext + output_len, &final_len);
        if (ret != CRYPT_SUCCESS) {
            LOG_ERROR("Failed to finalize decryption: %d", ret);
            PrintLastError();
            CRYPT_EAL_CipherFreeCtx(ctx);
            return SDR_SYMOPERR;
        }
    }
    
    *plaintext_len = output_len + final_len;
    
    /* Cleanup context */
    CRYPT_EAL_CipherFreeCtx(ctx);
    
    LOG_DEBUG("Symmetric decryption completed, algorithm: 0x%lx, input: %lu bytes, output: %lu bytes",
             (unsigned long)alg_id, (unsigned long)ciphertext_len, (unsigned long)*plaintext_len);
    return SDR_OK;
}