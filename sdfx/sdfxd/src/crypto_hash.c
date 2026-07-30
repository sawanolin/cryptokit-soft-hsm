/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file crypto_hash.c
 * @brief Hash algorithm implementation using openHiTLS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon_internal.h"
#include "hitls_init.h"
#include "hitls/crypto/crypt_eal_md.h"
#include "hitls/crypto/crypt_algid.h"
#include "hitls/crypto/crypt_errno.h"

/**
 * @brief Check hash module initialization status
 */
static int hash_crypto_engine_check(void)
{
    if (!sdfx_hitls_is_initialized()) {
        LOG_ERROR("openHiTLS library not initialized for hash operations");
        return -1;
    }
    return 0;
}

/**
 * @brief SDF algorithm ID to openHiTLS algorithm ID mapping
 */
static CRYPT_MD_AlgId sdf_to_hitls_hash_alg(ULONG sdf_alg_id)
{
    switch (sdf_alg_id) {
        case SGD_SM3:
            return CRYPT_MD_SM3;
        case SGD_SHA1:
            return CRYPT_MD_SHA1;
        case SGD_SHA224:
            return CRYPT_MD_SHA224;
        case SGD_SHA256:
            return CRYPT_MD_SHA256;
        case SGD_SHA384:
            return CRYPT_MD_SHA384;
        case SGD_SHA512:
            return CRYPT_MD_SHA512;
        default:
            return CRYPT_MD_MAX;
    }
}

/**
 * @brief Hash initialization
 */
int crypto_hash_init(daemon_context_t *ctx, session_info_t *session, ULONG alg_id)
{
    if (ctx == NULL || session == NULL) {
        return SDR_INARGERR;
    }
    
    LOG_DEBUG("Initializing hash for algorithm: 0x%lx", (unsigned long)alg_id);
    
    /* Ensure hash engine is initialized */
    if (hash_crypto_engine_check() != 0) {
        LOG_ERROR("openHiTLS library not initialized for hash operations");
        return SDR_SYMOPERR;
    }
    
    /* Cleanup existing hash context */
    if (session->hash_ctx != NULL) {
        CRYPT_EAL_MdFreeCtx((CRYPT_EAL_MdCTX *)session->hash_ctx);
        session->hash_ctx = NULL;
    }
    
    /* Map algorithm ID */
    CRYPT_MD_AlgId hitls_alg = sdf_to_hitls_hash_alg(alg_id);
    if (hitls_alg == CRYPT_MD_MAX) {
        LOG_ERROR("Unsupported hash algorithm: 0x%lx", (unsigned long)alg_id);
        return SDR_ALGNOTSUPPORT;
    }
    
    /* Create hash context */
    CRYPT_EAL_MdCTX *md_ctx = CRYPT_EAL_MdNewCtx(hitls_alg);
    if (md_ctx == NULL) {
        LOG_ERROR("Failed to create hash context for algorithm: 0x%lx", (unsigned long)alg_id);
        return SDR_NOBUFFER;
    }
    
    /* Initialize hash context */
    int32_t ret = CRYPT_EAL_MdInit(md_ctx);
    if (ret != CRYPT_SUCCESS) {
        LOG_ERROR("Failed to initialize hash context: 0x%x", ret);
        CRYPT_EAL_MdFreeCtx(md_ctx);
        return SDR_SYMOPERR;
    }
    
    session->hash_ctx = md_ctx;
    LOG_DEBUG("Hash initialized successfully for algorithm: 0x%lx using openHiTLS", (unsigned long)alg_id);
    return SDR_OK;
}

/**
 * @brief Hash update
 */
int crypto_hash_update(daemon_context_t *ctx, session_info_t *session, 
                      const BYTE *data, ULONG data_len)
{
    if (ctx == NULL || session == NULL || data == NULL || data_len == 0) {
        return SDR_INARGERR;
    }
    
    if (session->hash_ctx == NULL) {
        LOG_ERROR("Hash context not initialized");
        return SDR_STEPERR;
    }
    
    CRYPT_EAL_MdCTX *md_ctx = (CRYPT_EAL_MdCTX *)session->hash_ctx;
    
    int32_t ret = CRYPT_EAL_MdUpdate(md_ctx, data, data_len);
    if (ret != CRYPT_SUCCESS) {
        LOG_ERROR("Failed to update hash: 0x%x", ret);
        return SDR_SYMOPERR;
    }
    
    LOG_DEBUG("Hash updated with %lu bytes using openHiTLS", (unsigned long)data_len);
    return SDR_OK;
}

/**
 * @brief Hash finalization
 */
int crypto_hash_final(daemon_context_t *ctx, session_info_t *session,
                     BYTE *hash, ULONG *hash_len)
{
    if (ctx == NULL || session == NULL || hash == NULL || hash_len == NULL) {
        return SDR_INARGERR;
    }
    
    if (session->hash_ctx == NULL) {
        LOG_ERROR("Hash context not initialized");
        return SDR_STEPERR;
    }
    
    CRYPT_EAL_MdCTX *md_ctx = (CRYPT_EAL_MdCTX *)session->hash_ctx;
    
    uint32_t output_len = *hash_len;
    int32_t ret = CRYPT_EAL_MdFinal(md_ctx, hash, &output_len);
    if (ret != CRYPT_SUCCESS) {
        LOG_ERROR("Failed to finalize hash: 0x%x", ret);
        return SDR_SYMOPERR;
    }
    
    *hash_len = output_len;
    
    /* Cleanup hash context */
    CRYPT_EAL_MdFreeCtx(md_ctx);
    session->hash_ctx = NULL;
    
    LOG_DEBUG("Hash finalized using openHiTLS, output length: %lu", (unsigned long)*hash_len);
    return SDR_OK;
}

/**
 * @brief One-time hash calculation
 */
int crypto_hash_digest(ULONG alg_id, const BYTE *data, ULONG data_len,
                      BYTE *hash, ULONG *hash_len)
{
    if (data == NULL || data_len == 0 || hash == NULL || hash_len == NULL) {
        return SDR_INARGERR;
    }
    
    LOG_DEBUG("Computing hash digest for algorithm: 0x%lx, data length: %lu", 
             (unsigned long)alg_id, (unsigned long)data_len);
    
    /* Ensure hash engine is initialized */
    if (hash_crypto_engine_check() != 0) {
        LOG_ERROR("openHiTLS library not initialized for hash operations");
        return SDR_SYMOPERR;
    }
    
    /* Map algorithm ID */
    CRYPT_MD_AlgId hitls_alg = sdf_to_hitls_hash_alg(alg_id);
    if (hitls_alg == CRYPT_MD_MAX) {
        LOG_ERROR("Unsupported hash algorithm: 0x%lx", (unsigned long)alg_id);
        return SDR_ALGNOTSUPPORT;
    }
    
    uint32_t output_len = *hash_len;
    int32_t ret = CRYPT_EAL_Md(hitls_alg, data, data_len, hash, &output_len);
    if (ret != CRYPT_SUCCESS) {
        LOG_ERROR("Failed to compute hash: 0x%x", ret);
        return SDR_SYMOPERR;
    }
    
    *hash_len = output_len;
    LOG_DEBUG("Hash computed using openHiTLS, algorithm: 0x%lx, output length: %lu", 
             (unsigned long)alg_id, (unsigned long)*hash_len);
    return SDR_OK;
}