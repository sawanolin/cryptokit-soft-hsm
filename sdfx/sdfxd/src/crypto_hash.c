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

int crypto_hash_init_sm2_preprocess(daemon_context_t *ctx, session_info_t *session,
                                    const ECCrefPublicKey *public_key,
                                    const BYTE *id, ULONG id_len)
{
    static const BYTE sm2_curve_parameters[] = {
        /* a */
        0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc,
        /* b */
        0x28,0xe9,0xfa,0x9e,0x9d,0x9f,0x5e,0x34,0x4d,0x5a,0x9e,0x4b,0xcf,0x65,0x09,0xa7,
        0xf3,0x97,0x89,0xf5,0x15,0xab,0x8f,0x92,0xdd,0xbc,0xbd,0x41,0x4d,0x94,0x0e,0x93,
        /* xG */
        0x32,0xc4,0xae,0x2c,0x1f,0x19,0x81,0x19,0x5f,0x99,0x04,0x46,0x6a,0x39,0xc9,0x94,
        0x8f,0xe3,0x0b,0xbf,0xf2,0x66,0x0b,0xe1,0x71,0x5a,0x45,0x89,0x33,0x4c,0x74,0xc7,
        /* yG */
        0xbc,0x37,0x36,0xa2,0xf4,0xf6,0x77,0x9c,0x59,0xbd,0xce,0xe3,0x6b,0x69,0x21,0x53,
        0xd0,0xa9,0x87,0x7c,0xc6,0x2a,0x47,0x40,0x02,0xdf,0x32,0xe5,0x21,0x39,0xf0,0xa0
    };
    BYTE entl[2];
    BYTE z_digest[32] = {0};
    uint32_t z_length = sizeof(z_digest);
    CRYPT_EAL_MdCTX *z_ctx = NULL;
    CRYPT_EAL_MdCTX *message_ctx;
    int32_t hitls_ret;
    int ret;

    if (ctx == NULL || session == NULL || public_key == NULL || id == NULL ||
        id_len == 0 || id_len > SDFX_MAX_SM2_ID_LENGTH) {
        return SDR_INARGERR;
    }
    ret = crypto_sm2_validate_public_key(public_key);
    if (ret != SDR_OK) {
        return ret;
    }
    if (hash_crypto_engine_check() != 0) {
        return SDR_SYMOPERR;
    }

    entl[0] = (BYTE)((id_len * 8U) >> 8);
    entl[1] = (BYTE)(id_len * 8U);
    z_ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    if (z_ctx == NULL) {
        return SDR_NOBUFFER;
    }
    hitls_ret = CRYPT_EAL_MdInit(z_ctx);
    if (hitls_ret == CRYPT_SUCCESS) hitls_ret = CRYPT_EAL_MdUpdate(z_ctx, entl, sizeof(entl));
    if (hitls_ret == CRYPT_SUCCESS) hitls_ret = CRYPT_EAL_MdUpdate(z_ctx, id, id_len);
    if (hitls_ret == CRYPT_SUCCESS) hitls_ret = CRYPT_EAL_MdUpdate(z_ctx,
        sm2_curve_parameters, sizeof(sm2_curve_parameters));
    if (hitls_ret == CRYPT_SUCCESS) hitls_ret = CRYPT_EAL_MdUpdate(z_ctx,
        public_key->x + ECCref_MAX_LEN - 32, 32);
    if (hitls_ret == CRYPT_SUCCESS) hitls_ret = CRYPT_EAL_MdUpdate(z_ctx,
        public_key->y + ECCref_MAX_LEN - 32, 32);
    if (hitls_ret == CRYPT_SUCCESS) hitls_ret = CRYPT_EAL_MdFinal(z_ctx,
        z_digest, &z_length);
    CRYPT_EAL_MdFreeCtx(z_ctx);
    if (hitls_ret != CRYPT_SUCCESS || z_length != sizeof(z_digest)) {
        memset(z_digest, 0, sizeof(z_digest));
        LOG_ERROR("Failed to compute SM2 Z digest: 0x%x", hitls_ret);
        return SDR_SYMOPERR;
    }

    /* GM/T 0018 initializes the message digest as H(Z || M), not H(Z-input || M). */
    ret = crypto_hash_init(ctx, session, SGD_SM3);
    if (ret != SDR_OK) {
        memset(z_digest, 0, sizeof(z_digest));
        return ret;
    }
    message_ctx = (CRYPT_EAL_MdCTX *)session->hash_ctx;
    hitls_ret = CRYPT_EAL_MdUpdate(message_ctx, z_digest, z_length);
    memset(z_digest, 0, sizeof(z_digest));
    if (hitls_ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(message_ctx);
        session->hash_ctx = NULL;
        LOG_ERROR("Failed to initialize SM2 message digest with Z: 0x%x", hitls_ret);
        return SDR_SYMOPERR;
    }

    LOG_DEBUG("SM2 Z preprocessing initialized, identity length: %lu",
              (unsigned long)id_len);
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