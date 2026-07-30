/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file crypto_random.c
 * @brief Random number generation implementation using openHiTLS DRBG
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "daemon_internal.h"
#include "hitls_init.h"
#include "hitls/crypto/crypt_eal_rand.h"
#include "hitls/crypto/crypt_algid.h"
#include "hitls/crypto/crypt_errno.h"

/**
 * @brief Check crypto engine initialization status
 */
static int crypto_engine_check(void)
{
    if (!sdfx_hitls_is_initialized()) {
        LOG_ERROR("openHiTLS library not initialized");
        return -1;
    }
    return 0;
}


int crypto_generate_random(uint32_t length, BYTE *output)
{
    if (output == NULL || length == 0) {
        return SDR_INARGERR;
    }
    
    LOG_DEBUG("Generating %u bytes of random data using openHiTLS", length);
    
    /* Ensure crypto engine is initialized */
    if (crypto_engine_check() != 0) {
        LOG_ERROR("openHiTLS library not initialized");
        return SDR_RANDERR;
    }
    
    /* Use openHiTLS DRBG to generate random numbers */
    int ret = CRYPT_EAL_RandbytesEx(NULL, output, length);
    if (ret != CRYPT_SUCCESS) {
        LOG_ERROR("CRYPT_EAL_RandbytesEx failed: 0x%x", ret);
        return SDR_RANDERR;
    }
    
    LOG_DEBUG("Generated %u bytes of random data successfully using openHiTLS DRBG", length);
    return SDR_OK;
}