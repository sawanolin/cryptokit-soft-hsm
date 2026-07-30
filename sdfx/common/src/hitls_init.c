/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file hitls_init.c
 * @brief Unified openHiTLS initialization implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#include "hitls_init.h"
#include "sdf_err.h"
#include "log.h"

/* openHiTLS headers */
#include "hitls/crypto/crypt_eal_init.h"
#include "hitls/crypto/crypt_eal_rand.h"
#include "hitls/crypto/crypt_errno.h"
#include "hitls/bsl/bsl_sal.h"
#include "hitls/bsl/bsl_err.h"

/* Global state */
static int g_hitls_initialized = 0;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Memory allocation function */
static void* sdfx_malloc(uint32_t len)
{
    return malloc((size_t)len);
}

int sdfx_hitls_init(void)
{
    int ret = SDR_OK;
    int32_t hitls_ret;
    
    pthread_mutex_lock(&g_init_mutex);
    
    /* Check if already initialized */
    if (g_hitls_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return SDR_OK;
    }
    
    LOG_INFO("Initializing openHiTLS library...");
    
    /* Initialize error module */
    BSL_ERR_Init();
    
    /* Register memory allocation functions */
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, sdfx_malloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
    
    /* Initialize openHiTLS core */
    hitls_ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
    if (hitls_ret != CRYPT_SUCCESS) {
        LOG_ERROR("CRYPT_EAL_Init failed: 0x%x", hitls_ret);
        ret = SDR_UNKNOWERR;
        goto cleanup;
    }
    
    /* Initialize random number generator */
    hitls_ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, 
                                               "provider=default", NULL, 0, NULL);
    if (hitls_ret != CRYPT_SUCCESS) {
        LOG_ERROR("CRYPT_EAL_ProviderRandInitCtx failed: 0x%x", hitls_ret);
        ret = SDR_RANDERR;
        goto cleanup;
    }
    
    g_hitls_initialized = 1;
    LOG_INFO("openHiTLS library initialized successfully");
    
cleanup:
    if (ret != SDR_OK) {
        BSL_ERR_DeInit();
    }
    
    pthread_mutex_unlock(&g_init_mutex);
    return ret;
}

void sdfx_hitls_cleanup(void)
{
    pthread_mutex_lock(&g_init_mutex);
    
    if (g_hitls_initialized) {
        LOG_INFO("Cleaning up openHiTLS library...");
        
        /* Cleanup random number generator */
        CRYPT_EAL_RandDeinit();
        
        /* Cleanup error module */
        BSL_ERR_DeInit();
        
        g_hitls_initialized = 0;
        LOG_INFO("openHiTLS library cleanup completed");
    }
    
    pthread_mutex_unlock(&g_init_mutex);
}

int sdfx_hitls_is_initialized(void)
{
    int initialized;
    pthread_mutex_lock(&g_init_mutex);
    initialized = g_hitls_initialized;
    pthread_mutex_unlock(&g_init_mutex);
    return initialized;
}