/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file hitls_init.h
 * @brief Unified openHiTLS initialization interface
 */

#ifndef SDFX_HITLS_INIT_H
#define SDFX_HITLS_INIT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize openHiTLS library
 * @return SDR_OK on success, error code on failure
 */
int sdfx_hitls_init(void);

/**
 * @brief Cleanup openHiTLS library resources
 */
void sdfx_hitls_cleanup(void);

/**
 * @brief Check if openHiTLS is initialized
 * @return 1 if initialized, 0 otherwise
 */
int sdfx_hitls_is_initialized(void);

#ifdef __cplusplus
}
#endif

#endif /* SDFX_HITLS_INIT_H */
