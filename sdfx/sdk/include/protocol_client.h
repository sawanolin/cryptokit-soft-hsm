/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file protocol_client.h
 * @brief Protocol client interface definition
 */

#ifndef PROTOCOL_CLIENT_H
#define PROTOCOL_CLIENT_H

#include "sdf_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the client connection
 * @return SDR_OK for success, others for failure
 */
int protocol_client_init(void);

/**
 * @brief Clean up the client connection
 */
void protocol_client_cleanup(void);

/**
 * @brief Send a request and receive a response
 * @param req_msg Request message
 * @param req_len Request message length
 * @param resp_msg Response message buffer
 * @param resp_len Response message buffer size
 * @param actual_len Actual length of the received response
 * @return SDR_OK for success, others for failure
 */
LONG protocol_client_send_recv(const void *req_msg, size_t req_len,
                              void *resp_msg, size_t resp_len,
                              size_t *actual_len);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_CLIENT_H */