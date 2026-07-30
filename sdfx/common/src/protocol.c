/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file protocol.c
 * @brief SDFX protocol implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "sdfx.h"

sdfx_message_t* sdfx_message_create(ULONG cmd, ULONG session_id, 
                                   const void *data, ULONG data_len, 
                                   ULONG *msg_len)
{
    sdfx_message_t *msg;
    ULONG total_len = SDFX_MESSAGE_HEADER_SIZE + data_len;
    
    if (total_len > SDFX_MAX_MESSAGE_SIZE) {
        return NULL;
    }
    
    msg = (sdfx_message_t*)malloc(total_len);
    if (msg == NULL) {
        return NULL;
    }
    
    /* Fill message header */
    msg->header.magic = sdfx_htonl(SDFX_PROTOCOL_MAGIC);
    msg->header.version = sdfx_htonl(SDFX_PROTOCOL_VERSION);
    msg->header.cmd = sdfx_htonl(cmd);
    msg->header.length = sdfx_htonl(data_len);
    msg->header.session_id = sdfx_htonl(session_id);
    msg->header.status = sdfx_htonl(SDR_OK);
    msg->header.reserved[0] = 0;
    msg->header.reserved[1] = 0;
    
    /* Copy data */
    if (data != NULL && data_len > 0) {
        memcpy(msg->data, data, data_len);
    }
    
    if (msg_len != NULL) {
        *msg_len = total_len;
    }
    
    return msg;
}

void sdfx_message_destroy(sdfx_message_t *msg)
{
    if (msg != NULL) {
        free(msg);
    }
}

int sdfx_message_validate_header(const sdfx_message_header_t *header)
{
    if (header == NULL) {
        return SDR_INARGERR;
    }
    
    if (header->magic != SDFX_PROTOCOL_MAGIC) {
        return SDR_PROTOCOL_ERROR;
    }
    
    if (header->version != SDFX_PROTOCOL_VERSION) {
        return SDR_PROTOCOL_ERROR;
    }
    
    if (header->length > SDFX_MAX_MESSAGE_SIZE - SDFX_MESSAGE_HEADER_SIZE) {
        return SDR_PROTOCOL_ERROR;
    }
    
    return SDR_OK;
}

void sdfx_message_header_to_network(sdfx_message_header_t *header)
{
    if (header == NULL) {
        return;
    }
    
    header->magic = sdfx_htonl(header->magic);
    header->version = sdfx_htonl(header->version);
    header->cmd = sdfx_htonl(header->cmd);
    header->length = sdfx_htonl(header->length);
    header->session_id = sdfx_htonl(header->session_id);
    header->status = sdfx_htonl(header->status);
    header->reserved[0] = sdfx_htonl(header->reserved[0]);
    header->reserved[1] = sdfx_htonl(header->reserved[1]);
}

void sdfx_message_header_from_network(sdfx_message_header_t *header)
{
    if (header == NULL) {
        return;
    }
    
    header->magic = sdfx_ntohl(header->magic);
    header->version = sdfx_ntohl(header->version);
    header->cmd = sdfx_ntohl(header->cmd);
    header->length = sdfx_ntohl(header->length);
    header->session_id = sdfx_ntohl(header->session_id);
    header->status = sdfx_ntohl(header->status);
    header->reserved[0] = sdfx_ntohl(header->reserved[0]);
    header->reserved[1] = sdfx_ntohl(header->reserved[1]);
}