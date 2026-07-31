/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file protocol_handler.c
 * @brief Protocol Handler Module
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "daemon_internal.h"

/* Device Information */
static DEVICEINFO g_device_info = {
    .IssuerName = "SDFX Project",
    .DeviceName = "SDFX-1.0",
    .DeviceSerial = "SW000001",
    .DeviceVersion = 0x00010000,
    .StandardVersion = 0x00020023,
    .AsymAlgAbility = {SGD_SM2_1 | SGD_SM2_3, 256},
    .SymAlgAbility = SGD_SM4_ECB | SGD_SM4_CBC | SGD_SM4_CFB |
                     SGD_SM4_OFB | SGD_SM4_CTR | SGD_SM4_MAC,
    .HashAlgAbility = SGD_SM3,
    .BufferSize = 4096
};

#include "admin_protocol.inc"

static int handle_open_device(daemon_context_t *ctx, const sdfx_open_device_req_t *req,
                              sdfx_open_device_resp_t *resp)
{
    LOG_DEBUG("Handling open device request");
    
    uint32_t device_id = device_manager_create_device(ctx);
    if (device_id == 0) {
        return SDR_NOBUFFER;
    }
    
    resp->device_handle = sdfx_htonll(device_id);
    LOG_INFO("Device opened, device_id = %u", device_id);
    return SDR_OK;
}

static int handle_close_device(daemon_context_t *ctx, const sdfx_close_device_req_t *req,
                               sdfx_close_device_resp_t *resp)
{
    LOG_DEBUG("Handling close device request");
    
    uint32_t device_id = (uint32_t)sdfx_ntohll(req->device_handle);
    int ret = device_manager_validate_device(ctx, device_id);
    if (ret != SDR_OK) {
        return ret;
    }
    
    LOG_INFO("Device closed, device_id = %u", device_id);
    return SDR_OK;
}

static int handle_open_session(daemon_context_t *ctx, const sdfx_open_session_req_t *req,
                               sdfx_open_session_resp_t *resp)
{
    LOG_DEBUG("Handling open session request");
    
    uint32_t device_id = (uint32_t)sdfx_ntohll(req->device_handle);
    int ret = device_manager_validate_device(ctx, device_id);
    if (ret != SDR_OK) {
        return ret;
    }
    
    uint32_t session_id = session_manager_create_session(ctx, device_id);
    if (session_id == 0) {
        return SDR_NOBUFFER;
    }
    
    resp->session_handle = sdfx_htonll(session_id);
    LOG_INFO("Session opened, session_id = %u, device_id = %u",
             session_id, device_id);
    return SDR_OK;
}

static int handle_close_session(daemon_context_t *ctx, const sdfx_close_session_req_t *req,
                                sdfx_close_session_resp_t *resp)
{
    LOG_DEBUG("Handling close session request");
    
    uint32_t session_id = (uint32_t)sdfx_ntohll(req->session_handle);
    int ret = session_manager_close_session(ctx, session_id);
    LOG_INFO("Session closed, session_id = %u", session_id);
    return ret;
}

static int handle_get_device_info(daemon_context_t *ctx, const sdfx_get_device_info_req_t *req,
                                  sdfx_get_device_info_resp_t *resp)
{
    LOG_DEBUG("Handling get device info request");
    
    uint32_t session_id = (uint32_t)sdfx_ntohll(req->session_handle);
    int ret = session_manager_validate_session(ctx, session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    
    pthread_mutex_lock(&g_device_info_mutex);
    memcpy(&resp->device_info, &g_device_info, sizeof(DEVICEINFO));
    pthread_mutex_unlock(&g_device_info_mutex);
    return SDR_OK;
}

static int handle_generate_random(daemon_context_t *ctx, const sdfx_generate_random_req_t *req,
                                  sdfx_generate_random_resp_t *resp)
{
    uint32_t session_id = (uint32_t)sdfx_ntohll(req->session_handle);
    uint32_t length = sdfx_ntohl(req->length);
    
    LOG_DEBUG("Handling generate random request, length = %u", length);
    
    int ret = session_manager_validate_session(ctx, session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Enhanced input validation */
    if (length == 0) {
        LOG_ERROR("Random length cannot be zero");
        return SDR_INARGERR;
    }
    if (length > SDFX_MAX_RANDOM_LENGTH) {
        LOG_ERROR("Random length too large: %u bytes (max: %d)", length, SDFX_MAX_RANDOM_LENGTH);
        return SDR_INARGERR;
    }
    
    ret = crypto_generate_random(length, resp->random_data);
    if (ret != SDR_OK) {
        return ret;
    }
    
    resp->length = sdfx_htonl(length);
    LOG_DEBUG("Generated %u bytes of random data", length);
    return SDR_OK;
}

static int handle_hash_init(daemon_context_t *ctx, const sdfx_hash_init_req_t *req,
                           sdfx_hash_init_resp_t *resp)
{
    uint32_t session_id = (uint32_t)sdfx_ntohll(req->session_handle);
    ULONG alg_id = sdfx_ntohl(req->alg_id);
    
    LOG_DEBUG("Handling hash init request, session_id = %u, alg_id = 0x%lx", 
             session_id, (unsigned long)alg_id);
    
    int ret = session_manager_validate_session(ctx, session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    
    session_info_t *session = session_manager_get_session(ctx, session_id);
    if (session == NULL) {
        return SDR_SESSION_NOT_EXIST;
    }
    
    ret = crypto_hash_init(ctx, session, alg_id);
    if (ret != SDR_OK) {
        LOG_ERROR("Failed to initialize hash: %d", ret);
        session_manager_put_session(session);  /* Release session reference */
        return ret;
    }
    
    session_manager_put_session(session);  /* Release session reference */
    
    LOG_DEBUG("Hash initialized successfully");
    return SDR_OK;
}

static int handle_hash_update(daemon_context_t *ctx, const sdfx_hash_update_req_t *req,
                             sdfx_hash_update_resp_t *resp)
{
    uint32_t session_id = (uint32_t)sdfx_ntohll(req->session_handle);
    ULONG data_length = sdfx_ntohl(req->data_length);
    
    LOG_DEBUG("Handling hash update request, session_id = %u, data_length = %lu", 
             session_id, (unsigned long)data_length);
    
    int ret = session_manager_validate_session(ctx, session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    
    /* Enhanced input validation */
    if (data_length == 0) {
        LOG_ERROR("Hash data length cannot be zero");
        return SDR_INARGERR;
    }
    if (data_length > SDFX_MAX_MESSAGE_SIZE) {
        LOG_ERROR("Hash data too large: %lu bytes (max: %d)", (unsigned long)data_length, SDFX_MAX_MESSAGE_SIZE);
        return SDR_INARGERR;
    }
    
    session_info_t *session = session_manager_get_session(ctx, session_id);
    if (session == NULL) {
        return SDR_SESSION_NOT_EXIST;
    }
    
    ret = crypto_hash_update(ctx, session, req->data, data_length);
    if (ret != SDR_OK) {
        LOG_ERROR("Failed to update hash: %d", ret);
        session_manager_put_session(session);  /* Release session reference */
        return ret;
    }
    
    session_manager_put_session(session);  /* Release session reference */
    
    LOG_DEBUG("Hash updated successfully");
    return SDR_OK;
}

static int handle_hash_final(daemon_context_t *ctx, const sdfx_hash_final_req_t *req,
                            sdfx_hash_final_resp_t *resp)
{
    uint32_t session_id = (uint32_t)sdfx_ntohll(req->session_handle);
    
    LOG_DEBUG("Handling hash final request, session_id = %u", session_id);
    
    int ret = session_manager_validate_session(ctx, session_id);
    if (ret != SDR_OK) {
        return ret;
    }
    
    session_info_t *session = session_manager_get_session(ctx, session_id);
    if (session == NULL) {
        return SDR_SESSION_NOT_EXIST;
    }
    
    ULONG hash_length = 64;  // maximum hash length
    ret = crypto_hash_final(ctx, session, resp->hash_data, &hash_length);
    if (ret != SDR_OK) {
        LOG_ERROR("Failed to finalize hash: %d", ret);
        session_manager_put_session(session);  /* Release session reference */
        return ret;
    }
    
    session_manager_put_session(session);  /* Release session reference */
    
    resp->hash_length = sdfx_htonl(hash_length);
    LOG_DEBUG("Hash finalized successfully, length = %lu", (unsigned long)hash_length);
    return SDR_OK;
}

static int handle_encrypt(daemon_context_t *ctx, const sdfx_encrypt_req_t *req,
                         sdfx_encrypt_resp_t *resp)
{
    LOG_DEBUG("Handling encrypt request");
    
    uint32_t session_id = (uint32_t)sdfx_ntohll(req->session_handle);
    ULONG alg_id = sdfx_ntohl(req->alg_id);
    ULONG iv_length = sdfx_ntohl(req->iv_length);
    ULONG data_length = sdfx_ntohl(req->data_length);
    
    LOG_DEBUG("Encrypt: session=0x%lx, alg=0x%lx, iv_len=%lu, data_len=%lu", 
             (unsigned long)session_id, (unsigned long)alg_id, 
             (unsigned long)iv_length, (unsigned long)data_length);
    
    /* Validate session */
    int ret_validate = session_manager_validate_session(ctx, session_id);
    if (ret_validate != SDR_OK) {
        LOG_ERROR("Invalid session handle: 0x%lx", (unsigned long)session_id);
        return SDR_SESSION_NOT_EXIST;
    }
    
    /* Extract IV and data */
    const BYTE *iv = (iv_length > 0) ? req->payload : NULL;
    const BYTE *plaintext = req->payload + iv_length;
    
    uint64_t key_id = sdfx_ntohll(req->key_handle);
    BYTE key[64];
    uint32_t key_len = sizeof(key);
    session_info_t *session = session_manager_get_session(ctx, session_id);
    if (session == NULL) {
        return SDR_INVALID_HANDLE;
    }
    int key_ret = session_key_get(session, key_id, key, &key_len);
    session_manager_put_session(session);
    if (key_ret != SDR_OK) {
        memset(key, 0, sizeof(key));
        return key_ret;
    }
    
    /* Allocate output buffer (reserve enough space for padding) */
    ULONG max_ciphertext_len = data_length + 32; /* 32 bytes padding overhead */
    BYTE *ciphertext = malloc(max_ciphertext_len);
    if (ciphertext == NULL) {
        LOG_ERROR("Failed to allocate ciphertext buffer: %s", strerror(errno));
        return SDR_NOBUFFER;
    }
    
    /* Call symmetric encryption function */
    ULONG ciphertext_len = max_ciphertext_len;
    int result = crypto_symmetric_encrypt(alg_id, key, key_len, iv, iv_length,
                                        plaintext, data_length, ciphertext, &ciphertext_len);
    
    if (result == SDR_OK) {
        /* Convert ciphertext length to network byte order and copy data */
        resp->enc_data_length = sdfx_htonl(ciphertext_len);
        memcpy(resp->enc_data, ciphertext, ciphertext_len);
        LOG_DEBUG("Encryption successful, output length: %lu", (unsigned long)ciphertext_len);
    } else {
        LOG_ERROR("Encryption failed: 0x%x", result);
    }
    
    memset(key, 0, sizeof(key));
    free(ciphertext);
    return result;
}

static int handle_decrypt(daemon_context_t *ctx, const sdfx_decrypt_req_t *req,
                         sdfx_decrypt_resp_t *resp)
{
    LOG_DEBUG("Handling decrypt request");
    
    uint32_t session_id = (uint32_t)sdfx_ntohll(req->session_handle);
    ULONG alg_id = sdfx_ntohl(req->alg_id);
    ULONG iv_length = sdfx_ntohl(req->iv_length);
    ULONG enc_data_length = sdfx_ntohl(req->enc_data_length);
    
    LOG_DEBUG("Decrypt: session=0x%lx, alg=0x%lx, iv_len=%lu, enc_len=%lu", 
             (unsigned long)session_id, (unsigned long)alg_id, 
             (unsigned long)iv_length, (unsigned long)enc_data_length);
    
    /* Validate session */
    int ret_validate = session_manager_validate_session(ctx, session_id);
    if (ret_validate != SDR_OK) {
        LOG_ERROR("Invalid session handle: 0x%lx", (unsigned long)session_id);
        return SDR_SESSION_NOT_EXIST;
    }
    
    /* Extract IV and ciphertext data */
    const BYTE *iv = (iv_length > 0) ? req->payload : NULL;
    const BYTE *ciphertext = req->payload + iv_length;
    
    uint64_t key_id = sdfx_ntohll(req->key_handle);
    BYTE key[64];
    uint32_t key_len = sizeof(key);
    session_info_t *session = session_manager_get_session(ctx, session_id);
    if (session == NULL) {
        return SDR_INVALID_HANDLE;
    }
    int key_ret = session_key_get(session, key_id, key, &key_len);
    session_manager_put_session(session);
    if (key_ret != SDR_OK) {
        memset(key, 0, sizeof(key));
        return key_ret;
    }
    
    /* Allocate output buffer */
    ULONG max_plaintext_len = enc_data_length + 16; /* extra space */
    BYTE *plaintext = malloc(max_plaintext_len);
    if (plaintext == NULL) {
        LOG_ERROR("Failed to allocate plaintext buffer: %s", strerror(errno));
        return SDR_NOBUFFER;
    }
    
    /* Call symmetric decryption function */
    ULONG plaintext_len = max_plaintext_len;
    int result = crypto_symmetric_decrypt(alg_id, key, key_len, iv, iv_length,
                                        ciphertext, enc_data_length, plaintext, &plaintext_len);
    
    if (result == SDR_OK) {
        /* Convert plaintext length to network byte order and copy data */
        resp->data_length = sdfx_htonl(plaintext_len);
        memcpy(resp->data, plaintext, plaintext_len);
        LOG_DEBUG("Decryption successful, output length: %lu", (unsigned long)plaintext_len);
    } else {
        LOG_ERROR("Decryption failed: 0x%x", result);
    }
    
    memset(key, 0, sizeof(key));
    free(plaintext);
    return result;
}

/**
 * @brief Handle SM2 key pair generation request
 */
static int handle_internal_sign_ecc(daemon_context_t *ctx,
                                    const sdfx_internal_sign_ecc_req_t *req,
                                    sdfx_internal_sign_ecc_resp_t *resp)
{
    uint32_t session_id = (uint32_t)sdfx_ntohll(req->session_handle);
    uint32_t key_index = sdfx_ntohl(req->key_index);
    uint32_t data_length = sdfx_ntohl(req->data_length);
    session_info_t *session = session_manager_get_session(ctx, session_id);
    if (session == NULL) {
        return SDR_INVALID_HANDLE;
    }
    BYTE signature[64];
    int ret = internal_key_sign(session, key_index, req->data, data_length, signature);
    if (ret == SDR_OK) {
        memset(&resp->signature, 0, sizeof(resp->signature));
        memcpy(resp->signature.r + ECCref_MAX_LEN - 32, signature, 32);
        memcpy(resp->signature.s + ECCref_MAX_LEN - 32, signature + 32, 32);
    }
    memset(signature, 0, sizeof(signature));
    session_manager_put_session(session);
    return ret;
}

static int handle_internal_verify_ecc(daemon_context_t *ctx,
                                      const sdfx_internal_verify_ecc_req_t *req)
{
    uint32_t session_id = (uint32_t)sdfx_ntohll(req->session_handle);
    if (session_manager_validate_session(ctx, session_id) != SDR_OK) {
        return SDR_INVALID_HANDLE;
    }
    BYTE signature[64];
    memcpy(signature, req->signature.r + ECCref_MAX_LEN - 32, 32);
    memcpy(signature + 32, req->signature.s + ECCref_MAX_LEN - 32, 32);
    int ret = internal_key_verify(sdfx_ntohl(req->key_index), req->data,
                                  sdfx_ntohl(req->data_length), signature);
    memset(signature, 0, sizeof(signature));
    return ret;
}

static int handle_generate_keypair_ecc(daemon_context_t *ctx,
                                      const sdfx_generate_keypair_ecc_req_t *req,
                                      sdfx_generate_keypair_ecc_resp_t *resp)
{
    if (req == NULL || resp == NULL) {
        return SDR_INARGERR;
    }
    
    LOG_DEBUG("Handling ECC key pair generation request");
    
    /* Validate algorithm ID */
    ULONG alg_id = sdfx_ntohl(req->alg_id);
    if (alg_id != SGD_SM2_1) {
        LOG_ERROR("Unsupported algorithm ID: 0x%lx", alg_id);
        return SDR_NOTSUPPORT;
    }
    
    /* Generate SM2 key pair */
    int result = crypto_sm2_generate_keypair(&resp->public_key, &resp->private_key);
    
    if (result == SDR_OK) {
        LOG_DEBUG("SM2 key pair generated successfully");
    } else {
        LOG_ERROR("SM2 key pair generation failed: 0x%x", result);
    }
    
    return result;
}

/**
 * @brief Handle external SM2 encryption request
 */
static int handle_external_encrypt_ecc(daemon_context_t *ctx,
                                      const sdfx_external_encrypt_ecc_req_t *req,
                                      sdfx_external_encrypt_ecc_resp_t *resp)
{
    if (req == NULL || resp == NULL) {
        return SDR_INARGERR;
    }
    
    LOG_DEBUG("Handling external ECC encrypt request");
    
    /* Validate algorithm ID */
    ULONG alg_id = sdfx_ntohl(req->alg_id);
    if (alg_id != SGD_SM2_1) {
        LOG_ERROR("Unsupported algorithm ID: 0x%lx", alg_id);
        return SDR_NOTSUPPORT;
    }
    
    ULONG data_length = sdfx_ntohl(req->data_length);
    if (data_length == 0 || data_length > 256) {
        LOG_ERROR("Invalid data length: %lu", data_length);
        return SDR_INARGERR;
    }
    
    /* Perform SM2 encryption */
    ULONG cipher_len = data_length;
    int result = crypto_sm2_external_encrypt(&req->public_key, req->data, data_length,
                                           &resp->cipher, cipher_len);
    
    if (result == SDR_OK) {
        resp->cipher.L = sdfx_htonl(cipher_len);
        LOG_DEBUG("SM2 encryption completed: %lu bytes -> %lu bytes", data_length, cipher_len);
    } else {
        LOG_ERROR("SM2 encryption failed: 0x%x", result);
    }
    
    return result;
}

/**
 * @brief Handle external SM2 decryption request
 */
static int handle_external_decrypt_ecc(daemon_context_t *ctx,
                                      const sdfx_external_decrypt_ecc_req_t *req,
                                      sdfx_external_decrypt_ecc_resp_t *resp)
{
    if (req == NULL || resp == NULL) {
        return SDR_INARGERR;
    }
    
    LOG_DEBUG("Handling external ECC decrypt request");
    
    /* Validate algorithm ID */
    ULONG alg_id = sdfx_ntohl(req->alg_id);
    if (alg_id != SGD_SM2_1) {
        LOG_ERROR("Unsupported algorithm ID: 0x%lx", alg_id);
        return SDR_NOTSUPPORT;
    }
    
    ULONG cipher_len = sdfx_ntohl(req->cipher.L);
    if (cipher_len == 0 || cipher_len > 256) {
        LOG_ERROR("Invalid cipher length: %lu", cipher_len);
        return SDR_INARGERR;
    }

    BYTE cipher_buffer[sizeof(ECCCipher) + 255];
    ECCCipher *cipher = (ECCCipher *)cipher_buffer;
    size_t cipher_size = sizeof(ECCCipher) + cipher_len - 1;
    memcpy(cipher, &req->cipher, cipher_size);
    cipher->L = cipher_len;

    /* Perform SM2 decryption */
    ULONG plaintext_len = 256;  /* maximum plaintext length */
    int result = crypto_sm2_external_decrypt(&req->private_key, cipher,
                                           resp->data, &plaintext_len);
    
    if (result == SDR_OK) {
        resp->data_length = sdfx_htonl(plaintext_len);
        LOG_DEBUG("SM2 decryption completed: %lu bytes -> %lu bytes", cipher_len, plaintext_len);
    } else {
        LOG_ERROR("SM2 decryption failed: 0x%x", result);
    }
    
    return result;
}

/**
 * @brief Handle external SM2 signing request
 */
static int handle_external_sign_ecc(daemon_context_t *ctx,
                                   const sdfx_external_sign_ecc_req_t *req,
                                   sdfx_external_sign_ecc_resp_t *resp)
{
    if (req == NULL || resp == NULL) {
        return SDR_INARGERR;
    }
    
    LOG_DEBUG("Handling external ECC sign request");
    
    /* Validate algorithm ID */
    ULONG alg_id = sdfx_ntohl(req->alg_id);
    if (alg_id != SGD_SM2_3) {  /* SM2 signature algorithm */
        LOG_ERROR("Unsupported algorithm ID: 0x%lx", alg_id);
        return SDR_NOTSUPPORT;
    }
    
    ULONG data_length = sdfx_ntohl(req->data_length);
    if (data_length == 0) {
        LOG_ERROR("Invalid data length: %lu", data_length);
        return SDR_INARGERR;
    }
    
    /* Perform SM2 signing */
    ULONG signature_len = 128;  /* SM2 signature maximum length */
    int result = crypto_sm2_external_sign(&req->private_key, req->data, data_length,
                                        resp->signature, &signature_len);
    
    if (result == SDR_OK) {
        resp->signature_length = sdfx_htonl(signature_len);
        LOG_DEBUG("SM2 signature completed: %lu bytes data -> %lu bytes signature", 
                  data_length, signature_len);
    } else {
        LOG_ERROR("SM2 signature failed: 0x%x", result);
    }
    
    return result;
}

/**
 * @brief Handle external SM2 verification request
 */
static int handle_external_verify_ecc(daemon_context_t *ctx,
                                     const sdfx_external_verify_ecc_req_t *req,
                                     sdfx_external_verify_ecc_resp_t *resp)
{
    if (req == NULL || resp == NULL) {
        return SDR_INARGERR;
    }
    
    LOG_DEBUG("Handling external ECC verify request");
    
    /* Validate algorithm ID */
    ULONG alg_id = sdfx_ntohl(req->alg_id);
    if (alg_id != SGD_SM2_3) {  /* SM2 signature algorithm */
        LOG_ERROR("Unsupported algorithm ID: 0x%lx", alg_id);
        return SDR_NOTSUPPORT;
    }
    
    ULONG data_length = sdfx_ntohl(req->data_length);
    ULONG signature_length = sdfx_ntohl(req->signature_length);
    
    if (data_length == 0 || signature_length == 0) {
        LOG_ERROR("Invalid lengths - data: %lu, signature: %lu", data_length, signature_length);
        return SDR_INARGERR;
    }
    
    /* Get data and signature pointers */
    const BYTE *data = req->payload;
    const BYTE *signature = req->payload + data_length;
    
    /* Perform SM2 verification */
    int result = crypto_sm2_external_verify(&req->public_key, data, data_length,
                                          signature, signature_length);
    
    /* Set verification result */
    resp->result = sdfx_htonl((result == SDR_OK) ? 0 : 1);
    
    if (result == SDR_OK) {
        LOG_DEBUG("SM2 verification succeeded");
    } else {
        LOG_DEBUG("SM2 verification failed: 0x%x", result);
        result = SDR_OK;  /* Verification failure is not an error, distinguished by the result field */
    }
    
    return result;
}

static int handle_blob_command(daemon_context_t *ctx, ULONG cmd,
                               const sdfx_blob_req_t *req, size_t request_len,
                               sdfx_blob_resp_t *resp)
{
    if (req == NULL || resp == NULL || request_len < sizeof(*req)) {
        return SDR_PROTOCOL_ERROR;
    }

    uint32_t data_len = sdfx_ntohl(req->data_length);
    if (data_len > SDFX_MAX_BLOB_LENGTH ||
        data_len > request_len - sizeof(*req)) {
        return SDR_PROTOCOL_ERROR;
    }

    uint32_t session_id = (uint32_t)sdfx_ntohll(req->session_handle);
    session_info_t *session = session_manager_get_session(ctx, session_id);
    if (session == NULL) {
        return SDR_INVALID_HANDLE;
    }

    uint32_t p0 = sdfx_ntohl(req->param[0]);
    uint32_t p1 = sdfx_ntohl(req->param[1]);
    uint32_t p2 = sdfx_ntohl(req->param[2]);
    uint64_t object_id = sdfx_ntohll(req->object_handle);
    uint32_t output_len = 0;
    uint64_t output_object = 0;
    int ret = SDR_NOTSUPPORT;

    switch (cmd) {
        case SDFX_CMD_GENERATE_KEY_KEK:
            output_len = 64;
            ret = kek_generate_wrapped(session, p0, p1, p2, resp->data,
                                       &output_len, &output_object);
            break;
        case SDFX_CMD_IMPORT_KEY_KEK:
            if (p2 != data_len) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            ret = kek_import_wrapped(session, p0, p1, req->data, data_len,
                                     &output_object);
            break;
        case SDFX_CMD_DESTROY_KEY:
            ret = session_key_destroy(session, object_id);
            break;
        case SDFX_CMD_CALCULATE_MAC:
            if (p1 > 16 || p2 > data_len || p1 + p2 != data_len) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            output_len = 16;
            ret = crypto_calculate_mac(session, object_id, p0,
                                       p1 == 0 ? NULL : req->data,
                                       req->data + p1, p2,
                                       resp->data, &output_len);
            break;
        case SDFX_CMD_CREATE_FILE:
            if (p0 != data_len) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            ret = user_file_create(req->data, p0, p1);
            break;
        case SDFX_CMD_READ_FILE:
            if (p0 != data_len || p2 > SDFX_MAX_BLOB_LENGTH) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            output_len = p2;
            ret = user_file_read(req->data, p0, p1, resp->data, &output_len);
            break;
        case SDFX_CMD_WRITE_FILE:
            if (p0 > data_len || p2 != data_len - p0) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            ret = user_file_write(req->data, p0, p1, req->data + p0, p2);
            break;
        case SDFX_CMD_DELETE_FILE:
            if (p0 != data_len) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            ret = user_file_delete(req->data, p0);
            break;
        case SDFX_CMD_GET_PRIVATE_ACCESS:
            if (p0 == 0 || data_len > 256) {
                ret = SDR_INARGERR;
                break;
            }
            {
                int sm2_ret = internal_key_get_access(session, p0, req->data, data_len);
                int rsa_ret = rsa_key_get_access(session, p0, req->data, data_len);
                if (sm2_ret == SDR_OK || rsa_ret == SDR_OK) ret = SDR_OK;
                else if (sm2_ret == SDR_KEYNOTEXIST && rsa_ret == SDR_KEYNOTEXIST) ret = SDR_KEYNOTEXIST;
                else ret = SDR_PRKRERR;
            }
            break;
        case SDFX_CMD_RELEASE_PRIVATE_ACCESS:
            {
                int sm2_ret = internal_key_release_access(session, p0);
                int rsa_ret = rsa_key_release_access(session, p0);
                ret = sm2_ret == SDR_OK || rsa_ret == SDR_OK ? SDR_OK : SDR_PARDENY;
            }
            break;
        case SDFX_CMD_EXPORT_SIGN_PUB_ECC:
        case SDFX_CMD_EXPORT_ENC_PUB_ECC:
            output_len = sizeof(ECCrefPublicKey);
            ret = internal_key_export_public(
                cmd == SDFX_CMD_EXPORT_SIGN_PUB_ECC ? SDFX_INTERNAL_KEY_SIGN :
                                                       SDFX_INTERNAL_KEY_ENC,
                p0, (ECCrefPublicKey *)resp->data);
            break;
        case SDFX_CMD_GENERATE_KEY_IPK_ECC: {
            ECCCipher *wrapped = (ECCCipher *)resp->data;
            ret = internal_key_generate_with_ipk(session, p0, p1, wrapped, 32,
                                                 &output_object);
            if (ret == SDR_OK) {
                output_len = sizeof(ECCCipher) + wrapped->L - 1;
                wrapped->L = sdfx_htonl(wrapped->L);
            }
            break;
        }
        case SDFX_CMD_GENERATE_KEY_EPK_ECC: {
            if (data_len != sizeof(ECCrefPublicKey)) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            ECCCipher *wrapped = (ECCCipher *)resp->data;
            ret = external_key_generate_with_epk(session,
                    (const ECCrefPublicKey *)req->data, p0, wrapped, 32,
                    &output_object);
            if (ret == SDR_OK) {
                output_len = sizeof(ECCCipher) + wrapped->L - 1;
                wrapped->L = sdfx_htonl(wrapped->L);
            }
            break;
        }
        case SDFX_CMD_IMPORT_KEY_ISK_ECC: {
            if (data_len < sizeof(ECCCipher)) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            BYTE cipher_buffer[sizeof(ECCCipher) + 31];
            ECCCipher *wrapped = (ECCCipher *)cipher_buffer;
            uint32_t cipher_len = sdfx_ntohl(((const ECCCipher *)req->data)->L);
            if (cipher_len == 0 || cipher_len > 32 ||
                data_len != sizeof(ECCCipher) + cipher_len - 1) {
                ret = SDR_PROTOCOL_ERROR;
                break;
            }
            memcpy(wrapped, req->data, data_len);
            wrapped->L = cipher_len;
            ret = internal_key_import_with_isk(session, p0, wrapped, &output_object);
            memset(cipher_buffer, 0, sizeof(cipher_buffer));
            break;
        }
        case SDFX_CMD_EXPORT_SIGN_PUB_RSA:
        case SDFX_CMD_EXPORT_ENC_PUB_RSA:
            output_len = sizeof(RSArefPublicKey);
            ret = rsa_key_export_public(cmd == SDFX_CMD_EXPORT_SIGN_PUB_RSA ?
                SDFX_INTERNAL_KEY_SIGN : SDFX_INTERNAL_KEY_ENC, p0,
                (RSArefPublicKey *)resp->data);
            break;
        case SDFX_CMD_GENERATE_KEY_IPK_RSA:
            output_len = RSAref_MAX_LEN;
            ret = rsa_generate_with_ipk(session, p0, p1, resp->data,
                                        &output_len, &output_object);
            break;
        case SDFX_CMD_GENERATE_KEY_EPK_RSA:
            if (data_len != sizeof(RSArefPublicKey)) { ret = SDR_PROTOCOL_ERROR; break; }
            output_len = RSAref_MAX_LEN;
            ret = rsa_generate_with_epk(session, (const RSArefPublicKey *)req->data,
                                        p0, resp->data, &output_len, &output_object);
            break;
        case SDFX_CMD_IMPORT_KEY_ISK_RSA:
            ret = rsa_import_with_isk(session, p0, req->data, data_len, &output_object);
            break;
        case SDFX_CMD_EXTERNAL_PUBLIC_RSA:
            if (data_len < sizeof(RSArefPublicKey)) { ret = SDR_PROTOCOL_ERROR; break; }
            output_len = RSAref_MAX_LEN;
            ret = crypto_rsa_public_operation((const RSArefPublicKey *)req->data,
                req->data + sizeof(RSArefPublicKey),
                data_len - sizeof(RSArefPublicKey), resp->data, &output_len, 0);
            break;
        case SDFX_CMD_INTERNAL_PUBLIC_RSA:
            output_len = RSAref_MAX_LEN;
            ret = rsa_internal_public_operation(p0, req->data, data_len,
                                                resp->data, &output_len);
            break;
        case SDFX_CMD_INTERNAL_PRIVATE_RSA:
            output_len = RSAref_MAX_LEN;
            ret = rsa_internal_private_operation(session, p0, req->data, data_len,
                                                 resp->data, &output_len);
            break;
        case SDFX_CMD_GENERATE_KEYPAIR_RSA:
            output_len = sizeof(RSArefPublicKey) + sizeof(RSArefPrivateKey);
            ret = crypto_rsa_generate_keypair(p0, (RSArefPublicKey *)resp->data,
                (RSArefPrivateKey *)(resp->data + sizeof(RSArefPublicKey)));
            break;
        case SDFX_CMD_EXTERNAL_PRIVATE_RSA:
            if (data_len < sizeof(RSArefPrivateKey)) { ret = SDR_PROTOCOL_ERROR; break; }
            output_len = RSAref_MAX_LEN;
            ret = crypto_rsa_private_operation((const RSArefPrivateKey *)req->data,
                req->data + sizeof(RSArefPrivateKey),
                data_len - sizeof(RSArefPrivateKey), resp->data, &output_len, 0);
            break;
        default:
            ret = SDR_NOTSUPPORT;
            break;
    }

    if (ret == SDR_OK) {
        resp->object_handle = sdfx_htonll(output_object);
        resp->data_length = sdfx_htonl(output_len);
    }
    session_manager_put_session(session);
    return ret;
}

int protocol_handler_init(daemon_context_t *ctx)
{
    int device_ret = admin_device_info_load();
    if (device_ret != SDR_OK) {
        LOG_ERROR("Failed to load persisted device information: 0x%x", device_ret);
        return device_ret;
    }
    LOG_INFO("Protocol handler initialized");
    return SDR_OK;
}

void protocol_handler_cleanup(daemon_context_t *ctx)
{
    LOG_INFO("Protocol handler cleanup completed");
}

static int validate_variable_request(ULONG cmd, const BYTE *data, size_t length)
{
    size_t base = 0;
    size_t first = 0;
    size_t second = 0;

    switch (cmd) {
        case SDFX_CMD_OPEN_DEVICE: base = sizeof(sdfx_open_device_req_t); break;
        case SDFX_CMD_CLOSE_DEVICE: base = sizeof(sdfx_close_device_req_t); break;
        case SDFX_CMD_OPEN_SESSION: base = sizeof(sdfx_open_session_req_t); break;
        case SDFX_CMD_CLOSE_SESSION: base = sizeof(sdfx_close_session_req_t); break;
        case SDFX_CMD_GET_DEVICE_INFO: base = sizeof(sdfx_get_device_info_req_t); break;
        case SDFX_CMD_GENERATE_RANDOM:
            base = sizeof(sdfx_generate_random_req_t);
            if (length >= base) {
                first = sdfx_ntohl(((const sdfx_generate_random_req_t *)data)->length);
                if (first == 0 || first > 4096) return SDR_INARGERR;
                first = 0;
            }
            break;
        case SDFX_CMD_HASH_INIT:
            base = sizeof(sdfx_hash_init_req_t);
            if (length >= base) first = sdfx_ntohl(((const sdfx_hash_init_req_t *)data)->id_length);
            break;
        case SDFX_CMD_HASH_UPDATE:
            base = sizeof(sdfx_hash_update_req_t);
            if (length >= base) first = sdfx_ntohl(((const sdfx_hash_update_req_t *)data)->data_length);
            break;
        case SDFX_CMD_HASH_FINAL: base = sizeof(sdfx_hash_final_req_t); break;
        case SDFX_CMD_ENCRYPT:
            base = sizeof(sdfx_encrypt_req_t);
            if (length >= base) {
                const sdfx_encrypt_req_t *req = (const sdfx_encrypt_req_t *)data;
                first = sdfx_ntohl(req->iv_length);
                second = sdfx_ntohl(req->data_length);
                if (first > 16 || second > SDFX_MAX_BLOB_LENGTH) return SDR_INARGERR;
            }
            break;
        case SDFX_CMD_DECRYPT:
            base = sizeof(sdfx_decrypt_req_t);
            if (length >= base) {
                const sdfx_decrypt_req_t *req = (const sdfx_decrypt_req_t *)data;
                first = sdfx_ntohl(req->iv_length);
                second = sdfx_ntohl(req->enc_data_length);
                if (first > 16 || second > SDFX_MAX_BLOB_LENGTH) return SDR_INARGERR;
            }
            break;
        case SDFX_CMD_INTERNAL_SIGN_ECC:
            base = sizeof(sdfx_internal_sign_ecc_req_t);
            if (length >= base) first = sdfx_ntohl(((const sdfx_internal_sign_ecc_req_t *)data)->data_length);
            if (length >= base && (first == 0 || first > SDFX_MAX_BLOB_LENGTH)) return SDR_INARGERR;
            break;
        case SDFX_CMD_INTERNAL_VERIFY_ECC:
            base = sizeof(sdfx_internal_verify_ecc_req_t);
            if (length >= base) first = sdfx_ntohl(((const sdfx_internal_verify_ecc_req_t *)data)->data_length);
            if (length >= base && (first == 0 || first > SDFX_MAX_BLOB_LENGTH)) return SDR_INARGERR;
            break;
        case SDFX_CMD_GENERATE_KEYPAIR_ECC: base = sizeof(sdfx_generate_keypair_ecc_req_t); break;
        case SDFX_CMD_EXTERNAL_ENCRYPT_ECC:
            base = sizeof(sdfx_external_encrypt_ecc_req_t);
            if (length >= base) {
                first = sdfx_ntohl(((const sdfx_external_encrypt_ecc_req_t *)data)->data_length);
                if (first == 0 || first > 256) return SDR_INARGERR;
            }
            break;
        case SDFX_CMD_EXTERNAL_DECRYPT_ECC:
            base = sizeof(sdfx_external_decrypt_ecc_req_t);
            if (length >= base) {
                first = sdfx_ntohl(((const sdfx_external_decrypt_ecc_req_t *)data)->cipher.L);
                if (first == 0 || first > 256) return SDR_INARGERR;
                first--;
            }
            break;
        case SDFX_CMD_EXTERNAL_SIGN_ECC:
            base = sizeof(sdfx_external_sign_ecc_req_t);
            if (length >= base) first = sdfx_ntohl(((const sdfx_external_sign_ecc_req_t *)data)->data_length);
            if (length >= base && (first == 0 || first > SDFX_MAX_BLOB_LENGTH)) return SDR_INARGERR;
            break;
        case SDFX_CMD_EXTERNAL_VERIFY_ECC:
            base = sizeof(sdfx_external_verify_ecc_req_t);
            if (length >= base) {
                const sdfx_external_verify_ecc_req_t *req = (const sdfx_external_verify_ecc_req_t *)data;
                first = sdfx_ntohl(req->data_length);
                second = sdfx_ntohl(req->signature_length);
                if (first == 0 || first > SDFX_MAX_BLOB_LENGTH || second != 64) return SDR_INARGERR;
            }
            break;
        case SDFX_CMD_GENERATE_KEY_KEK:
        case SDFX_CMD_IMPORT_KEY_KEK:
        case SDFX_CMD_DESTROY_KEY:
        case SDFX_CMD_CALCULATE_MAC:
        case SDFX_CMD_CREATE_FILE:
        case SDFX_CMD_READ_FILE:
        case SDFX_CMD_WRITE_FILE:
        case SDFX_CMD_DELETE_FILE:
        case SDFX_CMD_GET_PRIVATE_ACCESS:
        case SDFX_CMD_RELEASE_PRIVATE_ACCESS:
        case SDFX_CMD_EXPORT_SIGN_PUB_ECC:
        case SDFX_CMD_EXPORT_ENC_PUB_ECC:
        case SDFX_CMD_GENERATE_KEY_IPK_ECC:
        case SDFX_CMD_GENERATE_KEY_EPK_ECC:
        case SDFX_CMD_IMPORT_KEY_ISK_ECC:
        case SDFX_CMD_EXPORT_SIGN_PUB_RSA:
        case SDFX_CMD_EXPORT_ENC_PUB_RSA:
        case SDFX_CMD_GENERATE_KEY_IPK_RSA:
        case SDFX_CMD_GENERATE_KEY_EPK_RSA:
        case SDFX_CMD_IMPORT_KEY_ISK_RSA:
        case SDFX_CMD_EXTERNAL_PUBLIC_RSA:
        case SDFX_CMD_INTERNAL_PUBLIC_RSA:
        case SDFX_CMD_INTERNAL_PRIVATE_RSA:
        case SDFX_CMD_GENERATE_KEYPAIR_RSA:
        case SDFX_CMD_EXTERNAL_PRIVATE_RSA:
        case SDFX_CMD_ADMIN_STATUS:
        case SDFX_CMD_ADMIN_KEY_LIST:
        case SDFX_CMD_ADMIN_KEY_CREATE:
        case SDFX_CMD_ADMIN_KEY_DELETE:
        case SDFX_CMD_ADMIN_KEY_ENABLE:
        case SDFX_CMD_ADMIN_KEY_DISABLE:
        case SDFX_CMD_ADMIN_KEY_PUBLIC:
        case SDFX_CMD_ADMIN_KEY_PASSWORD:
        case SDFX_CMD_ADMIN_DEVICE_CONFIG:
        case SDFX_CMD_ADMIN_SESSION_LIST:
        case SDFX_CMD_ADMIN_SESSION_CLOSE:
            case SDFX_CMD_ADMIN_KEK_LIST:
            case SDFX_CMD_ADMIN_KEK_CREATE:
            case SDFX_CMD_ADMIN_KEK_DELETE:
            case SDFX_CMD_ADMIN_KEK_ENABLE:
            case SDFX_CMD_ADMIN_KEK_DISABLE:
            case SDFX_CMD_ADMIN_BACKUP_LIST:
            case SDFX_CMD_ADMIN_BACKUP_CREATE:
            case SDFX_CMD_ADMIN_BACKUP_RESTORE:
            case SDFX_CMD_ADMIN_BACKUP_DELETE:
            case SDFX_CMD_ADMIN_DEVICE_RESET:
            case SDFX_CMD_ADMIN_SELFTEST:
            case SDFX_CMD_ADMIN_INTEGRITY_INIT:
            case SDFX_CMD_ADMIN_KEY_VERIFY:
            case SDFX_CMD_ADMIN_KEY_REINDEX:
            case SDFX_CMD_ADMIN_RSA_KEY_LIST:
            case SDFX_CMD_ADMIN_RSA_KEY_CREATE:
            case SDFX_CMD_ADMIN_RSA_KEY_DELETE:
            case SDFX_CMD_ADMIN_RSA_KEY_ENABLE:
            case SDFX_CMD_ADMIN_RSA_KEY_DISABLE:
            case SDFX_CMD_ADMIN_RSA_KEY_PUBLIC:
            case SDFX_CMD_ADMIN_RSA_KEY_PASSWORD:
            case SDFX_CMD_ADMIN_RSA_KEY_VERIFY:
            case SDFX_CMD_ADMIN_RSA_KEY_REINDEX:
            case SDFX_CMD_ADMIN_KEK_VERIFY:
            base = sizeof(sdfx_blob_req_t);
            if (length >= base) {
                first = sdfx_ntohl(((const sdfx_blob_req_t *)data)->data_length);
                if (first > SDFX_MAX_BLOB_LENGTH) return SDR_INARGERR;
            }
            break;
        default:
            return SDR_OK;
    }

    if (length < base || first > length - base || second > length - base - first ||
        length != base + first + second) {
        return SDR_PROTOCOL_ERROR;
    }
    return SDR_OK;
}
int protocol_handler_process_message(daemon_context_t *ctx,
                                    const sdfx_message_t *request,
                                    sdfx_message_t **response,
                                    size_t *response_size)
{
    if (ctx == NULL || request == NULL || response == NULL || response_size == NULL) {
        return SDR_INARGERR;
    }
    
    ULONG result = SDR_OK;
    size_t resp_data_size = 0;
    
    /* Get command from network byte order */
    ULONG cmd = sdfx_ntohl(request->header.cmd);
    size_t request_data_size = sdfx_ntohl(request->header.length);
    if (request_data_size > SDFX_MAX_MESSAGE_SIZE - sizeof(sdfx_message_header_t)) {
        return SDR_PROTOCOL_ERROR;
    }
    int validation_result = validate_variable_request(cmd, request->data, request_data_size);
    if (validation_result != SDR_OK) {
        LOG_WARN("Rejected malformed command %lu (payload=%zu, error=0x%x)",
                 (unsigned long)cmd, request_data_size, validation_result);
        *response_size = sizeof(sdfx_message_header_t);
        *response = calloc(1, *response_size);
        if (*response == NULL) {
            return SDR_NOBUFFER;
        }
        (*response)->header.magic = sdfx_htonl(SDFX_MAGIC);
        (*response)->header.version = sdfx_htonl(SDFX_PROTOCOL_VERSION);
        (*response)->header.cmd = request->header.cmd;
        (*response)->header.length = sdfx_htonl(0);
        (*response)->header.session_id = request->header.session_id;
        (*response)->header.status = sdfx_htonl(validation_result);
        return validation_result;
    }
    
    LOG_DEBUG("Processing command %lu", (unsigned long)cmd);
    ctx->total_requests++;
    
    /* Determine response data size based on command type */
    switch (cmd) {
        case SDFX_CMD_OPEN_DEVICE:
            resp_data_size = sizeof(sdfx_open_device_resp_t);
            break;
        case SDFX_CMD_CLOSE_DEVICE:
            resp_data_size = sizeof(sdfx_close_device_resp_t);
            break;
        case SDFX_CMD_OPEN_SESSION:
            resp_data_size = sizeof(sdfx_open_session_resp_t);
            break;
        case SDFX_CMD_CLOSE_SESSION:
            resp_data_size = sizeof(sdfx_close_session_resp_t);
            break;
        case SDFX_CMD_GET_DEVICE_INFO:
            resp_data_size = sizeof(sdfx_get_device_info_resp_t);
            break;
        case SDFX_CMD_GENERATE_RANDOM: {
            const sdfx_generate_random_req_t *req = (const sdfx_generate_random_req_t *)request->data;
            ULONG length = sdfx_ntohl(req->length);
            resp_data_size = sizeof(sdfx_generate_random_resp_t) + length;
            break;
        }
        case SDFX_CMD_HASH_INIT:
            resp_data_size = 0;  // No response data
            break;
        case SDFX_CMD_HASH_UPDATE:
            resp_data_size = 0;  // No response data
            break;
        case SDFX_CMD_HASH_FINAL:
            resp_data_size = sizeof(sdfx_hash_final_resp_t) + 64;  // maximum hash length
            break;
        case SDFX_CMD_ENCRYPT: {
            const sdfx_encrypt_req_t *req = (const sdfx_encrypt_req_t *)request->data;
            ULONG data_length = sdfx_ntohl(req->data_length);
            resp_data_size = sizeof(sdfx_encrypt_resp_t) + data_length + 32;  // Reserve space for padding
            break;
        }
        case SDFX_CMD_DECRYPT: {
            const sdfx_decrypt_req_t *req = (const sdfx_decrypt_req_t *)request->data;
            ULONG enc_data_length = sdfx_ntohl(req->enc_data_length);
            resp_data_size = sizeof(sdfx_decrypt_resp_t) + enc_data_length + 16;  // Reserve space
            break;
        }
        case SDFX_CMD_INTERNAL_SIGN_ECC:
            resp_data_size = sizeof(sdfx_internal_sign_ecc_resp_t);
            break;
        case SDFX_CMD_INTERNAL_VERIFY_ECC:
            resp_data_size = 0;
            break;
        case SDFX_CMD_GENERATE_KEYPAIR_ECC:
            resp_data_size = sizeof(sdfx_generate_keypair_ecc_resp_t);
            break;
        case SDFX_CMD_EXTERNAL_ENCRYPT_ECC: {
            const sdfx_external_encrypt_ecc_req_t *req = (const sdfx_external_encrypt_ecc_req_t *)request->data;
            ULONG data_length = sdfx_ntohl(req->data_length);
            resp_data_size = sizeof(sdfx_external_encrypt_ecc_resp_t) + data_length - 1;
            break;
        }
        case SDFX_CMD_EXTERNAL_DECRYPT_ECC: {
            const sdfx_external_decrypt_ecc_req_t *req = (const sdfx_external_decrypt_ecc_req_t *)request->data;
            resp_data_size = sizeof(sdfx_external_decrypt_ecc_resp_t) + 256;  // Reserve space for decryption
            break;
        }
        case SDFX_CMD_EXTERNAL_SIGN_ECC: {
            resp_data_size = sizeof(sdfx_external_sign_ecc_resp_t) + 128;  // SM2 signature length
            break;
        }
        case SDFX_CMD_EXTERNAL_VERIFY_ECC:
            resp_data_size = sizeof(sdfx_external_verify_ecc_resp_t);
            break;
        case SDFX_CMD_GENERATE_KEY_KEK:
        case SDFX_CMD_IMPORT_KEY_KEK:
        case SDFX_CMD_DESTROY_KEY:
        case SDFX_CMD_CALCULATE_MAC:
        case SDFX_CMD_CREATE_FILE:
        case SDFX_CMD_READ_FILE:
        case SDFX_CMD_WRITE_FILE:
        case SDFX_CMD_DELETE_FILE:
        case SDFX_CMD_GET_PRIVATE_ACCESS:
        case SDFX_CMD_RELEASE_PRIVATE_ACCESS:
        case SDFX_CMD_EXPORT_SIGN_PUB_ECC:
        case SDFX_CMD_EXPORT_ENC_PUB_ECC:
        case SDFX_CMD_GENERATE_KEY_IPK_ECC:
        case SDFX_CMD_GENERATE_KEY_EPK_ECC:
        case SDFX_CMD_IMPORT_KEY_ISK_ECC:
        case SDFX_CMD_EXPORT_SIGN_PUB_RSA:
        case SDFX_CMD_EXPORT_ENC_PUB_RSA:
        case SDFX_CMD_GENERATE_KEY_IPK_RSA:
        case SDFX_CMD_GENERATE_KEY_EPK_RSA:
        case SDFX_CMD_IMPORT_KEY_ISK_RSA:
        case SDFX_CMD_EXTERNAL_PUBLIC_RSA:
        case SDFX_CMD_INTERNAL_PUBLIC_RSA:
        case SDFX_CMD_INTERNAL_PRIVATE_RSA:
        case SDFX_CMD_GENERATE_KEYPAIR_RSA:
        case SDFX_CMD_EXTERNAL_PRIVATE_RSA:
        case SDFX_CMD_ADMIN_STATUS:
        case SDFX_CMD_ADMIN_KEY_LIST:
        case SDFX_CMD_ADMIN_KEY_CREATE:
        case SDFX_CMD_ADMIN_KEY_DELETE:
        case SDFX_CMD_ADMIN_KEY_ENABLE:
        case SDFX_CMD_ADMIN_KEY_DISABLE:
        case SDFX_CMD_ADMIN_KEY_PUBLIC:
        case SDFX_CMD_ADMIN_KEY_PASSWORD:
        case SDFX_CMD_ADMIN_DEVICE_CONFIG:
        case SDFX_CMD_ADMIN_SESSION_LIST:
        case SDFX_CMD_ADMIN_SESSION_CLOSE:
            case SDFX_CMD_ADMIN_KEK_LIST:
            case SDFX_CMD_ADMIN_KEK_CREATE:
            case SDFX_CMD_ADMIN_KEK_DELETE:
            case SDFX_CMD_ADMIN_KEK_ENABLE:
            case SDFX_CMD_ADMIN_KEK_DISABLE:
            case SDFX_CMD_ADMIN_BACKUP_LIST:
            case SDFX_CMD_ADMIN_BACKUP_CREATE:
            case SDFX_CMD_ADMIN_BACKUP_RESTORE:
            case SDFX_CMD_ADMIN_BACKUP_DELETE:
            case SDFX_CMD_ADMIN_DEVICE_RESET:
            case SDFX_CMD_ADMIN_SELFTEST:
            case SDFX_CMD_ADMIN_INTEGRITY_INIT:
            case SDFX_CMD_ADMIN_KEY_VERIFY:
            case SDFX_CMD_ADMIN_KEY_REINDEX:
            case SDFX_CMD_ADMIN_RSA_KEY_LIST:
            case SDFX_CMD_ADMIN_RSA_KEY_CREATE:
            case SDFX_CMD_ADMIN_RSA_KEY_DELETE:
            case SDFX_CMD_ADMIN_RSA_KEY_ENABLE:
            case SDFX_CMD_ADMIN_RSA_KEY_DISABLE:
            case SDFX_CMD_ADMIN_RSA_KEY_PUBLIC:
            case SDFX_CMD_ADMIN_RSA_KEY_PASSWORD:
            case SDFX_CMD_ADMIN_RSA_KEY_VERIFY:
            case SDFX_CMD_ADMIN_RSA_KEY_REINDEX:
            case SDFX_CMD_ADMIN_KEK_VERIFY:
            resp_data_size = sizeof(sdfx_blob_resp_t) + SDFX_MAX_BLOB_LENGTH;
            break;
        default:
            LOG_WARN("Unknown command %lu", (unsigned long)cmd);
            result = SDR_NOTSUPPORT;
            resp_data_size = 0;
            break;
    }
    
    /* Allocate response message with bounds check */
    if (resp_data_size > SDFX_MAX_MESSAGE_SIZE - sizeof(sdfx_message_header_t)) {
        LOG_ERROR("Response data too large: %zu bytes (max: %lu)",
                 resp_data_size, 
                 (unsigned long)(SDFX_MAX_MESSAGE_SIZE - sizeof(sdfx_message_header_t)));
        return SDR_NOBUFFER;
    }
    
    *response_size = sizeof(sdfx_message_header_t) + resp_data_size;
    *response = malloc(*response_size);
    if (*response == NULL) {
        LOG_ERROR("Failed to allocate response message: %s", strerror(errno));
        return SDR_NOBUFFER;
    }
    
    memset(*response, 0, *response_size);
    (*response)->header.magic = sdfx_htonl(SDFX_MAGIC);
    (*response)->header.version = sdfx_htonl(SDFX_PROTOCOL_VERSION);  /* Add version number */
    (*response)->header.cmd = request->header.cmd;
    (*response)->header.length = sdfx_htonl(resp_data_size);
    (*response)->header.session_id = request->header.session_id;
    
    /* Process command */
    if (result == SDR_OK) {
        switch (cmd) {
            case SDFX_CMD_OPEN_DEVICE:
                result = handle_open_device(ctx,
                    (const sdfx_open_device_req_t *)request->data,
                    (sdfx_open_device_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_CLOSE_DEVICE:
                result = handle_close_device(ctx,
                    (const sdfx_close_device_req_t *)request->data,
                    (sdfx_close_device_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_OPEN_SESSION:
                result = handle_open_session(ctx,
                    (const sdfx_open_session_req_t *)request->data,
                    (sdfx_open_session_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_CLOSE_SESSION:
                result = handle_close_session(ctx,
                    (const sdfx_close_session_req_t *)request->data,
                    (sdfx_close_session_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_GET_DEVICE_INFO:
                result = handle_get_device_info(ctx,
                    (const sdfx_get_device_info_req_t *)request->data,
                    (sdfx_get_device_info_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_GENERATE_RANDOM:
                result = handle_generate_random(ctx,
                    (const sdfx_generate_random_req_t *)request->data,
                    (sdfx_generate_random_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_HASH_INIT:
                result = handle_hash_init(ctx,
                    (const sdfx_hash_init_req_t *)request->data,
                    (sdfx_hash_init_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_HASH_UPDATE:
                result = handle_hash_update(ctx,
                    (const sdfx_hash_update_req_t *)request->data,
                    (sdfx_hash_update_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_HASH_FINAL:
                result = handle_hash_final(ctx,
                    (const sdfx_hash_final_req_t *)request->data,
                    (sdfx_hash_final_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_ENCRYPT:
                result = handle_encrypt(ctx,
                    (const sdfx_encrypt_req_t *)request->data,
                    (sdfx_encrypt_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_DECRYPT:
                result = handle_decrypt(ctx,
                    (const sdfx_decrypt_req_t *)request->data,
                    (sdfx_decrypt_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_INTERNAL_SIGN_ECC:
                result = handle_internal_sign_ecc(ctx,
                    (const sdfx_internal_sign_ecc_req_t *)request->data,
                    (sdfx_internal_sign_ecc_resp_t *)(*response)->data);
                break;

            case SDFX_CMD_INTERNAL_VERIFY_ECC:
                result = handle_internal_verify_ecc(ctx,
                    (const sdfx_internal_verify_ecc_req_t *)request->data);
                break;

            case SDFX_CMD_GENERATE_KEYPAIR_ECC:
                result = handle_generate_keypair_ecc(ctx,
                    (const sdfx_generate_keypair_ecc_req_t *)request->data,
                    (sdfx_generate_keypair_ecc_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_EXTERNAL_ENCRYPT_ECC:
                result = handle_external_encrypt_ecc(ctx,
                    (const sdfx_external_encrypt_ecc_req_t *)request->data,
                    (sdfx_external_encrypt_ecc_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_EXTERNAL_DECRYPT_ECC:
                result = handle_external_decrypt_ecc(ctx,
                    (const sdfx_external_decrypt_ecc_req_t *)request->data,
                    (sdfx_external_decrypt_ecc_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_EXTERNAL_SIGN_ECC:
                result = handle_external_sign_ecc(ctx,
                    (const sdfx_external_sign_ecc_req_t *)request->data,
                    (sdfx_external_sign_ecc_resp_t *)(*response)->data);
                break;
                
            case SDFX_CMD_EXTERNAL_VERIFY_ECC:
                result = handle_external_verify_ecc(ctx,
                    (const sdfx_external_verify_ecc_req_t *)request->data,
                    (sdfx_external_verify_ecc_resp_t *)(*response)->data);
                break;

            case SDFX_CMD_GENERATE_KEY_KEK:
            case SDFX_CMD_IMPORT_KEY_KEK:
            case SDFX_CMD_DESTROY_KEY:
            case SDFX_CMD_CALCULATE_MAC:
            case SDFX_CMD_CREATE_FILE:
            case SDFX_CMD_READ_FILE:
            case SDFX_CMD_WRITE_FILE:
            case SDFX_CMD_DELETE_FILE:
            case SDFX_CMD_GET_PRIVATE_ACCESS:
            case SDFX_CMD_RELEASE_PRIVATE_ACCESS:
            case SDFX_CMD_EXPORT_SIGN_PUB_ECC:
            case SDFX_CMD_EXPORT_ENC_PUB_ECC:
            case SDFX_CMD_GENERATE_KEY_IPK_ECC:
            case SDFX_CMD_GENERATE_KEY_EPK_ECC:
            case SDFX_CMD_IMPORT_KEY_ISK_ECC:
                result = handle_blob_command(ctx, cmd,
                    (const sdfx_blob_req_t *)request->data,
                    sdfx_ntohl(request->header.length),
                    (sdfx_blob_resp_t *)(*response)->data);
                break;

            case SDFX_CMD_EXPORT_SIGN_PUB_RSA:
            case SDFX_CMD_EXPORT_ENC_PUB_RSA:
            case SDFX_CMD_GENERATE_KEY_IPK_RSA:
            case SDFX_CMD_GENERATE_KEY_EPK_RSA:
            case SDFX_CMD_IMPORT_KEY_ISK_RSA:
            case SDFX_CMD_EXTERNAL_PUBLIC_RSA:
            case SDFX_CMD_INTERNAL_PUBLIC_RSA:
            case SDFX_CMD_INTERNAL_PRIVATE_RSA:
            case SDFX_CMD_GENERATE_KEYPAIR_RSA:
            case SDFX_CMD_EXTERNAL_PRIVATE_RSA:
                result = handle_blob_command(ctx, cmd,
                    (const sdfx_blob_req_t *)request->data,
                    sdfx_ntohl(request->header.length),
                    (sdfx_blob_resp_t *)(*response)->data);
                break;

            case SDFX_CMD_ADMIN_STATUS:
            case SDFX_CMD_ADMIN_KEY_LIST:
            case SDFX_CMD_ADMIN_KEY_CREATE:
            case SDFX_CMD_ADMIN_KEY_DELETE:
            case SDFX_CMD_ADMIN_KEY_ENABLE:
            case SDFX_CMD_ADMIN_KEY_DISABLE:
            case SDFX_CMD_ADMIN_KEY_PUBLIC:
            case SDFX_CMD_ADMIN_KEY_PASSWORD:
            case SDFX_CMD_ADMIN_DEVICE_CONFIG:
            case SDFX_CMD_ADMIN_SESSION_LIST:
            case SDFX_CMD_ADMIN_SESSION_CLOSE:
            case SDFX_CMD_ADMIN_KEK_LIST:
            case SDFX_CMD_ADMIN_KEK_CREATE:
            case SDFX_CMD_ADMIN_KEK_DELETE:
            case SDFX_CMD_ADMIN_KEK_ENABLE:
            case SDFX_CMD_ADMIN_KEK_DISABLE:
            case SDFX_CMD_ADMIN_BACKUP_LIST:
            case SDFX_CMD_ADMIN_BACKUP_CREATE:
            case SDFX_CMD_ADMIN_BACKUP_RESTORE:
            case SDFX_CMD_ADMIN_BACKUP_DELETE:
            case SDFX_CMD_ADMIN_DEVICE_RESET:
            case SDFX_CMD_ADMIN_SELFTEST:
            case SDFX_CMD_ADMIN_INTEGRITY_INIT:
            case SDFX_CMD_ADMIN_KEY_VERIFY:
            case SDFX_CMD_ADMIN_KEY_REINDEX:
            case SDFX_CMD_ADMIN_RSA_KEY_LIST:
            case SDFX_CMD_ADMIN_RSA_KEY_CREATE:
            case SDFX_CMD_ADMIN_RSA_KEY_DELETE:
            case SDFX_CMD_ADMIN_RSA_KEY_ENABLE:
            case SDFX_CMD_ADMIN_RSA_KEY_DISABLE:
            case SDFX_CMD_ADMIN_RSA_KEY_PUBLIC:
            case SDFX_CMD_ADMIN_RSA_KEY_PASSWORD:
            case SDFX_CMD_ADMIN_RSA_KEY_VERIFY:
            case SDFX_CMD_ADMIN_RSA_KEY_REINDEX:
            case SDFX_CMD_ADMIN_KEK_VERIFY:
                result = handle_admin_command(ctx, cmd,
                    (const sdfx_blob_req_t *)request->data,
                    sdfx_ntohl(request->header.length),
                    (sdfx_blob_resp_t *)(*response)->data);
                break;
        }
    }

    if ((cmd >= SDFX_CMD_GENERATE_KEY_KEK && cmd <= SDFX_CMD_IMPORT_KEY_ISK_ECC) ||
        (cmd >= SDFX_CMD_EXPORT_SIGN_PUB_RSA && cmd <= SDFX_CMD_EXTERNAL_PRIVATE_RSA) ||
        (cmd >= SDFX_CMD_ADMIN_STATUS && cmd <= SDFX_CMD_ADMIN_RSA_KEY_REINDEX) ||
        cmd == SDFX_CMD_ADMIN_KEK_VERIFY) {
        sdfx_blob_resp_t *blob = (sdfx_blob_resp_t *)(*response)->data;
        size_t actual = sizeof(*blob) + sdfx_ntohl(blob->data_length);
        if (actual <= resp_data_size) {
            *response_size = sizeof(sdfx_message_header_t) + actual;
            (*response)->header.length = sdfx_htonl((ULONG)actual);
        }
    }

    (*response)->header.status = sdfx_htonl(result);
    
    LOG_DEBUG("Command %lu processed, result = %ld", (unsigned long)cmd, result);
    return result;
}
