/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file daemon_internal.h
 * @brief SDFX daemon internal interface definitions
 */

#ifndef DAEMON_INTERNAL_H
#define DAEMON_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>

#include "sdf_types.h"
#include "sdf_err.h"
#include "sdfx.h"
#include "protocol.h"
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Session information structure */
typedef struct session_key {
    uint64_t key_id;
    uint32_t key_len;
    BYTE key[64];
    struct session_key *next;
} session_key_t;

typedef struct private_key_permission {
    uint32_t key_index;
    bool sign_allowed;
    bool enc_allowed;
    BYTE sign_secret[32];
    BYTE enc_secret[32];
    struct private_key_permission *next;
} private_key_permission_t;

typedef struct rsa_private_key_permission {
    uint32_t key_index;
    bool sign_allowed;
    bool enc_allowed;
    BYTE sign_secret[32];
    BYTE enc_secret[32];
    struct rsa_private_key_permission *next;
} rsa_private_key_permission_t;

typedef struct session_info {
    uint32_t session_id;
    uint32_t device_handle;
    time_t create_time;
    time_t last_access;
    bool active;
    
    /* Reference counting for thread safety */
    int ref_count;
    pthread_mutex_t ref_mutex;
    
    /* Crypto contexts */
    void *hash_ctx;
    void *cipher_ctx;

    /* Session-scoped objects; key bytes never leave the server. */
    pthread_mutex_t object_mutex;
    session_key_t *keys;
    uint32_t next_key_id;
    private_key_permission_t *private_permissions;
    rsa_private_key_permission_t *rsa_private_permissions;
    
    struct session_info *next;
} session_info_t;

/* Daemon context */
typedef struct daemon_context {
    /* Transport layer */
    void *transport_ctx;
    
    /* Session management */
    session_info_t *sessions;
    pthread_mutex_t sessions_mutex;
    uint32_t next_session_id;
    uint32_t next_device_id;
    
    /* Control flags */
    volatile bool running;
    
    /* Statistics */
    uint64_t total_requests;
    uint32_t active_sessions_count;
} daemon_context_t;

/* Function declarations */

/* Thread pool */
int thread_pool_create(int thread_count);
void thread_pool_destroy(void);
int thread_pool_submit(void (*function)(void*), void *arg);
int thread_pool_get_stats(int *thread_count, int *queue_size);

/* Daemon core */
int daemon_core_init(daemon_context_t *ctx);
int daemon_core_init_with_config(daemon_context_t *ctx, const void *config);
void daemon_core_cleanup(daemon_context_t *ctx);
int daemon_core_run(daemon_context_t *ctx);
daemon_context_t* daemon_get_context(void);

/* Session management */
int session_manager_init(daemon_context_t *ctx);
void session_manager_cleanup(daemon_context_t *ctx);
uint32_t session_manager_create_session(daemon_context_t *ctx, uint32_t device_handle);
int session_manager_close_session(daemon_context_t *ctx, uint32_t session_id);
int session_manager_validate_session(daemon_context_t *ctx, uint32_t session_id);
/* DEPRECATED: Use session_manager_get_session() instead to avoid race conditions */
session_info_t* session_manager_find_session_deprecated(daemon_context_t *ctx, uint32_t session_id);

/* Session reference counting for thread safety */
session_info_t* session_manager_get_session(daemon_context_t *ctx, uint32_t session_id);
void session_manager_put_session(session_info_t *session);

/* Protocol Handler */
int protocol_handler_init(daemon_context_t *ctx);
void protocol_handler_cleanup(daemon_context_t *ctx);
int protocol_handler_process_message(daemon_context_t *ctx, 
                                    const sdfx_message_t *request,
                                    sdfx_message_t **response,
                                    size_t *response_size);

/* Device management */
uint32_t device_manager_create_device(daemon_context_t *ctx);
int device_manager_validate_device(daemon_context_t *ctx, uint32_t device_handle);

/* Random Number Generation */
int crypto_generate_random(uint32_t length, BYTE *output);
void crypto_engine_cleanup(void);

/* Hash Algorithm */
int crypto_hash_init(daemon_context_t *ctx, session_info_t *session, ULONG alg_id);
int crypto_hash_update(daemon_context_t *ctx, session_info_t *session, 
                      const BYTE *data, ULONG data_len);
int crypto_hash_final(daemon_context_t *ctx, session_info_t *session,
                     BYTE *hash, ULONG *hash_len);
int crypto_hash_digest(ULONG alg_id, const BYTE *data, ULONG data_len,
                      BYTE *hash, ULONG *hash_len);

/* Symmetric Cryptography */
int crypto_symmetric_encrypt(ULONG alg_id, const BYTE *key, ULONG key_len,
                            const BYTE *iv, ULONG iv_len,
                            const BYTE *plaintext, ULONG plaintext_len,
                            BYTE *ciphertext, ULONG *ciphertext_len);
/* Session key and persistent user-file management. */
int session_key_create(session_info_t *session, const BYTE *key, uint32_t key_len,
                       uint64_t *key_id);
int session_key_get(session_info_t *session, uint64_t key_id, BYTE *key,
                    uint32_t *key_len);
int session_key_destroy(session_info_t *session, uint64_t key_id);
void session_objects_cleanup(session_info_t *session);
int kek_generate_wrapped(session_info_t *session, uint32_t key_bits,
                         uint32_t alg_id, uint32_t kek_index,
                         BYTE *wrapped, uint32_t *wrapped_len,
                         uint64_t *key_id);
int kek_import_wrapped(session_info_t *session, uint32_t alg_id,
                       uint32_t kek_index, const BYTE *wrapped,
                       uint32_t wrapped_len, uint64_t *key_id);
int kek_admin_create(uint32_t index);
int kek_admin_delete(uint32_t index);
int kek_admin_set_enabled(uint32_t index, bool enabled);
int kek_admin_list(BYTE *output, uint32_t *output_len, uint32_t *key_count);
int backup_admin_create(daemon_context_t *ctx, const BYTE *id, uint32_t id_len);
int backup_admin_list(BYTE *output, uint32_t *output_len);
int backup_admin_delete(const BYTE *id, uint32_t id_len);
int backup_admin_restore(daemon_context_t *ctx, const BYTE *id, uint32_t id_len);
int backup_admin_reset(daemon_context_t *ctx);
int crypto_calculate_mac(session_info_t *session, uint64_t key_id,
                         uint32_t alg_id, const BYTE *iv,
                         const BYTE *data, uint32_t data_len,
                         BYTE *mac, uint32_t *mac_len);
int user_file_create(const BYTE *name, uint32_t name_len, uint32_t file_size);
int user_file_read(const BYTE *name, uint32_t name_len, uint32_t offset,
                   BYTE *buffer, uint32_t *length);
int user_file_write(const BYTE *name, uint32_t name_len, uint32_t offset,
                    const BYTE *buffer, uint32_t length);
int user_file_delete(const BYTE *name, uint32_t name_len);

#define SDFX_INTERNAL_KEY_SIGN 1U
#define SDFX_INTERNAL_KEY_ENC  2U
int internal_key_get_access(session_info_t *session, uint32_t index,
                            const BYTE *password, uint32_t password_len);
int internal_key_release_access(session_info_t *session, uint32_t index);
int internal_key_export_public(uint32_t type, uint32_t index,
                               ECCrefPublicKey *public_key);
int internal_key_sign(session_info_t *session, uint32_t index,
                      const BYTE *data, uint32_t data_len,
                      BYTE signature[64]);
int internal_key_verify(uint32_t index, const BYTE *data, uint32_t data_len,
                        const BYTE signature[64]);
int internal_key_generate_with_ipk(session_info_t *session, uint32_t index,
                                   uint32_t key_bits, ECCCipher *wrapped,
                                   uint32_t wrapped_capacity, uint64_t *key_id);
int external_key_generate_with_epk(session_info_t *session,
                                   const ECCrefPublicKey *public_key,
                                   uint32_t key_bits, ECCCipher *wrapped,
                                   uint32_t wrapped_capacity, uint64_t *key_id);
int internal_key_import_with_isk(session_info_t *session, uint32_t index,
                                 const ECCCipher *wrapped, uint64_t *key_id);

int internal_key_admin_create(uint32_t type, uint32_t index,
                              const BYTE *password, uint32_t password_len);
int internal_key_admin_delete(uint32_t type, uint32_t index);
int internal_key_admin_set_enabled(uint32_t type, uint32_t index, bool enabled);
int internal_key_admin_export_public(uint32_t type, uint32_t index,
                                     ECCrefPublicKey *public_key);
int internal_key_admin_change_password(uint32_t type, uint32_t index,
                                       const BYTE *old_password,
                                       uint32_t old_password_len,
                                       const BYTE *new_password,
                                       uint32_t new_password_len);
int internal_key_admin_list(BYTE *output, uint32_t *output_len,
                            uint32_t *key_count);
int internal_key_admin_integrity_init(void);
int internal_key_admin_verify(uint32_t type, uint32_t index);
int internal_key_admin_reindex(uint32_t type, uint32_t old_index,
                               uint32_t new_index);

int crypto_symmetric_decrypt(ULONG alg_id, const BYTE *key, ULONG key_len,
                            const BYTE *iv, ULONG iv_len,
                            const BYTE *ciphertext, ULONG ciphertext_len,
                            BYTE *plaintext, ULONG *plaintext_len);

/* SM2 Asymmetric Cryptography */
int crypto_sm2_internal_sign(ULONG key_index, const BYTE *data, ULONG data_len,
                            BYTE *signature, ULONG *signature_len);
int crypto_sm2_internal_verify(ULONG key_index, const BYTE *data, ULONG data_len,
                              const BYTE *signature, ULONG signature_len);
int crypto_sm2_external_encrypt(const ECCrefPublicKey *public_key,
                               const BYTE *plaintext, ULONG plaintext_len,
                               ECCCipher *ciphertext, ULONG ciphertext_capacity);
int crypto_sm2_external_decrypt(const ECCrefPrivateKey *private_key,
                               const ECCCipher *ciphertext,
                               BYTE *plaintext, ULONG *plaintext_len);
int crypto_sm2_external_sign(const ECCrefPrivateKey *private_key,
                            const BYTE *data, ULONG data_len,
                            BYTE *signature, ULONG *signature_len);
int crypto_sm2_external_verify(const ECCrefPublicKey *public_key,
                              const BYTE *data, ULONG data_len,
                              const BYTE *signature, ULONG signature_len);
int crypto_sm2_generate_keypair(ECCrefPublicKey *public_key, ECCrefPrivateKey *private_key);

/* RSA cryptography and protected internal RSA keys. */
int crypto_rsa_generate_keypair(uint32_t bits, RSArefPublicKey *public_key,
                                RSArefPrivateKey *private_key);
int crypto_rsa_public_operation(const RSArefPublicKey *key, const BYTE *input,
                                uint32_t input_len, BYTE *output,
                                uint32_t *output_len, int wrapped);
int crypto_rsa_private_operation(const RSArefPrivateKey *key, const BYTE *input,
                                 uint32_t input_len, BYTE *output,
                                 uint32_t *output_len, int wrapped);
int rsa_key_get_access(session_info_t *session, uint32_t index,
                       const BYTE *password, uint32_t password_len);
int rsa_key_release_access(session_info_t *session, uint32_t index);
int rsa_key_export_public(uint32_t type, uint32_t index, RSArefPublicKey *public_key);
int rsa_key_admin_create(uint32_t type, uint32_t index, uint32_t bits,
                         const BYTE *password, uint32_t password_len);
int rsa_key_admin_delete(uint32_t type, uint32_t index);
int rsa_key_admin_set_enabled(uint32_t type, uint32_t index, bool enabled);
int rsa_key_admin_export_public(uint32_t type, uint32_t index,
                                RSArefPublicKey *public_key);
int rsa_key_admin_change_password(uint32_t type, uint32_t index,
                                  const BYTE *old_password, uint32_t old_password_len,
                                  const BYTE *new_password, uint32_t new_password_len);
int rsa_key_admin_verify(uint32_t type, uint32_t index);
int rsa_key_admin_reindex(uint32_t type, uint32_t old_index, uint32_t new_index);
int rsa_key_admin_list(BYTE *output, uint32_t *output_len, uint32_t *key_count);
int rsa_key_admin_exists(uint32_t type, uint32_t index);
int rsa_internal_public_operation(uint32_t index, const BYTE *input,
                                  uint32_t input_len, BYTE *output, uint32_t *output_len);
int rsa_internal_private_operation(session_info_t *session, uint32_t index,
                                   const BYTE *input, uint32_t input_len,
                                   BYTE *output, uint32_t *output_len);
int rsa_generate_with_ipk(session_info_t *session, uint32_t index,
                          uint32_t key_bits, BYTE *wrapped,
                          uint32_t *wrapped_len, uint64_t *key_id);
int rsa_generate_with_epk(session_info_t *session, const RSArefPublicKey *public_key,
                          uint32_t key_bits, BYTE *wrapped,
                          uint32_t *wrapped_len, uint64_t *key_id);
int rsa_import_with_isk(session_info_t *session, uint32_t index,
                        const BYTE *wrapped, uint32_t wrapped_len,
                        uint64_t *key_id);

/* SM2 context management */
void crypto_sm2_cleanup_contexts(void);

#ifdef __cplusplus
}
#endif

#endif /* DAEMON_INTERNAL_H */

