/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file crypto_asymmetric.c
 * @brief SM2 asymmetric cryptography implementation using openHiTLS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon_internal.h"
#include "hitls_init.h"
#include "hitls/crypto/crypt_eal_pkey.h"
#include "hitls/crypto/crypt_algid.h"
#define SM2_PUBLIC_KEY_LEN 65
#define SM2_MAX_PLAINTEXT_LEN 256
#include "hitls/crypto/crypt_errno.h"
#include "hitls/crypto/crypt_eal_rand.h"

/* SM2 curve parameter length (256 bits) */
#define SM2_KEY_LEN 32

/* SM2 context management - Thread Safe */
#define MAX_SM2_CONTEXTS 100
static struct {
    uint32_t key_id;
    CRYPT_EAL_PkeyCtx *ctx;
    int in_use;
} g_sm2_contexts[MAX_SM2_CONTEXTS];
static uint32_t g_next_key_id = 1;
static pthread_mutex_t g_sm2_contexts_mutex = PTHREAD_MUTEX_INITIALIZER;

static int ensure_hitls_init(void) {
    if (!sdfx_hitls_is_initialized()) {
        LOG_ERROR("openHiTLS library not initialized");
        return SDR_KEYERR;
    }
    
    /* Initialize context manager with thread safety */
    static int contexts_initialized = 0;
    static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    pthread_mutex_lock(&init_mutex);
    if (!contexts_initialized) {
        memset(g_sm2_contexts, 0, sizeof(g_sm2_contexts));
        contexts_initialized = 1;
        
    }
    pthread_mutex_unlock(&init_mutex);
    
    return SDR_OK;
}

static uint32_t store_sm2_context(CRYPT_EAL_PkeyCtx *ctx) {
    pthread_mutex_lock(&g_sm2_contexts_mutex);
    
    uint32_t key_id = 0;
    for (int i = 0; i < MAX_SM2_CONTEXTS; i++) {
        if (!g_sm2_contexts[i].in_use) {
            g_sm2_contexts[i].key_id = g_next_key_id++;
            g_sm2_contexts[i].ctx = ctx;
            g_sm2_contexts[i].in_use = 1;
            key_id = g_sm2_contexts[i].key_id;
            
            break;
        }
    }
    
    pthread_mutex_unlock(&g_sm2_contexts_mutex);
    
    if (key_id == 0) {
        LOG_ERROR("No available SM2 context slots (max: %d)", MAX_SM2_CONTEXTS);
    }
    
    return key_id;
}

static CRYPT_EAL_PkeyCtx* get_sm2_context(uint32_t key_id) {
    pthread_mutex_lock(&g_sm2_contexts_mutex);
    
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    for (int i = 0; i < MAX_SM2_CONTEXTS; i++) {
        if (g_sm2_contexts[i].in_use && g_sm2_contexts[i].key_id == key_id) {
            ctx = g_sm2_contexts[i].ctx;
            
            break;
        }
    }
    
    pthread_mutex_unlock(&g_sm2_contexts_mutex);
    
    if (ctx == NULL) {
        LOG_ERROR("SM2 context not found: key_id=%u", key_id);
    }
    
    return ctx;
}

static void free_sm2_context(uint32_t key_id) {
    pthread_mutex_lock(&g_sm2_contexts_mutex);
    
    for (int i = 0; i < MAX_SM2_CONTEXTS; i++) {
        if (g_sm2_contexts[i].in_use && g_sm2_contexts[i].key_id == key_id) {
            if (g_sm2_contexts[i].ctx != NULL) {
                CRYPT_EAL_PkeyFreeCtx(g_sm2_contexts[i].ctx);
                
            }
            g_sm2_contexts[i].ctx = NULL;
            g_sm2_contexts[i].key_id = 0;
            g_sm2_contexts[i].in_use = 0;
            break;
        }
    }
    
    pthread_mutex_unlock(&g_sm2_contexts_mutex);
}

/**
 * @brief Cleanup all SM2 contexts (should be called on daemon shutdown)
 */
void crypto_sm2_cleanup_contexts(void) {
    pthread_mutex_lock(&g_sm2_contexts_mutex);
    
    int freed_count = 0;
    for (int i = 0; i < MAX_SM2_CONTEXTS; i++) {
        if (g_sm2_contexts[i].in_use && g_sm2_contexts[i].ctx != NULL) {
            CRYPT_EAL_PkeyFreeCtx(g_sm2_contexts[i].ctx);
            g_sm2_contexts[i].ctx = NULL;
            g_sm2_contexts[i].key_id = 0;
            g_sm2_contexts[i].in_use = 0;
            freed_count++;
        }
    }
    
    pthread_mutex_unlock(&g_sm2_contexts_mutex);
    
    LOG_INFO("SM2 context cleanup completed: freed %d contexts", freed_count);
}

static CRYPT_EAL_PkeyCtx *sm2_ctx_from_public(const ECCrefPublicKey *key)
{
    if (key == NULL || key->bits != 256) {
        return NULL;
    }
    uint8_t encoded[SM2_PUBLIC_KEY_LEN] = {0x04};
    memcpy(encoded + 1, key->x + ECCref_MAX_LEN - SM2_KEY_LEN, SM2_KEY_LEN);
    memcpy(encoded + 1 + SM2_KEY_LEN, key->y + ECCref_MAX_LEN - SM2_KEY_LEN, SM2_KEY_LEN);
    CRYPT_EAL_PkeyPub pub = {0};
    pub.id = CRYPT_PKEY_SM2;
    pub.key.eccPub.data = encoded;
    pub.key.eccPub.len = sizeof(encoded);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (ctx == NULL || CRYPT_EAL_PkeySetPub(ctx, &pub) != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

int crypto_sm2_validate_public_key(const ECCrefPublicKey *public_key)
{
    if (ensure_hitls_init() != SDR_OK) {
        return SDR_KEYERR;
    }
    CRYPT_EAL_PkeyCtx *ctx = sm2_ctx_from_public(public_key);
    if (ctx == NULL) {
        return SDR_KEYERR;
    }
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return SDR_OK;
}

static CRYPT_EAL_PkeyCtx *sm2_ctx_from_private(const ECCrefPrivateKey *key)
{
    if (key == NULL || key->bits != 256) {
        return NULL;
    }
    CRYPT_EAL_PkeyPrv prv = {0};
    prv.id = CRYPT_PKEY_SM2;
    prv.key.eccPrv.data = (uint8_t *)(key->K + ECCref_MAX_LEN - SM2_KEY_LEN);
    prv.key.eccPrv.len = SM2_KEY_LEN;
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (ctx == NULL || CRYPT_EAL_PkeySetPrv(ctx, &prv) != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

static int der_read_length(const uint8_t **cursor, const uint8_t *end, size_t *length)
{
    if (*cursor >= end) {
        return -1;
    }
    uint8_t first = *(*cursor)++;
    if ((first & 0x80U) == 0) {
        *length = first;
        return 0;
    }
    uint8_t count = first & 0x7fU;
    if (count == 0 || count > sizeof(size_t) || (size_t)(end - *cursor) < count) {
        return -1;
    }
    size_t value = 0;
    for (uint8_t i = 0; i < count; i++) {
        value = (value << 8) | *(*cursor)++;
    }
    if (value > (size_t)(end - *cursor)) {
        return -1;
    }
    *length = value;
    return 0;
}

static int der_read_value(const uint8_t **cursor, const uint8_t *end, uint8_t tag,
                          const uint8_t **value, size_t *length)
{
    if (*cursor >= end || *(*cursor)++ != tag || der_read_length(cursor, end, length) != 0 ||
        *length > (size_t)(end - *cursor)) {
        return -1;
    }
    *value = *cursor;
    *cursor += *length;
    return 0;
}

static int sm2_der_to_sdf(const uint8_t *der, size_t der_len, ECCCipher *cipher,
                          size_t cipher_capacity)
{
    const uint8_t *cursor = der;
    const uint8_t *end = der + der_len;
    const uint8_t *sequence = NULL;
    size_t sequence_len = 0;
    if (der_read_value(&cursor, end, 0x30, &sequence, &sequence_len) != 0 || cursor != end) {
        return -1;
    }
    cursor = sequence;
    end = sequence + sequence_len;
    const uint8_t *x = NULL, *y = NULL, *hash = NULL, *data = NULL;
    size_t x_len = 0, y_len = 0, hash_len = 0, data_len = 0;
    if (der_read_value(&cursor, end, 0x02, &x, &x_len) != 0 ||
        der_read_value(&cursor, end, 0x02, &y, &y_len) != 0 ||
        der_read_value(&cursor, end, 0x04, &hash, &hash_len) != 0 ||
        der_read_value(&cursor, end, 0x04, &data, &data_len) != 0 || cursor != end) {
        return -1;
    }
    while (x_len > SM2_KEY_LEN && *x == 0) { x++; x_len--; }
    while (y_len > SM2_KEY_LEN && *y == 0) { y++; y_len--; }
    if (x_len > SM2_KEY_LEN || y_len > SM2_KEY_LEN || hash_len != sizeof(cipher->M) ||
        data_len == 0 || data_len > cipher_capacity) {
        return -1;
    }
    memset(cipher->x, 0, sizeof(cipher->x));
    memset(cipher->y, 0, sizeof(cipher->y));
    memcpy(cipher->x + sizeof(cipher->x) - x_len, x, x_len);
    memcpy(cipher->y + sizeof(cipher->y) - y_len, y, y_len);
    memcpy(cipher->M, hash, hash_len);
    memcpy(cipher->C, data, data_len);
    cipher->L = (ULONG)data_len;
    return 0;
}

static size_t der_write_length(uint8_t *out, size_t length)
{
    if (length < 128) {
        out[0] = (uint8_t)length;
        return 1;
    }
    size_t count = 0;
    for (size_t n = length; n != 0; n >>= 8) { count++; }
    out[0] = 0x80U | (uint8_t)count;
    for (size_t i = 0; i < count; i++) {
        out[count - i] = (uint8_t)(length >> (i * 8));
    }
    return count + 1;
}

static int der_write_tlv(uint8_t **cursor, const uint8_t *end, uint8_t tag,
                         const uint8_t *value, size_t length)
{
    uint8_t len_buf[1 + sizeof(size_t)];
    size_t len_len = der_write_length(len_buf, length);
    if ((size_t)(end - *cursor) < 1 + len_len + length) {
        return -1;
    }
    *(*cursor)++ = tag;
    memcpy(*cursor, len_buf, len_len);
    *cursor += len_len;
    memcpy(*cursor, value, length);
    *cursor += length;
    return 0;
}

static int der_write_integer32(uint8_t **cursor, const uint8_t *end, const uint8_t value[32])
{
    size_t offset = 0;
    while (offset < 31 && value[offset] == 0) { offset++; }
    uint8_t encoded[33];
    size_t length = 32 - offset;
    if ((value[offset] & 0x80U) != 0) {
        encoded[0] = 0;
        memcpy(encoded + 1, value + offset, length);
        length++;
    } else {
        memcpy(encoded, value + offset, length);
    }
    return der_write_tlv(cursor, end, 0x02, encoded, length);
}

static int sm2_sdf_to_der(const ECCCipher *cipher, uint8_t *der, size_t *der_len)
{
    if (cipher == NULL || cipher->L == 0 || cipher->L > SM2_MAX_PLAINTEXT_LEN) {
        return -1;
    }
    uint8_t content[SM2_MAX_PLAINTEXT_LEN + 128];
    uint8_t *cursor = content;
    const uint8_t *end = content + sizeof(content);
    if (der_write_integer32(&cursor, end, cipher->x + ECCref_MAX_LEN - SM2_KEY_LEN) != 0 ||
        der_write_integer32(&cursor, end, cipher->y + ECCref_MAX_LEN - SM2_KEY_LEN) != 0 ||
        der_write_tlv(&cursor, end, 0x04, cipher->M, sizeof(cipher->M)) != 0 ||
        der_write_tlv(&cursor, end, 0x04, cipher->C, cipher->L) != 0) {
        return -1;
    }
    size_t content_len = (size_t)(cursor - content);
    uint8_t len_buf[1 + sizeof(size_t)];
    size_t len_len = der_write_length(len_buf, content_len);
    if (*der_len < 1 + len_len + content_len) {
        return -1;
    }
    der[0] = 0x30;
    memcpy(der + 1, len_buf, len_len);
    memcpy(der + 1 + len_len, content, content_len);
    *der_len = 1 + len_len + content_len;
    return 0;
}

/**
 * @brief Generate SM2 key pair
 */
int crypto_sm2_generate_keypair(ECCrefPublicKey *public_key, ECCrefPrivateKey *private_key)
{
    if (public_key == NULL || private_key == NULL) {
        return SDR_INARGERR;
    }
    int ret = ensure_hitls_init();
    if (ret != SDR_OK) {
        return ret;
    }
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (ctx == NULL) {
        return SDR_NOBUFFER;
    }
    int hitls_ret = CRYPT_EAL_PkeyGen(ctx);
    if (hitls_ret != CRYPT_SUCCESS) {
        LOG_ERROR("Failed to generate SM2 key pair: 0x%x", hitls_ret);
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return SDR_KEYERR;
    }

    uint8_t pub_buf[SM2_PUBLIC_KEY_LEN];
    uint8_t prv_buf[SM2_KEY_LEN];
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    pub.id = CRYPT_PKEY_SM2;
    pub.key.eccPub.data = pub_buf;
    pub.key.eccPub.len = sizeof(pub_buf);
    prv.id = CRYPT_PKEY_SM2;
    prv.key.eccPrv.data = prv_buf;
    prv.key.eccPrv.len = sizeof(prv_buf);
    if (CRYPT_EAL_PkeyGetPub(ctx, &pub) != CRYPT_SUCCESS ||
        CRYPT_EAL_PkeyGetPrv(ctx, &prv) != CRYPT_SUCCESS ||
        pub.key.eccPub.len != SM2_PUBLIC_KEY_LEN || pub_buf[0] != 0x04 ||
        prv.key.eccPrv.len == 0 || prv.key.eccPrv.len > SM2_KEY_LEN) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return SDR_KEYERR;
    }

    memset(public_key, 0, sizeof(*public_key));
    memset(private_key, 0, sizeof(*private_key));
    public_key->bits = 256;
    private_key->bits = 256;
    memcpy(public_key->x + ECCref_MAX_LEN - SM2_KEY_LEN, pub_buf + 1, SM2_KEY_LEN);
    memcpy(public_key->y + ECCref_MAX_LEN - SM2_KEY_LEN, pub_buf + 1 + SM2_KEY_LEN, SM2_KEY_LEN);
    memcpy(private_key->K + ECCref_MAX_LEN - prv.key.eccPrv.len, prv_buf, prv.key.eccPrv.len);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return SDR_OK;
}
/**
 * @brief SM2 external public key encryption
 */
int crypto_sm2_external_encrypt(const ECCrefPublicKey *public_key,
                                const BYTE *plaintext, ULONG plaintext_len,
                                ECCCipher *ciphertext, ULONG ciphertext_capacity)
{
    if (public_key == NULL || plaintext == NULL || ciphertext == NULL ||
        plaintext_len == 0 || plaintext_len > SM2_MAX_PLAINTEXT_LEN ||
        ciphertext_capacity < plaintext_len) {
        return SDR_INARGERR;
    }
    int ret = ensure_hitls_init();
    if (ret != SDR_OK) {
        return ret;
    }
    CRYPT_EAL_PkeyCtx *ctx = sm2_ctx_from_public(public_key);
    if (ctx == NULL) {
        return SDR_KEYERR;
    }
    uint8_t der[SM2_MAX_PLAINTEXT_LEN + 128];
    uint32_t der_len = sizeof(der);
    int hitls_ret = CRYPT_EAL_PkeyEncrypt(ctx, plaintext, plaintext_len, der, &der_len);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (hitls_ret != CRYPT_SUCCESS ||
        sm2_der_to_sdf(der, der_len, ciphertext, ciphertext_capacity) != 0) {
        LOG_ERROR("SM2 encryption failed: 0x%x", hitls_ret);
        return SDR_KEYERR;
    }
    return SDR_OK;
}
/**
 * @brief SM2 external private key decryption
 */
int crypto_sm2_external_decrypt(const ECCrefPrivateKey *private_key,
                                const ECCCipher *ciphertext,
                                BYTE *plaintext, ULONG *plaintext_len)
{
    if (private_key == NULL || ciphertext == NULL || plaintext == NULL || plaintext_len == NULL ||
        ciphertext->L == 0 || ciphertext->L > SM2_MAX_PLAINTEXT_LEN) {
        return SDR_INARGERR;
    }
    int ret = ensure_hitls_init();
    if (ret != SDR_OK) {
        return ret;
    }
    uint8_t der[SM2_MAX_PLAINTEXT_LEN + 128];
    size_t der_len = sizeof(der);
    if (sm2_sdf_to_der(ciphertext, der, &der_len) != 0) {
        return SDR_INARGERR;
    }
    CRYPT_EAL_PkeyCtx *ctx = sm2_ctx_from_private(private_key);
    if (ctx == NULL) {
        return SDR_KEYERR;
    }
    uint32_t out_len = *plaintext_len;
    int hitls_ret = CRYPT_EAL_PkeyDecrypt(ctx, der, (uint32_t)der_len, plaintext, &out_len);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (hitls_ret != CRYPT_SUCCESS) {
        LOG_ERROR("SM2 decryption failed: 0x%x", hitls_ret);
        return SDR_KEYERR;
    }
    *plaintext_len = out_len;
    return SDR_OK;
}
/**
 * @brief SM2 external signature (using private key)
 */
int crypto_sm2_external_sign(const ECCrefPrivateKey *private_key,
                            const BYTE *data, ULONG data_len,
                            BYTE *signature, ULONG *signature_len)
{
    if (private_key == NULL || data == NULL || signature == NULL || signature_len == NULL ||
        data_len == 0 || *signature_len < 64) {
        return SDR_INARGERR;
    }
    int ret = ensure_hitls_init();
    if (ret != SDR_OK) {
        return ret;
    }
    CRYPT_EAL_PkeyCtx *ctx = sm2_ctx_from_private(private_key);
    if (ctx == NULL) {
        return SDR_KEYERR;
    }
    uint8_t user_id[32] = {0};
    if (CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, user_id, sizeof(user_id)) != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return SDR_KEYERR;
    }
    uint8_t der[80];
    uint32_t der_len = sizeof(der);
    int hitls_ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, data, data_len, der, &der_len);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (hitls_ret != CRYPT_SUCCESS) {
        return SDR_KEYERR;
    }
    const uint8_t *cursor = der;
    const uint8_t *end = der + der_len;
    const uint8_t *sequence = NULL, *r = NULL, *s = NULL;
    size_t sequence_len = 0, r_len = 0, s_len = 0;
    if (der_read_value(&cursor, end, 0x30, &sequence, &sequence_len) != 0 || cursor != end) {
        return SDR_KEYERR;
    }
    cursor = sequence;
    end = sequence + sequence_len;
    if (der_read_value(&cursor, end, 0x02, &r, &r_len) != 0 ||
        der_read_value(&cursor, end, 0x02, &s, &s_len) != 0 || cursor != end) {
        return SDR_KEYERR;
    }
    while (r_len > SM2_KEY_LEN && *r == 0) { r++; r_len--; }
    while (s_len > SM2_KEY_LEN && *s == 0) { s++; s_len--; }
    if (r_len > SM2_KEY_LEN || s_len > SM2_KEY_LEN) {
        return SDR_KEYERR;
    }
    memset(signature, 0, 64);
    memcpy(signature + SM2_KEY_LEN - r_len, r, r_len);
    memcpy(signature + 2 * SM2_KEY_LEN - s_len, s, s_len);
    *signature_len = 64;
    return SDR_OK;
}
/**
 * @brief SM2 external verification (using public key)
 */
int crypto_sm2_external_verify(const ECCrefPublicKey *public_key,
                               const BYTE *data, ULONG data_len,
                               const BYTE *signature, ULONG signature_len)
{
    if (public_key == NULL || data == NULL || signature == NULL ||
        data_len == 0 || signature_len != 64) {
        return SDR_INARGERR;
    }
    int ret = ensure_hitls_init();
    if (ret != SDR_OK) {
        return ret;
    }
    CRYPT_EAL_PkeyCtx *ctx = sm2_ctx_from_public(public_key);
    if (ctx == NULL) {
        return SDR_KEYERR;
    }
    uint8_t user_id[32] = {0};
    if (CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, user_id, sizeof(user_id)) != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return SDR_KEYERR;
    }
    uint8_t content[72];
    uint8_t *content_cursor = content;
    const uint8_t *content_end = content + sizeof(content);
    if (der_write_integer32(&content_cursor, content_end, signature) != 0 ||
        der_write_integer32(&content_cursor, content_end, signature + SM2_KEY_LEN) != 0) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return SDR_KEYERR;
    }
    uint8_t der[80];
    uint8_t *der_cursor = der;
    const uint8_t *der_end = der + sizeof(der);
    if (der_write_tlv(&der_cursor, der_end, 0x30, content,
                      (size_t)(content_cursor - content)) != 0) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return SDR_KEYERR;
    }
    int hitls_ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, data, data_len,
                                         der, (uint32_t)(der_cursor - der));
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return hitls_ret == CRYPT_SUCCESS ? SDR_OK : SDR_VERIFYERR;
}
/* RSA operations required by GM/T 0018.  SDF public/private operations use
 * raw modular exponentiation (RSA_NO_PAD); wrapped session keys use
 * RSAES-PKCS1-v1_5 so a 128/256-bit key can be transported safely. */
static void rsa_secure_clear(void *ptr, size_t len)
{
    volatile BYTE *p = (volatile BYTE *)ptr;
    while (len-- > 0) *p++ = 0;
}

static const BYTE *rsa_component(const BYTE *value, size_t capacity, uint32_t bytes)
{
    return bytes <= capacity ? value + capacity - bytes : NULL;
}

static void rsa_right_align(BYTE *target, size_t capacity,
                            const BYTE *source, uint32_t length)
{
    memset(target, 0, capacity);
    if (length > capacity) {
        source += length - capacity;
        length = (uint32_t)capacity;
    }
    memcpy(target + capacity - length, source, length);
}

static CRYPT_EAL_PkeyCtx *rsa_ctx_from_public(const RSArefPublicKey *key)
{
    if (key == NULL || key->bits < 1024 || key->bits > RSAref_MAX_BITS ||
        (key->bits & 7U) != 0) return NULL;
    uint32_t bytes = key->bits / 8;
    const BYTE *n = rsa_component(key->m, sizeof(key->m), bytes);
    if (n == NULL) return NULL;
    size_t e_offset = 0;
    while (e_offset + 1 < sizeof(key->e) && key->e[e_offset] == 0) e_offset++;
    CRYPT_EAL_PkeyPub pub = {0};
    pub.id = CRYPT_PKEY_RSA;
    pub.key.rsaPub.n = (BYTE *)n;
    pub.key.rsaPub.nLen = bytes;
    pub.key.rsaPub.e = (BYTE *)(key->e + e_offset);
    pub.key.rsaPub.eLen = (uint32_t)(sizeof(key->e) - e_offset);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (ctx == NULL || CRYPT_EAL_PkeySetPub(ctx, &pub) != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

static CRYPT_EAL_PkeyCtx *rsa_ctx_from_private(const RSArefPrivateKey *key)
{
    if (key == NULL || key->bits < 1024 || key->bits > RSAref_MAX_BITS ||
        (key->bits & 7U) != 0) return NULL;
    uint32_t bytes = key->bits / 8;
    uint32_t half = bytes / 2;
    CRYPT_EAL_PkeyPrv prv = {0};
    prv.id = CRYPT_PKEY_RSA;
    prv.key.rsaPrv.n = (BYTE *)rsa_component(key->m, sizeof(key->m), bytes);
    prv.key.rsaPrv.nLen = bytes;
    prv.key.rsaPrv.d = (BYTE *)rsa_component(key->d, sizeof(key->d), bytes);
    prv.key.rsaPrv.dLen = bytes;
    size_t e_offset = 0;
    while (e_offset + 1 < sizeof(key->e) && key->e[e_offset] == 0) e_offset++;
    prv.key.rsaPrv.e = (BYTE *)(key->e + e_offset);
    prv.key.rsaPrv.eLen = (uint32_t)(sizeof(key->e) - e_offset);
    prv.key.rsaPrv.p = (BYTE *)rsa_component(key->prime[0], sizeof(key->prime[0]), half);
    prv.key.rsaPrv.pLen = half;
    prv.key.rsaPrv.q = (BYTE *)rsa_component(key->prime[1], sizeof(key->prime[1]), half);
    prv.key.rsaPrv.qLen = half;
    prv.key.rsaPrv.dP = (BYTE *)rsa_component(key->pexp[0], sizeof(key->pexp[0]), half);
    prv.key.rsaPrv.dPLen = half;
    prv.key.rsaPrv.dQ = (BYTE *)rsa_component(key->pexp[1], sizeof(key->pexp[1]), half);
    prv.key.rsaPrv.dQLen = half;
    prv.key.rsaPrv.qInv = (BYTE *)rsa_component(key->coef, sizeof(key->coef), half);
    prv.key.rsaPrv.qInvLen = half;
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (ctx == NULL || CRYPT_EAL_PkeySetPrv(ctx, &prv) != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

static int rsa_set_padding(CRYPT_EAL_PkeyCtx *ctx, int wrapped)
{
    if (wrapped) {
        int32_t md = CRYPT_MD_SHA256;
        return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15,
                                 &md, sizeof(md)) == CRYPT_SUCCESS
            ? SDR_OK : SDR_KEYERR;
    }
    int32_t no_pad = CRYPT_RSA_NO_PAD;
    return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_PADDING,
                             &no_pad, sizeof(no_pad)) == CRYPT_SUCCESS
        ? SDR_OK : SDR_KEYERR;
}

int crypto_rsa_generate_keypair(uint32_t bits, RSArefPublicKey *public_key,
                                RSArefPrivateKey *private_key)
{
    if (public_key == NULL || private_key == NULL || bits < 1024 ||
        bits > RSAref_MAX_BITS || (bits % 256U) != 0) return SDR_INARGERR;
    int ret = ensure_hitls_init();
    if (ret != SDR_OK) return ret;
    BYTE exponent[] = {0x01, 0x00, 0x01};
    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.e = exponent;
    para.para.rsaPara.eLen = sizeof(exponent);
    para.para.rsaPara.bits = bits;
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (ctx == NULL) return SDR_NOBUFFER;
    if (CRYPT_EAL_PkeySetPara(ctx, &para) != CRYPT_SUCCESS ||
        CRYPT_EAL_PkeyGen(ctx) != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return SDR_KEYERR;
    }
    BYTE n[RSAref_MAX_LEN], e[RSAref_MAX_LEN], d[RSAref_MAX_LEN];
    BYTE p[RSAref_MAX_PLEN], q[RSAref_MAX_PLEN];
    BYTE dp[RSAref_MAX_PLEN], dq[RSAref_MAX_PLEN], qi[RSAref_MAX_PLEN];
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    pub.id = CRYPT_PKEY_RSA;
    pub.key.rsaPub.n = n; pub.key.rsaPub.nLen = sizeof(n);
    pub.key.rsaPub.e = e; pub.key.rsaPub.eLen = sizeof(e);
    prv.id = CRYPT_PKEY_RSA;
    prv.key.rsaPrv.n = n; prv.key.rsaPrv.nLen = sizeof(n);
    prv.key.rsaPrv.e = e; prv.key.rsaPrv.eLen = sizeof(e);
    prv.key.rsaPrv.d = d; prv.key.rsaPrv.dLen = sizeof(d);
    prv.key.rsaPrv.p = p; prv.key.rsaPrv.pLen = sizeof(p);
    prv.key.rsaPrv.q = q; prv.key.rsaPrv.qLen = sizeof(q);
    prv.key.rsaPrv.dP = dp; prv.key.rsaPrv.dPLen = sizeof(dp);
    prv.key.rsaPrv.dQ = dq; prv.key.rsaPrv.dQLen = sizeof(dq);
    prv.key.rsaPrv.qInv = qi; prv.key.rsaPrv.qInvLen = sizeof(qi);
    if (CRYPT_EAL_PkeyGetPub(ctx, &pub) != CRYPT_SUCCESS ||
        CRYPT_EAL_PkeyGetPrv(ctx, &prv) != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return SDR_KEYERR;
    }
    memset(public_key, 0, sizeof(*public_key));
    memset(private_key, 0, sizeof(*private_key));
    public_key->bits = bits; private_key->bits = bits;
    rsa_right_align(public_key->m, sizeof(public_key->m), n, pub.key.rsaPub.nLen);
    rsa_right_align(public_key->e, sizeof(public_key->e), e, pub.key.rsaPub.eLen);
    rsa_right_align(private_key->m, sizeof(private_key->m), n, prv.key.rsaPrv.nLen);
    rsa_right_align(private_key->e, sizeof(private_key->e), e, prv.key.rsaPrv.eLen);
    rsa_right_align(private_key->d, sizeof(private_key->d), d, prv.key.rsaPrv.dLen);
    rsa_right_align(private_key->prime[0], sizeof(private_key->prime[0]), p, prv.key.rsaPrv.pLen);
    rsa_right_align(private_key->prime[1], sizeof(private_key->prime[1]), q, prv.key.rsaPrv.qLen);
    rsa_right_align(private_key->pexp[0], sizeof(private_key->pexp[0]), dp, prv.key.rsaPrv.dPLen);
    rsa_right_align(private_key->pexp[1], sizeof(private_key->pexp[1]), dq, prv.key.rsaPrv.dQLen);
    rsa_right_align(private_key->coef, sizeof(private_key->coef), qi, prv.key.rsaPrv.qInvLen);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    rsa_secure_clear(d, sizeof(d)); rsa_secure_clear(p, sizeof(p)); rsa_secure_clear(q, sizeof(q));
    rsa_secure_clear(dp, sizeof(dp)); rsa_secure_clear(dq, sizeof(dq)); rsa_secure_clear(qi, sizeof(qi));
    return SDR_OK;
}

int crypto_rsa_public_operation(const RSArefPublicKey *key, const BYTE *input,
                                uint32_t input_len, BYTE *output,
                                uint32_t *output_len, int wrapped)
{
    if (key == NULL || input == NULL || output == NULL || output_len == NULL)
        return SDR_INARGERR;
    uint32_t modulus_len = key->bits / 8;
    if ((!wrapped && input_len != modulus_len) ||
        (wrapped && (input_len == 0 || input_len > modulus_len - 11)) ||
        *output_len < modulus_len) {
        *output_len = modulus_len;
        return SDR_INARGERR;
    }
    CRYPT_EAL_PkeyCtx *ctx = rsa_ctx_from_public(key);
    if (ctx == NULL) return SDR_KEYERR;
    int ret = rsa_set_padding(ctx, wrapped);
    uint32_t length = *output_len;
    if (ret == SDR_OK && CRYPT_EAL_PkeyEncrypt(ctx, input, input_len,
                                               output, &length) != CRYPT_SUCCESS)
        ret = SDR_PKOPERR;
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret == SDR_OK) *output_len = length;
    return ret;
}

int crypto_rsa_private_operation(const RSArefPrivateKey *key, const BYTE *input,
                                 uint32_t input_len, BYTE *output,
                                 uint32_t *output_len, int wrapped)
{
    if (key == NULL || input == NULL || output == NULL || output_len == NULL)
        return SDR_INARGERR;
    uint32_t modulus_len = key->bits / 8;
    if (input_len != modulus_len || *output_len < (wrapped ? 32U : modulus_len))
        return SDR_INARGERR;
    CRYPT_EAL_PkeyCtx *ctx = rsa_ctx_from_private(key);
    if (ctx == NULL) return SDR_KEYERR;
    int ret = rsa_set_padding(ctx, wrapped);
    uint32_t length = *output_len;
    if (ret == SDR_OK && CRYPT_EAL_PkeyDecrypt(ctx, input, input_len,
                                               output, &length) != CRYPT_SUCCESS)
        ret = SDR_SKOPERR;
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret == SDR_OK) *output_len = length;
    return ret;
}

