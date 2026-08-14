/*
 * GM/T 0018-2023 streaming symmetric, authenticated encryption and HMAC.
 */
#include <stdlib.h>
#include <string.h>

#include "daemon_internal.h"
#include "hitls/crypto/crypt_eal_cipher.h"
#include "hitls/crypto/crypt_eal_mac.h"
#include "hitls/crypto/crypt_algid.h"
#include "hitls/crypto/crypt_errno.h"

typedef struct extended_cipher_state {
    CRYPT_EAL_CipherCtx *ctx;
    int authenticated;
    int decrypt;
    BYTE expected_tag[16];
    uint32_t expected_tag_len;
} extended_cipher_state_t;

typedef struct extended_mac_state {
    int hmac;
    CRYPT_EAL_MacCtx *hmac_ctx;
    BYTE key[64];
    uint32_t key_len;
    ULONG alg_id;
    BYTE iv[16];
    BYTE *data;
    uint32_t data_len;
    uint32_t data_capacity;
} extended_mac_state_t;

static CRYPT_CIPHER_AlgId extended_cipher_alg(ULONG alg_id)
{
    switch (alg_id) {
        case SGD_SM4_ECB: return CRYPT_CIPHER_SM4_ECB;
        case SGD_SM4_CBC: return CRYPT_CIPHER_SM4_CBC;
        case SGD_SM4_CFB: return CRYPT_CIPHER_SM4_CFB;
        case SGD_SM4_OFB: return CRYPT_CIPHER_SM4_OFB;
        case SGD_SM4_CTR: return CRYPT_CIPHER_SM4_CTR;
        case SGD_SM4_XTS: return CRYPT_CIPHER_SM4_XTS;
        case SGD_SM4_GCM: return CRYPT_CIPHER_SM4_GCM;
        case SGD_SM4_CCM: return CRYPT_CIPHER_SM4_CCM;
        default: return CRYPT_CIPHER_MAX;
    }
}

static CRYPT_MAC_AlgId extended_hmac_alg(ULONG alg_id)
{
    switch (alg_id) {
        case SGD_SM3:
        case SGD_SM3_HMAC: return CRYPT_MAC_HMAC_SM3;
        case SDFX_SHA1: return CRYPT_MAC_HMAC_SHA1;
        case SDFX_SHA224: return CRYPT_MAC_HMAC_SHA224;
        case SGD_SHA256:
        case SGD_SHA256_HMAC: return CRYPT_MAC_HMAC_SHA256;
        case SDFX_SHA384: return CRYPT_MAC_HMAC_SHA384;
        case SDFX_SHA512: return CRYPT_MAC_HMAC_SHA512;
        default: return CRYPT_MAC_MAX;
    }
}

static int constant_time_equal(const BYTE *a, const BYTE *b, uint32_t len)
{
    BYTE difference = 0;
    for (uint32_t i = 0; i < len; ++i) {
        difference |= (BYTE)(a[i] ^ b[i]);
    }
    return difference == 0;
}

static void cipher_state_free(session_info_t *session)
{
    extended_cipher_state_t *state =
        session == NULL ? NULL : (extended_cipher_state_t *)session->cipher_ctx;
    if (state != NULL) {
        CRYPT_EAL_CipherFreeCtx(state->ctx);
        memset(state, 0, sizeof(*state));
        free(state);
        session->cipher_ctx = NULL;
    }
}

static void mac_state_free(session_info_t *session)
{
    extended_mac_state_t *state =
        session == NULL ? NULL : (extended_mac_state_t *)session->mac_ctx;
    if (state != NULL) {
        CRYPT_EAL_MacFreeCtx(state->hmac_ctx);
        if (state->data != NULL) {
            memset(state->data, 0, state->data_capacity);
            free(state->data);
        }
        memset(state, 0, sizeof(*state));
        free(state);
        session->mac_ctx = NULL;
    }
}

void crypto_extended_cleanup_session(session_info_t *session)
{
    cipher_state_free(session);
    mac_state_free(session);
}

int crypto_extended_cipher_init(session_info_t *session, const BYTE *key,
                                uint32_t key_len, ULONG alg_id,
                                const BYTE *iv, uint32_t iv_len, int decrypt,
                                const BYTE *aad, uint32_t aad_len,
                                const BYTE *tag, uint32_t tag_len,
                                uint32_t total_data_len)
{
    if (session == NULL || key == NULL) {
        return SDR_INARGERR;
    }

    CRYPT_CIPHER_AlgId cipher_alg = extended_cipher_alg(alg_id);
    if (cipher_alg == CRYPT_CIPHER_MAX) {
        return SDR_ALGNOTSUPPORT;
    }

    int authenticated = (alg_id == SGD_SM4_GCM || alg_id == SGD_SM4_CCM);
    uint32_t required_key_len = alg_id == SGD_SM4_XTS ? 32U : 16U;
    if (key_len != required_key_len ||
        (!authenticated && tag_len != 0) ||
        (alg_id == SGD_SM4_ECB && (iv != NULL || iv_len != 0)) ||
        ((alg_id == SGD_SM4_CBC || alg_id == SGD_SM4_CFB ||
          alg_id == SGD_SM4_OFB || alg_id == SGD_SM4_CTR ||
          alg_id == SGD_SM4_XTS) && (iv == NULL || iv_len != 16)) ||
        (alg_id == SGD_SM4_GCM &&
         (iv == NULL || iv_len == 0 || iv_len > 64 ||
          tag_len == 0 || tag_len > 16 || (decrypt && tag == NULL))) ||
        (alg_id == SGD_SM4_CCM &&
         (iv == NULL || iv_len < 7 || iv_len > 13 ||
          tag_len < 4 || tag_len > 16 || (tag_len & 1U) != 0 ||
          (decrypt && tag == NULL))) ||
        (aad_len > 0 && aad == NULL)) {
        return SDR_INARGERR;
    }

    cipher_state_free(session);
    extended_cipher_state_t *state = calloc(1, sizeof(*state));
    if (state == NULL) {
        return SDR_NOBUFFER;
    }
    state->ctx = CRYPT_EAL_CipherNewCtx(cipher_alg);
    if (state->ctx == NULL) {
        free(state);
        return SDR_NOBUFFER;
    }

    int32_t hitls_ret = CRYPT_EAL_CipherInit(state->ctx, key, key_len,
                                             iv, iv_len, decrypt == 0);
    if (hitls_ret == CRYPT_SUCCESS && authenticated) {
        uint32_t configured_tag_len = tag_len;
        hitls_ret = CRYPT_EAL_CipherCtrl(state->ctx, CRYPT_CTRL_SET_TAGLEN,
                                         &configured_tag_len,
                                         sizeof(configured_tag_len));
        if (hitls_ret == CRYPT_SUCCESS && alg_id == SGD_SM4_CCM) {
            uint64_t message_length = total_data_len;
            hitls_ret = CRYPT_EAL_CipherCtrl(state->ctx,
                                             CRYPT_CTRL_SET_MSGLEN,
                                             &message_length,
                                             sizeof(message_length));
        }
        if (hitls_ret == CRYPT_SUCCESS && aad_len > 0) {
            hitls_ret = CRYPT_EAL_CipherCtrl(state->ctx, CRYPT_CTRL_SET_AAD,
                                             (void *)aad, aad_len);
        }
        if (hitls_ret == CRYPT_SUCCESS && decrypt) {
            hitls_ret = CRYPT_EAL_CipherCtrl(state->ctx, CRYPT_CTRL_SET_TAG,
                                             (void *)tag, tag_len);
        }
    }
    if (hitls_ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(state->ctx);
        free(state);
        return SDR_SYMOPERR;
    }

    state->authenticated = authenticated;
    state->decrypt = decrypt != 0;
    state->expected_tag_len = authenticated ? tag_len : 0;
    session->cipher_ctx = state;
    return SDR_OK;
}
int crypto_extended_cipher_update(session_info_t *session,
                                  const BYTE *input, uint32_t input_len,
                                  BYTE *output, uint32_t *output_len)
{
    if (session == NULL || input == NULL || input_len == 0 ||
        output == NULL || output_len == NULL) {
        return SDR_INARGERR;
    }
    extended_cipher_state_t *state = (extended_cipher_state_t *)session->cipher_ctx;
    if (state == NULL || state->ctx == NULL) {
        return SDR_STEPERR;
    }

    uint32_t capacity = *output_len;
    int32_t ret = CRYPT_EAL_CipherUpdate(state->ctx, input, input_len,
                                         output, &capacity);
    if (ret != CRYPT_SUCCESS) {
        return SDR_SYMOPERR;
    }
    *output_len = capacity;
    return SDR_OK;
}

int crypto_extended_cipher_final(session_info_t *session,
                                 BYTE *output, uint32_t *output_len,
                                 BYTE *tag, uint32_t *tag_len)
{
    if (session == NULL || output_len == NULL) {
        return SDR_INARGERR;
    }
    extended_cipher_state_t *state = (extended_cipher_state_t *)session->cipher_ctx;
    if (state == NULL || state->ctx == NULL) {
        return SDR_STEPERR;
    }

    BYTE dummy[16] = {0};
    BYTE computed_tag[16] = {0};
    uint32_t capacity = *output_len;
    BYTE *target = output;
    if (target == NULL) {
        if (capacity != 0) {
            return SDR_INARGERR;
        }
        target = dummy;
        capacity = sizeof(dummy);
    }

    int result = SDR_OK;
    int32_t hitls_ret = CRYPT_EAL_CipherFinal(state->ctx, target, &capacity);
    if (hitls_ret != CRYPT_SUCCESS) {
        result = state->authenticated && state->decrypt ?
                 SDR_VERIFYERR : SDR_SYMOPERR;
    } else {
        *output_len = (output == NULL) ? 0 : capacity;
    }

    if (result == SDR_OK && state->authenticated && !state->decrypt) {
        hitls_ret = CRYPT_EAL_CipherCtrl(state->ctx, CRYPT_CTRL_GET_TAG,
                                         computed_tag,
                                         state->expected_tag_len);
        if (hitls_ret != CRYPT_SUCCESS) {
            result = SDR_SYMOPERR;
        } else if (tag == NULL || tag_len == NULL ||
                   *tag_len < state->expected_tag_len) {
            if (tag_len != NULL) {
                *tag_len = state->expected_tag_len;
            }
            result = SDR_NOBUFFER;
        } else {
            memcpy(tag, computed_tag, state->expected_tag_len);
            *tag_len = state->expected_tag_len;
        }
    }

    memset(computed_tag, 0, sizeof(computed_tag));
    cipher_state_free(session);
    return result;
}
int crypto_extended_mac_init(session_info_t *session, const BYTE *key,
                             uint32_t key_len, ULONG alg_id,
                             const BYTE *iv, uint32_t iv_len, int hmac)
{
    if (session == NULL || key == NULL || key_len == 0 || key_len > 64) {
        return SDR_INARGERR;
    }
    mac_state_free(session);

    extended_mac_state_t *state = calloc(1, sizeof(*state));
    if (state == NULL) {
        return SDR_NOBUFFER;
    }
    state->hmac = hmac != 0;
    state->alg_id = alg_id;
    state->key_len = key_len;
    memcpy(state->key, key, key_len);

    if (state->hmac) {
        CRYPT_MAC_AlgId mac_alg = extended_hmac_alg(alg_id);
        if (mac_alg == CRYPT_MAC_MAX) {
            free(state);
            return SDR_ALGNOTSUPPORT;
        }
        state->hmac_ctx = CRYPT_EAL_MacNewCtx(mac_alg);
        if (state->hmac_ctx == NULL) {
            free(state);
            return SDR_NOBUFFER;
        }
        if (CRYPT_EAL_MacInit(state->hmac_ctx, key, key_len) != CRYPT_SUCCESS) {
            CRYPT_EAL_MacFreeCtx(state->hmac_ctx);
            memset(state, 0, sizeof(*state));
            free(state);
            return SDR_SYMOPERR;
        }
    } else {
        if (alg_id != SGD_SM4_MAC || key_len != 16 ||
            (iv_len != 0 && iv_len != 16) || (iv_len > 0 && iv == NULL)) {
            memset(state, 0, sizeof(*state));
            free(state);
            return alg_id == SGD_SM4_MAC ? SDR_INARGERR : SDR_ALGNOTSUPPORT;
        }
        if (iv_len == 16) {
            memcpy(state->iv, iv, 16);
        }
    }

    session->mac_ctx = state;
    return SDR_OK;
}

int crypto_extended_mac_update(session_info_t *session,
                               const BYTE *input, uint32_t input_len)
{
    if (session == NULL || input == NULL || input_len == 0) {
        return SDR_INARGERR;
    }
    extended_mac_state_t *state = (extended_mac_state_t *)session->mac_ctx;
    if (state == NULL) {
        return SDR_STEPERR;
    }

    if (state->hmac) {
        return CRYPT_EAL_MacUpdate(state->hmac_ctx, input, input_len) ==
               CRYPT_SUCCESS ? SDR_OK : SDR_SYMOPERR;
    }

    if (input_len > SDFX_MAX_BLOB_LENGTH - state->data_len) {
        return SDR_INARGERR;
    }
    uint32_t needed = state->data_len + input_len;
    if (needed > state->data_capacity) {
        uint32_t capacity = state->data_capacity == 0 ? 256 : state->data_capacity;
        while (capacity < needed && capacity < SDFX_MAX_BLOB_LENGTH) {
            capacity *= 2;
        }
        if (capacity > SDFX_MAX_BLOB_LENGTH) {
            capacity = SDFX_MAX_BLOB_LENGTH;
        }
        BYTE *replacement = realloc(state->data, capacity);
        if (replacement == NULL) {
            return SDR_NOBUFFER;
        }
        state->data = replacement;
        state->data_capacity = capacity;
    }
    memcpy(state->data + state->data_len, input, input_len);
    state->data_len += input_len;
    return SDR_OK;
}

int crypto_extended_mac_final(session_info_t *session,
                              BYTE *output, uint32_t *output_len)
{
    if (session == NULL || output == NULL || output_len == NULL) {
        return SDR_INARGERR;
    }
    extended_mac_state_t *state = (extended_mac_state_t *)session->mac_ctx;
    if (state == NULL) {
        return SDR_STEPERR;
    }

    int result;
    if (state->hmac) {
        uint32_t capacity = *output_len;
        result = CRYPT_EAL_MacFinal(state->hmac_ctx, output, &capacity) ==
                 CRYPT_SUCCESS ? SDR_OK : SDR_SYMOPERR;
        if (result == SDR_OK) {
            *output_len = capacity;
        }
    } else if (state->data_len == 0 || (state->data_len % 16) != 0) {
        result = SDR_INARGERR;
    } else if (*output_len < 16) {
        *output_len = 16;
        result = SDR_NOBUFFER;
    } else {
        BYTE *ciphertext = malloc(state->data_len);
        if (ciphertext == NULL) {
            result = SDR_NOBUFFER;
        } else {
            ULONG ciphertext_len = state->data_len;
            result = crypto_symmetric_encrypt(SGD_SM4_CBC, state->key,
                state->key_len, state->iv, sizeof(state->iv),
                state->data, state->data_len, ciphertext, &ciphertext_len);
            if (result == SDR_OK && ciphertext_len >= 16) {
                memcpy(output, ciphertext + ciphertext_len - 16, 16);
                *output_len = 16;
            }
            memset(ciphertext, 0, state->data_len);
            free(ciphertext);
        }
    }

    mac_state_free(session);
    return result;
}
