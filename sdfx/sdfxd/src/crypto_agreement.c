/*
 * GM/T 0018-2023 SM2 key agreement.
 */
#include <stdlib.h>
#include <string.h>

#include "daemon_internal.h"
#include "hitls_init.h"
#include "hitls/crypto/crypt_eal_pkey.h"
#include "hitls/crypto/crypt_algid.h"
#include "hitls/crypto/crypt_errno.h"

typedef struct agreement_state {
    uint64_t id;
    uint32_t key_bits;
    BYTE *self_id;
    uint32_t self_id_len;
    ECCrefPublicKey static_public;
    ECCrefPrivateKey static_private;
    ECCrefPublicKey temporary_public;
    ECCrefPrivateKey temporary_private;
    struct agreement_state *next;
} agreement_state_t;

static void agreement_clear(agreement_state_t *state)
{
    if (state == NULL) {
        return;
    }
    if (state->self_id != NULL) {
        memset(state->self_id, 0, state->self_id_len);
        free(state->self_id);
    }
    memset(state, 0, sizeof(*state));
}

void crypto_agreement_cleanup_session(session_info_t *session)
{
    if (session == NULL) {
        return;
    }
    pthread_mutex_lock(&session->object_mutex);
    agreement_state_t *state = (agreement_state_t *)session->agreements;
    session->agreements = NULL;
    while (state != NULL) {
        agreement_state_t *next = state->next;
        agreement_clear(state);
        free(state);
        state = next;
    }
    pthread_mutex_unlock(&session->object_mutex);
}

static int agreement_parameters_valid(uint32_t key_bits,
                                      const BYTE *identity,
                                      uint32_t identity_len)
{
    return key_bits >= 64 && key_bits <= 512 && (key_bits % 8) == 0 &&
           identity != NULL && identity_len > 0 &&
           identity_len <= SDFX_MAX_SM2_ID_LENGTH;
}

static void encode_public(const ECCrefPublicKey *key, BYTE encoded[65])
{
    encoded[0] = 0x04;
    memcpy(encoded + 1, key->x + ECCref_MAX_LEN - 32, 32);
    memcpy(encoded + 33, key->y + ECCref_MAX_LEN - 32, 32);
}

static CRYPT_EAL_PkeyCtx *agreement_context(
    const ECCrefPublicKey *static_public,
    const ECCrefPrivateKey *static_private,
    const BYTE *identity, uint32_t identity_len,
    int server, const ECCrefPublicKey *temporary_public,
    const ECCrefPrivateKey *temporary_private)
{
    if (static_public == NULL || identity == NULL ||
        temporary_public == NULL || static_public->bits != 256 ||
        temporary_public->bits != 256) {
        return NULL;
    }

    BYTE encoded_static[65];
    BYTE encoded_temporary[65];
    encode_public(static_public, encoded_static);
    encode_public(temporary_public, encoded_temporary);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (ctx == NULL) {
        return NULL;
    }

    CRYPT_EAL_PkeyPub public_key = {0};
    public_key.id = CRYPT_PKEY_SM2;
    public_key.key.eccPub.data = encoded_static;
    public_key.key.eccPub.len = sizeof(encoded_static);
    int32_t ret = CRYPT_EAL_PkeySetPub(ctx, &public_key);

    if (ret == CRYPT_SUCCESS && static_private != NULL) {
        if (static_private->bits != 256) {
            ret = CRYPT_INVALID_ARG;
        } else {
            CRYPT_EAL_PkeyPrv private_key = {0};
            private_key.id = CRYPT_PKEY_SM2;
            private_key.key.eccPrv.data =
                (BYTE *)(static_private->K + ECCref_MAX_LEN - 32);
            private_key.key.eccPrv.len = 32;
            ret = CRYPT_EAL_PkeySetPrv(ctx, &private_key);
        }
    }
    if (ret == CRYPT_SUCCESS) {
        ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID,
                                 (void *)identity, identity_len);
    }
    if (ret == CRYPT_SUCCESS) {
        int32_t role = server;
        ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_SERVER,
                                 &role, sizeof(role));
    }
    if (ret == CRYPT_SUCCESS && temporary_private != NULL) {
        if (temporary_private->bits != 256) {
            ret = CRYPT_INVALID_ARG;
        } else {
            ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_RANDOM,
                (void *)(temporary_private->K + ECCref_MAX_LEN - 32), 32);
        }
    } else if (ret == CRYPT_SUCCESS) {
        ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_R,
                                 encoded_temporary,
                                 sizeof(encoded_temporary));
    }

    memset(encoded_static, 0, sizeof(encoded_static));
    memset(encoded_temporary, 0, sizeof(encoded_temporary));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

static int compute_agreement_key(
    int self_is_server, uint32_t key_bits,
    const BYTE *self_id, uint32_t self_id_len,
    const ECCrefPublicKey *self_public,
    const ECCrefPrivateKey *self_private,
    const ECCrefPublicKey *self_temporary_public,
    const ECCrefPrivateKey *self_temporary_private,
    const BYTE *peer_id, uint32_t peer_id_len,
    const ECCrefPublicKey *peer_public,
    const ECCrefPublicKey *peer_temporary_public,
    BYTE output[64], uint32_t *output_len)
{
    if (!sdfx_hitls_is_initialized() || output == NULL || output_len == NULL ||
        !agreement_parameters_valid(key_bits, self_id, self_id_len) ||
        peer_id == NULL || peer_id_len == 0 ||
        peer_id_len > SDFX_MAX_SM2_ID_LENGTH) {
        return SDR_INARGERR;
    }

    CRYPT_EAL_PkeyCtx *self = agreement_context(self_public, self_private,
        self_id, self_id_len, self_is_server, self_temporary_public,
        self_temporary_private);
    CRYPT_EAL_PkeyCtx *peer = agreement_context(peer_public, NULL,
        peer_id, peer_id_len, !self_is_server, peer_temporary_public, NULL);
    if (self == NULL || peer == NULL) {
        CRYPT_EAL_PkeyFreeCtx(self);
        CRYPT_EAL_PkeyFreeCtx(peer);
        return SDR_KEYERR;
    }

    uint32_t length = key_bits / 8;
    int32_t ret = CRYPT_EAL_PkeyComputeShareKey(self, peer, output, &length);
    CRYPT_EAL_PkeyFreeCtx(self);
    CRYPT_EAL_PkeyFreeCtx(peer);
    if (ret != CRYPT_SUCCESS || length != key_bits / 8) {
        memset(output, 0, 64);
        return SDR_KEYERR;
    }
    *output_len = length;
    return SDR_OK;
}

int crypto_agreement_generate_sponsor(
    session_info_t *session, uint32_t key_index, uint32_t key_bits,
    const BYTE *sponsor_id, uint32_t sponsor_id_len,
    ECCrefPublicKey *sponsor_public,
    ECCrefPublicKey *sponsor_temporary_public,
    uint64_t *agreement_id)
{
    if (session == NULL || sponsor_public == NULL ||
        sponsor_temporary_public == NULL || agreement_id == NULL ||
        !agreement_parameters_valid(key_bits, sponsor_id, sponsor_id_len)) {
        return SDR_INARGERR;
    }

    agreement_state_t *state = calloc(1, sizeof(*state));
    if (state == NULL) {
        return SDR_NOBUFFER;
    }
    state->self_id = malloc(sponsor_id_len);
    if (state->self_id == NULL) {
        free(state);
        return SDR_NOBUFFER;
    }
    memcpy(state->self_id, sponsor_id, sponsor_id_len);
    state->self_id_len = sponsor_id_len;
    state->key_bits = key_bits;

    int ret = internal_key_load_private_for_agreement(session, key_index,
                                                       &state->static_private);
    if (ret == SDR_OK) {
        ret = internal_key_export_public(SDFX_INTERNAL_KEY_ENC, key_index,
                                          &state->static_public);
    }
    if (ret == SDR_OK) {
        ret = crypto_sm2_generate_keypair(&state->temporary_public,
                                           &state->temporary_private);
    }
    if (ret != SDR_OK) {
        agreement_clear(state);
        free(state);
        return ret;
    }

    pthread_mutex_lock(&session->object_mutex);
    if (session->next_agreement_id == 0) {
        session->next_agreement_id = 1;
    }
    state->id = session->next_agreement_id++;
    state->next = (agreement_state_t *)session->agreements;
    session->agreements = state;
    pthread_mutex_unlock(&session->object_mutex);

    memcpy(sponsor_public, &state->static_public, sizeof(*sponsor_public));
    memcpy(sponsor_temporary_public, &state->temporary_public,
           sizeof(*sponsor_temporary_public));
    *agreement_id = state->id;
    return SDR_OK;
}

int crypto_agreement_complete_sponsor(
    session_info_t *session, uint64_t agreement_id,
    const BYTE *response_id, uint32_t response_id_len,
    const ECCrefPublicKey *response_public,
    const ECCrefPublicKey *response_temporary_public,
    uint64_t *key_id)
{
    if (session == NULL || agreement_id == 0 || response_public == NULL ||
        response_temporary_public == NULL || key_id == NULL ||
        response_id == NULL || response_id_len == 0 ||
        response_id_len > SDFX_MAX_SM2_ID_LENGTH) {
        return SDR_INARGERR;
    }

    pthread_mutex_lock(&session->object_mutex);
    agreement_state_t **cursor = (agreement_state_t **)&session->agreements;
    while (*cursor != NULL && (*cursor)->id != agreement_id) {
        cursor = &(*cursor)->next;
    }
    agreement_state_t *state = *cursor;
    if (state != NULL) {
        *cursor = state->next;
    }
    pthread_mutex_unlock(&session->object_mutex);
    if (state == NULL) {
        return SDR_INVALID_HANDLE;
    }

    BYTE key[64] = {0};
    uint32_t key_len = 0;
    int ret = compute_agreement_key(0, state->key_bits,
        state->self_id, state->self_id_len,
        &state->static_public, &state->static_private,
        &state->temporary_public, &state->temporary_private,
        response_id, response_id_len, response_public,
        response_temporary_public, key, &key_len);
    if (ret == SDR_OK) {
        ret = session_key_create(session, key, key_len, key_id);
    }
    memset(key, 0, sizeof(key));
    agreement_clear(state);
    free(state);
    return ret;
}

int crypto_agreement_generate_response(
    session_info_t *session, uint32_t key_index, uint32_t key_bits,
    const BYTE *response_id, uint32_t response_id_len,
    const BYTE *sponsor_id, uint32_t sponsor_id_len,
    const ECCrefPublicKey *sponsor_public,
    const ECCrefPublicKey *sponsor_temporary_public,
    ECCrefPublicKey *response_public,
    ECCrefPublicKey *response_temporary_public,
    uint64_t *key_id)
{
    if (session == NULL || sponsor_public == NULL ||
        sponsor_temporary_public == NULL || response_public == NULL ||
        response_temporary_public == NULL || key_id == NULL ||
        !agreement_parameters_valid(key_bits, response_id, response_id_len) ||
        sponsor_id == NULL || sponsor_id_len == 0 ||
        sponsor_id_len > SDFX_MAX_SM2_ID_LENGTH) {
        return SDR_INARGERR;
    }

    ECCrefPrivateKey static_private;
    ECCrefPrivateKey temporary_private;
    BYTE key[64] = {0};
    uint32_t key_len = 0;
    memset(&static_private, 0, sizeof(static_private));
    memset(&temporary_private, 0, sizeof(temporary_private));

    int ret = internal_key_load_private_for_agreement(session, key_index,
                                                       &static_private);
    if (ret == SDR_OK) {
        ret = internal_key_export_public(SDFX_INTERNAL_KEY_ENC, key_index,
                                          response_public);
    }
    if (ret == SDR_OK) {
        ret = crypto_sm2_generate_keypair(response_temporary_public,
                                           &temporary_private);
    }
    if (ret == SDR_OK) {
        ret = compute_agreement_key(1, key_bits, response_id, response_id_len,
            response_public, &static_private, response_temporary_public,
            &temporary_private, sponsor_id, sponsor_id_len, sponsor_public,
            sponsor_temporary_public, key, &key_len);
    }
    if (ret == SDR_OK) {
        ret = session_key_create(session, key, key_len, key_id);
    }

    memset(&static_private, 0, sizeof(static_private));
    memset(&temporary_private, 0, sizeof(temporary_private));
    memset(key, 0, sizeof(key));
    return ret;
}
