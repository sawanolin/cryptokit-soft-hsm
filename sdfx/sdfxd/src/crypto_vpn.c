/*
 * Appendix C VPN key derivation helpers (GM/T 0022 and GM/T 0024 profiles).
 */
#include <stdlib.h>
#include <string.h>

#include "daemon_internal.h"
#include "hitls/crypto/crypt_eal_mac.h"
#include "hitls/crypto/crypt_algid.h"
#include "hitls/crypto/crypt_errno.h"

static CRYPT_MAC_AlgId vpn_hmac_alg(ULONG alg_id)
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

static int hmac_once(CRYPT_MAC_AlgId alg, const BYTE *key, uint32_t key_len,
                     const BYTE *first, uint32_t first_len,
                     const BYTE *second, uint32_t second_len,
                     const BYTE *third, uint32_t third_len,
                     BYTE output[64], uint32_t *output_len)
{
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg);
    if (ctx == NULL) return SDR_NOBUFFER;
    int32_t ret = CRYPT_EAL_MacInit(ctx, key, key_len);
    if (ret == CRYPT_SUCCESS && first_len > 0)
        ret = CRYPT_EAL_MacUpdate(ctx, first, first_len);
    if (ret == CRYPT_SUCCESS && second_len > 0)
        ret = CRYPT_EAL_MacUpdate(ctx, second, second_len);
    if (ret == CRYPT_SUCCESS && third_len > 0)
        ret = CRYPT_EAL_MacUpdate(ctx, third, third_len);
    uint32_t length = 64;
    if (ret == CRYPT_SUCCESS)
        ret = CRYPT_EAL_MacFinal(ctx, output, &length);
    CRYPT_EAL_MacFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) return SDR_SYMOPERR;
    *output_len = length;
    return SDR_OK;
}

static int prf_expand(ULONG alg_id, const BYTE *key, uint32_t key_len,
                      const BYTE *label, uint32_t label_len,
                      const BYTE *seed, uint32_t seed_len,
                      BYTE *output, uint32_t output_len)
{
    CRYPT_MAC_AlgId alg = vpn_hmac_alg(alg_id);
    if (alg == CRYPT_MAC_MAX) return SDR_ALGNOTSUPPORT;
    if (key == NULL || key_len == 0 || output == NULL || output_len == 0 ||
        (label_len > 0 && label == NULL) || (seed_len > 0 && seed == NULL))
        return SDR_INARGERR;

    BYTE a[64] = {0};
    BYTE block[64] = {0};
    uint32_t a_len = 0;
    uint32_t written = 0;
    int ret = hmac_once(alg, key, key_len, label, label_len,
                        seed, seed_len, NULL, 0, a, &a_len);
    while (ret == SDR_OK && written < output_len) {
        uint32_t block_len = 0;
        ret = hmac_once(alg, key, key_len, a, a_len,
                        label, label_len, seed, seed_len,
                        block, &block_len);
        if (ret != SDR_OK) break;
        uint32_t take = output_len - written;
        if (take > block_len) take = block_len;
        memcpy(output + written, block, take);
        written += take;
        BYTE next_a[64] = {0};
        uint32_t next_a_len = 0;
        ret = hmac_once(alg, key, key_len, a, a_len,
                        NULL, 0, NULL, 0, next_a, &next_a_len);
        memset(a, 0, sizeof(a));
        memcpy(a, next_a, next_a_len);
        a_len = next_a_len;
        memset(next_a, 0, sizeof(next_a));
    }
    memset(a, 0, sizeof(a));
    memset(block, 0, sizeof(block));
    return ret;
}
static int validate_key_bits(const uint32_t *bits, size_t count,
                             uint32_t *total_bytes)
{
    uint32_t total = 0;
    for (size_t i = 0; i < count; ++i) {
        if (bits[i] == 0) continue;
        if (bits[i] > 512 || (bits[i] % 8) != 0)
            return SDR_INARGERR;
        total += bits[i] / 8;
    }
    *total_bytes = total;
    return total <= 256 ? SDR_OK : SDR_INARGERR;
}

int crypto_vpn_derive_ike(ULONG prf_alg,
                          const BYTE *ni, uint32_t ni_len,
                          const BYTE *nr, uint32_t nr_len,
                          const BYTE *cookie_i, uint32_t cookie_i_len,
                          const BYTE *cookie_r, uint32_t cookie_r_len,
                          const uint32_t bits[3], BYTE output[192])
{
    if (ni == NULL || nr == NULL || cookie_i == NULL || cookie_r == NULL ||
        ni_len == 0 || nr_len == 0 || cookie_i_len == 0 || cookie_r_len == 0)
        return SDR_INARGERR;
    uint32_t total = 0;
    int ret = validate_key_bits(bits, 3, &total);
    if (ret != SDR_OK || total > 192) return SDR_INARGERR;

    uint32_t nonce_len = ni_len + nr_len;
    uint32_t cookie_len = cookie_i_len + cookie_r_len;
    BYTE *nonces = malloc(nonce_len);
    BYTE *cookies = malloc(cookie_len);
    if (nonces == NULL || cookies == NULL) {
        free(nonces); free(cookies); return SDR_NOBUFFER;
    }
    memcpy(nonces, ni, ni_len); memcpy(nonces + ni_len, nr, nr_len);
    memcpy(cookies, cookie_i, cookie_i_len);
    memcpy(cookies + cookie_i_len, cookie_r, cookie_r_len);

    CRYPT_MAC_AlgId alg = vpn_hmac_alg(prf_alg);
    BYTE skeyid[64] = {0};
    uint32_t skeyid_len = 0;
    if (alg == CRYPT_MAC_MAX) ret = SDR_ALGNOTSUPPORT;
    else ret = hmac_once(alg, nonces, nonce_len, cookies, cookie_len,
                         NULL, 0, NULL, 0, skeyid, &skeyid_len);
    if (ret == SDR_OK)
        ret = prf_expand(prf_alg, skeyid, skeyid_len,
                         (const BYTE *)"IKE key expansion", 17,
                         cookies, cookie_len, output, total);
    memset(skeyid, 0, sizeof(skeyid));
    memset(nonces, 0, nonce_len); memset(cookies, 0, cookie_len);
    free(nonces); free(cookies);
    return ret;
}

int crypto_vpn_derive_ipsec(ULONG prf_alg, const BYTE *base_key,
                            uint32_t base_key_len,
                            const BYTE *protocol, uint32_t protocol_len,
                            const BYTE *spi, uint32_t spi_len,
                            const BYTE *ni, uint32_t ni_len,
                            const BYTE *nr, uint32_t nr_len,
                            const uint32_t bits[2], uint32_t salt_len,
                            BYTE output[132])
{
    if (base_key == NULL || base_key_len == 0 || protocol == NULL ||
        spi == NULL || ni == NULL || nr == NULL || protocol_len == 0 ||
        spi_len == 0 || ni_len == 0 || nr_len == 0 || salt_len > 32)
        return SDR_INARGERR;
    uint32_t key_total = 0;
    int ret = validate_key_bits(bits, 2, &key_total);
    if (ret != SDR_OK || key_total + salt_len > 132) return SDR_INARGERR;
    uint32_t seed_len = protocol_len + spi_len + ni_len + nr_len;
    BYTE *seed = malloc(seed_len);
    if (seed == NULL) return SDR_NOBUFFER;
    BYTE *cursor = seed;
    memcpy(cursor, protocol, protocol_len); cursor += protocol_len;
    memcpy(cursor, spi, spi_len); cursor += spi_len;
    memcpy(cursor, ni, ni_len); cursor += ni_len;
    memcpy(cursor, nr, nr_len);
    ret = prf_expand(prf_alg, base_key, base_key_len,
                     (const BYTE *)"IPSEC key expansion", 19,
                     seed, seed_len, output, key_total + salt_len);
    memset(seed, 0, seed_len); free(seed);
    return ret;
}

int crypto_vpn_derive_ssl(ULONG prf_alg, const BYTE *pre_master,
                          uint32_t pre_master_len,
                          const BYTE *client_random, uint32_t client_len,
                          const BYTE *server_random, uint32_t server_len,
                          const uint32_t bits[4], uint32_t client_iv_len,
                          uint32_t server_iv_len, BYTE output[320])
{
    if (pre_master == NULL || pre_master_len == 0 || client_random == NULL ||
        server_random == NULL || client_len == 0 || server_len == 0 ||
        client_iv_len > 64 || server_iv_len > 64) return SDR_INARGERR;
    uint32_t key_total = 0;
    int ret = validate_key_bits(bits, 4, &key_total);
    uint32_t total = key_total + client_iv_len + server_iv_len;
    if (ret != SDR_OK || total > 320) return SDR_INARGERR;

    uint32_t random_len = client_len + server_len;
    BYTE *randoms = malloc(random_len);
    BYTE *reversed = malloc(random_len);
    if (randoms == NULL || reversed == NULL) {
        free(randoms); free(reversed); return SDR_NOBUFFER;
    }
    memcpy(randoms, client_random, client_len);
    memcpy(randoms + client_len, server_random, server_len);
    memcpy(reversed, server_random, server_len);
    memcpy(reversed + server_len, client_random, client_len);

    BYTE master[48] = {0};
    ret = prf_expand(prf_alg, pre_master, pre_master_len,
                     (const BYTE *)"master secret", 13,
                     randoms, random_len, master, sizeof(master));
    if (ret == SDR_OK)
        ret = prf_expand(prf_alg, master, sizeof(master),
                         (const BYTE *)"key expansion", 13,
                         reversed, random_len, output, total);
    memset(master, 0, sizeof(master));
    memset(randoms, 0, random_len); memset(reversed, 0, random_len);
    free(randoms); free(reversed);
    return ret;
}
