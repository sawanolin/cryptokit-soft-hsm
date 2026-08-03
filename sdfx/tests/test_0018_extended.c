#include <stdio.h>
#include <string.h>

#include "sdf.h"

#define CHECK_OK(expr) do { \
    LONG check_ret = (expr); \
    if (check_ret != SDR_OK) { \
        fprintf(stderr, "%s failed: 0x%08x at line %d\n", #expr, \
                (unsigned int)check_ret, __LINE__); \
        return 1; \
    } \
} while (0)

static int test_external_symmetric(HANDLE session)
{
    BYTE key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    BYTE xts_key[32], iv[16], plain[32], cipher[64], recovered[64];
    ULONG cipher_len, recovered_len;
    for (size_t i = 0; i < sizeof(xts_key); ++i) xts_key[i] = (BYTE)i;
    for (size_t i = 0; i < sizeof(iv); ++i) iv[i] = (BYTE)(0xa0 + i);
    for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (BYTE)(0x30 + i);

    ULONG modes[] = {SGD_SM4_ECB, SGD_SM4_CBC};
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        BYTE *mode_iv = modes[i] == SGD_SM4_ECB ? NULL : iv;
        ULONG iv_len = mode_iv == NULL ? 0 : sizeof(iv);
        cipher_len = sizeof(cipher);
        CHECK_OK(SDF_ExternalKeyEncrypt(session, modes[i], key, sizeof(key),
            mode_iv, iv_len, plain, sizeof(plain), cipher, &cipher_len));
        recovered_len = sizeof(recovered);
        CHECK_OK(SDF_ExternalKeyDecrypt(session, modes[i], key, sizeof(key),
            mode_iv, iv_len, cipher, cipher_len, recovered, &recovered_len));
        if (recovered_len != sizeof(plain) ||
            memcmp(plain, recovered, sizeof(plain)) != 0) return 1;
    }

    cipher_len = sizeof(cipher);
    CHECK_OK(SDF_ExternalKeyEncrypt(session, SGD_SM4_XTS, xts_key,
        sizeof(xts_key), iv, sizeof(iv), plain, 31, cipher, &cipher_len));
    recovered_len = sizeof(recovered);
    CHECK_OK(SDF_ExternalKeyDecrypt(session, SGD_SM4_XTS, xts_key,
        sizeof(xts_key), iv, sizeof(iv), cipher, cipher_len,
        recovered, &recovered_len));
    if (recovered_len != 31 || memcmp(plain, recovered, 31) != 0) return 1;

    CHECK_OK(SDF_ExternalKeyEncryptInit(session, SGD_SM4_CBC, key,
        sizeof(key), iv, sizeof(iv)));
    ULONG first_len = 32;
    CHECK_OK(SDF_EncryptUpdate(session, plain, 16, cipher, &first_len));
    ULONG second_len = 32;
    CHECK_OK(SDF_EncryptUpdate(session, plain + 16, 16,
        cipher + first_len, &second_len));
    ULONG final_len = 16;
    CHECK_OK(SDF_EncryptFinal(session, cipher + first_len + second_len,
        &final_len));
    cipher_len = first_len + second_len + final_len;
    CHECK_OK(SDF_ExternalKeyDecryptInit(session, SGD_SM4_CBC, key,
        sizeof(key), iv, sizeof(iv)));
    recovered_len = sizeof(recovered);
    CHECK_OK(SDF_DecryptUpdate(session, cipher, cipher_len,
        recovered, &recovered_len));
    final_len = sizeof(recovered) - recovered_len;
    CHECK_OK(SDF_DecryptFinal(session, recovered + recovered_len, &final_len));
    recovered_len += final_len;
    return recovered_len == sizeof(plain) &&
           memcmp(plain, recovered, sizeof(plain)) == 0 ? 0 : 1;
}

static int test_external_hmac(HANDLE session)
{
    static const BYTE expected[32] = {
        0xbd,0x4a,0x34,0x07,0x78,0x88,0x16,0x2b,
        0x21,0x06,0x45,0xb8,0xeb,0xf7,0x4b,0x9a,
        0xf3,0x57,0x30,0x37,0x89,0x35,0x7a,0x27,
        0xc7,0xfc,0x45,0x72,0x44,0xeb,0xd3,0x98
    };
    BYTE key[] = "key";
    BYTE message[] = "The quick brown fox jumps over the lazy dog";
    BYTE mac[64];
    ULONG mac_len = sizeof(mac);
    CHECK_OK(SDF_ExternalKeyHMACInit(session, SGD_SM3, key, 3));
    CHECK_OK(SDF_HMACUpdate(session, message, 19));
    CHECK_OK(SDF_HMACUpdate(session, message + 19, sizeof(message) - 1 - 19));
    CHECK_OK(SDF_HMACFinal(session, mac, &mac_len));
    return mac_len == sizeof(expected) &&
           memcmp(mac, expected, sizeof(expected)) == 0 ? 0 : 1;
}

static int test_auth_mode(HANDLE session, HANDLE key, ULONG alg,
                          ULONG iv_len)
{
    BYTE iv[16] = {0};
    BYTE aad[] = "0018-AAD";
    BYTE plain[] = "authenticated message";
    BYTE cipher[64], recovered[64], tag[16];
    ULONG cipher_len = sizeof(cipher), tag_len = sizeof(tag);
    CHECK_OK(SDF_AuthEnc(session, key, alg, iv, iv_len,
        aad, sizeof(aad) - 1, plain, sizeof(plain) - 1,
        cipher, &cipher_len, tag, &tag_len));
    ULONG recovered_len = sizeof(recovered);
    CHECK_OK(SDF_AuthDec(session, key, alg, iv, iv_len,
        aad, sizeof(aad) - 1, tag, tag_len, cipher, cipher_len,
        recovered, &recovered_len));
    if (recovered_len != sizeof(plain) - 1 ||
        memcmp(plain, recovered, recovered_len) != 0) return 1;

    tag[0] ^= 1;
    recovered_len = sizeof(recovered);
    LONG ret = SDF_AuthDec(session, key, alg, iv, iv_len,
        aad, sizeof(aad) - 1, tag, tag_len, cipher, cipher_len,
        recovered, &recovered_len);
    tag[0] ^= 1;
    if (ret != SDR_VERIFYERR) return 1;

    CHECK_OK(SDF_AuthEncInit(session, key, alg, iv, iv_len,
        aad, sizeof(aad) - 1, sizeof(plain) - 1));
    cipher_len = sizeof(cipher);
    CHECK_OK(SDF_AuthEncUpdate(session, plain, sizeof(plain) - 1,
        cipher, &cipher_len));
    ULONG last_len = sizeof(cipher) - cipher_len;
    tag_len = sizeof(tag);
    CHECK_OK(SDF_AuthEncFinal(session, cipher + cipher_len, &last_len,
        tag, &tag_len));
    cipher_len += last_len;
    CHECK_OK(SDF_AuthDecInit(session, key, alg, iv, iv_len,
        aad, sizeof(aad) - 1, tag, tag_len, sizeof(plain) - 1));
    recovered_len = sizeof(recovered);
    CHECK_OK(SDF_AuthDecUpdate(session, cipher, cipher_len,
        recovered, &recovered_len));
    last_len = sizeof(recovered) - recovered_len;
    CHECK_OK(SDF_AuthDecFinal(session, recovered + recovered_len, &last_len));
    recovered_len += last_len;
    return recovered_len == sizeof(plain) - 1 &&
           memcmp(plain, recovered, recovered_len) == 0 ? 0 : 1;
}

static int decrypt_wrapped_key(HANDLE session, ECCrefPrivateKey *private_key,
                               ECCCipher *cipher, ULONG expected_length)
{
    BYTE plain[64] = {0};
    ULONG plain_length = sizeof(plain);
    CHECK_OK(SDF_ExternalDecrypt_ECC(session, SGD_SM2_3, private_key, cipher,
                                    plain, &plain_length));
    return plain_length == expected_length ? 0 : 1;
}

static int test_vpn_epk(HANDLE session, HANDLE kd, HANDLE ka)
{
    BYTE ni[16] = {1}, nr[16] = {2}, ci[8] = {3}, cr[8] = {4};
    BYTE protocol[] = {3}, spi[4] = {1,2,3,4};
    ECCrefPublicKey public_key;
    ECCrefPrivateKey private_key;
    CHECK_OK(SDF_GenerateKeyPair_ECC(session, SGD_SM2_3, 256,
                                    &public_key, &private_key));

    BYTE ike_d_buf[sizeof(ECCCipher) + 32] = {0};
    BYTE ike_a_buf[sizeof(ECCCipher) + 32] = {0};
    BYTE ike_e_buf[sizeof(ECCCipher) + 32] = {0};
    ECCCipher *ike_d = (ECCCipher *)ike_d_buf;
    ECCCipher *ike_a = (ECCCipher *)ike_a_buf;
    ECCCipher *ike_e = (ECCCipher *)ike_e_buf;
    LONG bad_alg = SDF_GenerateKeywithEPK_IKE(session, ni, sizeof(ni), nr,
        sizeof(nr), ci, sizeof(ci), cr, sizeof(cr), SGD_SM3, SGD_SM2_1,
        &public_key, ike_d, 128, ike_a, 128, ike_e, 128);
    if (bad_alg != SDR_ALGNOTSUPPORT) return 1;

    CHECK_OK(SDF_GenerateKeywithEPK_IKE(session, ni, sizeof(ni), nr,
        sizeof(nr), ci, sizeof(ci), cr, sizeof(cr), SGD_SM3, SGD_SM2_3,
        &public_key, ike_d, 128, ike_a, 128, ike_e, 128));
    if (decrypt_wrapped_key(session, &private_key, ike_d, 16) != 0 ||
        decrypt_wrapped_key(session, &private_key, ike_a, 16) != 0 ||
        decrypt_wrapped_key(session, &private_key, ike_e, 16) != 0) return 1;

    BYTE ipsec_enc_buf[sizeof(ECCCipher) + 32] = {0};
    BYTE ipsec_mac_buf[sizeof(ECCCipher) + 32] = {0};
    BYTE salt[4] = {0};
    ECCCipher *ipsec_enc = (ECCCipher *)ipsec_enc_buf;
    ECCCipher *ipsec_mac = (ECCCipher *)ipsec_mac_buf;
    CHECK_OK(SDF_GenerateKeywithEPK_IPSEC(session, protocol,
        sizeof(protocol), spi, sizeof(spi), ni, sizeof(ni), nr, sizeof(nr),
        kd, SGD_SM3, SGD_SM2_3, &public_key, ipsec_enc, 128, ipsec_mac, 128,
        salt, sizeof(salt)));
    if (decrypt_wrapped_key(session, &private_key, ipsec_enc, 16) != 0 ||
        decrypt_wrapped_key(session, &private_key, ipsec_mac, 16) != 0)
        return 1;

    BYTE ssl_cm_buf[sizeof(ECCCipher) + 32] = {0};
    BYTE ssl_sm_buf[sizeof(ECCCipher) + 32] = {0};
    BYTE ssl_ce_buf[sizeof(ECCCipher) + 32] = {0};
    BYTE ssl_se_buf[sizeof(ECCCipher) + 32] = {0};
    BYTE client_iv[16], server_iv[16];
    ECCCipher *ssl_cm = (ECCCipher *)ssl_cm_buf;
    ECCCipher *ssl_sm = (ECCCipher *)ssl_sm_buf;
    ECCCipher *ssl_ce = (ECCCipher *)ssl_ce_buf;
    ECCCipher *ssl_se = (ECCCipher *)ssl_se_buf;
    CHECK_OK(SDF_GenerateKeywithEPK_SSL(session, ka, ni, sizeof(ni), nr,
        sizeof(nr), SGD_SM3, SGD_SM2_3, &public_key,
        ssl_cm, 128, ssl_sm, 128, ssl_ce, 128, ssl_se, 128,
        client_iv, sizeof(client_iv), server_iv, sizeof(server_iv)));
    if (decrypt_wrapped_key(session, &private_key, ssl_cm, 16) != 0 ||
        decrypt_wrapped_key(session, &private_key, ssl_sm, 16) != 0 ||
        decrypt_wrapped_key(session, &private_key, ssl_ce, 16) != 0 ||
        decrypt_wrapped_key(session, &private_key, ssl_se, 16) != 0)
        return 1;
    return 0;
}
static int test_vpn_and_internal(HANDLE session)
{
    BYTE ni[16] = {1}, nr[16] = {2}, ci[8] = {3}, cr[8] = {4};
    HANDLE kd = NULL, ka = NULL, ke = NULL;
    CHECK_OK(SDF_GenerateKeywithIKE(session, ni, sizeof(ni), nr, sizeof(nr),
        ci, sizeof(ci), cr, sizeof(cr), SGD_SM3,
        &kd, 128, &ka, 128, &ke, 128));

    BYTE block[32], iv[16] = {0}, encrypted[64], decrypted[64];
    for (size_t i = 0; i < sizeof(block); ++i) block[i] = (BYTE)i;
    CHECK_OK(SDF_EncryptInit(session, ke, SGD_SM4_CBC, iv, sizeof(iv)));
    ULONG encrypted_len = sizeof(encrypted);
    CHECK_OK(SDF_EncryptUpdate(session, block, sizeof(block),
        encrypted, &encrypted_len));
    ULONG final_len = sizeof(encrypted) - encrypted_len;
    CHECK_OK(SDF_EncryptFinal(session, encrypted + encrypted_len, &final_len));
    encrypted_len += final_len;
    CHECK_OK(SDF_DecryptInit(session, ke, SGD_SM4_CBC, iv, sizeof(iv)));
    ULONG decrypted_len = sizeof(decrypted);
    CHECK_OK(SDF_DecryptUpdate(session, encrypted, encrypted_len,
        decrypted, &decrypted_len));
    final_len = sizeof(decrypted) - decrypted_len;
    CHECK_OK(SDF_DecryptFinal(session, decrypted + decrypted_len, &final_len));
    decrypted_len += final_len;
    if (decrypted_len != sizeof(block) || memcmp(block, decrypted, sizeof(block)))
        return 1;

    BYTE mac_one[16], mac_stream[16];
    ULONG mac_one_len = sizeof(mac_one), mac_stream_len = sizeof(mac_stream);
    CHECK_OK(SDF_CalculateMAC(session, kd, SGD_SM4_MAC, iv, block,
        sizeof(block), mac_one, &mac_one_len));
    CHECK_OK(SDF_CalculateMACInit(session, kd, SGD_SM4_MAC, iv, sizeof(iv)));
    CHECK_OK(SDF_CalculateMACUpdate(session, block, 16));
    CHECK_OK(SDF_CalculateMACUpdate(session, block + 16, 16));
    CHECK_OK(SDF_CalculateMACFinal(session, mac_stream, &mac_stream_len));
    if (mac_one_len != mac_stream_len || memcmp(mac_one, mac_stream, mac_one_len))
        return 1;

    if (test_auth_mode(session, kd, SGD_SM4_GCM, 12) != 0 ||
        test_auth_mode(session, kd, SGD_SM4_CCM, 12) != 0) return 1;

    BYTE protocol[] = {3}, spi[4] = {1,2,3,4}, salt[4];
    HANDLE ipsec_enc = NULL, ipsec_mac = NULL;
    CHECK_OK(SDF_GenerateKeywithIPSEC(session, protocol, sizeof(protocol),
        spi, sizeof(spi), ni, sizeof(ni), nr, sizeof(nr), kd, SGD_SM3,
        &ipsec_enc, 128, &ipsec_mac, 128, salt, sizeof(salt)));

    HANDLE ssl_cm = NULL, ssl_sm = NULL, ssl_ce = NULL, ssl_se = NULL;
    BYTE client_iv[16], server_iv[16];
    CHECK_OK(SDF_GenerateKeywithSSL(session, ka, ni, sizeof(ni), nr,
        sizeof(nr), SGD_SM3, &ssl_cm, 128, &ssl_sm, 128,
        &ssl_ce, 128, &ssl_se, 128, client_iv, sizeof(client_iv),
        server_iv, sizeof(server_iv)));

    if (test_vpn_epk(session, kd, ka) != 0) return 1;

    HANDLE handles[] = {kd, ka, ke, ipsec_enc, ipsec_mac,
                        ssl_cm, ssl_sm, ssl_ce, ssl_se};
    for (size_t i = 0; i < sizeof(handles) / sizeof(handles[0]); ++i)
        CHECK_OK(SDF_DestroyKey(session, handles[i]));
    return 0;
}

int main(void)
{
    HANDLE device = NULL, session = NULL;
    CHECK_OK(SDF_OpenDevice(&device));
    CHECK_OK(SDF_OpenSession(device, &session));
    if (test_external_symmetric(session) != 0 ||
        test_external_hmac(session) != 0 ||
        test_vpn_and_internal(session) != 0) {
        fprintf(stderr, "GM/T 0018 extended integration test failed\n");
        return 1;
    }
    CHECK_OK(SDF_CloseSession(session));
    CHECK_OK(SDF_CloseDevice(device));
    puts("GM/T 0018 extended integration test passed");
    return 0;
}