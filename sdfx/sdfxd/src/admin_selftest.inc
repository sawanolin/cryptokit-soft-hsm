/*
 * Online algorithm self-test for the Web management plane.
 *
 * The test only uses ephemeral material. It deliberately does not load an
 * internal private key or grant a private-key access right.
 */
static int admin_crypto_selftest(BYTE *output, uint32_t *output_len)
{
    static const BYTE sm3_expected[32] = {
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
        0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
        0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
    };
    static const BYTE sm4_key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const BYTE sample[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    BYTE random_bytes[32] = {0};
    BYTE digest[32] = {0};
    BYTE cipher[32] = {0};
    BYTE recovered[32] = {0};
    BYTE signature[128] = {0};
    ECCrefPublicKey public_key = {0};
    ECCrefPrivateKey private_key = {0};
    RSArefPublicKey rsa_public = {0};
    RSArefPrivateKey rsa_private = {0};
    BYTE rsa_input[RSAref_MAX_LEN] = {0};
    BYTE rsa_signed[RSAref_MAX_LEN] = {0};
    BYTE rsa_recovered[RSAref_MAX_LEN] = {0};
    ULONG length;
    int ret;
    bool any_nonzero = false;

    if (output == NULL || output_len == NULL ||
        *output_len < 512U) {
        return SDR_OUTARGERR;
    }

    ret = crypto_generate_random(sizeof(random_bytes), random_bytes);
    if (ret != SDR_OK) {
        goto cleanup;
    }
    for (size_t i = 0; i < sizeof(random_bytes); ++i) {
        any_nonzero |= random_bytes[i] != 0;
    }
    if (!any_nonzero) {
        ret = SDR_RANDERR;
        goto cleanup;
    }

    length = sizeof(digest);
    ret = crypto_hash_digest(SGD_SM3, (const BYTE *)"abc", 3,
                             digest, &length);
    if (ret != SDR_OK || length != sizeof(digest) ||
        memcmp(digest, sm3_expected, sizeof(digest)) != 0) {
        ret = ret == SDR_OK ? SDR_HARDFAIL : ret;
        goto cleanup;
    }

    length = sizeof(cipher);
    ret = crypto_symmetric_encrypt(SGD_SM4_ECB, sm4_key, sizeof(sm4_key),
                                   NULL, 0, sample, sizeof(sample),
                                   cipher, &length);
    if (ret != SDR_OK || length != sizeof(sample)) {
        goto cleanup;
    }
    length = sizeof(recovered);
    ret = crypto_symmetric_decrypt(SGD_SM4_ECB, sm4_key, sizeof(sm4_key),
                                   NULL, 0, cipher, sizeof(sample),
                                   recovered, &length);
    if (ret != SDR_OK || length != sizeof(sample) ||
        memcmp(recovered, sample, sizeof(sample)) != 0) {
        ret = ret == SDR_OK ? SDR_SYMOPERR : ret;
        goto cleanup;
    }

    ret = crypto_sm2_generate_keypair(&public_key, &private_key);
    if (ret != SDR_OK) {
        goto cleanup;
    }
    length = sizeof(signature);
    ret = crypto_sm2_external_sign(&private_key, digest, sizeof(digest),
                                   signature, &length);
    if (ret != SDR_OK) {
        goto cleanup;
    }
    ret = crypto_sm2_external_verify(&public_key, digest, sizeof(digest),
                                     signature, length);
    if (ret != SDR_OK) {
        goto cleanup;
    }

    ret = crypto_rsa_generate_keypair(1024, &rsa_public, &rsa_private);
    if (ret != SDR_OK) {
        goto cleanup;
    }
    rsa_input[127] = 0x2a;
    length = 128;
    ret = crypto_rsa_private_operation(&rsa_private, rsa_input, 128,
                                       rsa_signed, &length, 0);
    if (ret != SDR_OK || length != 128) {
        goto cleanup;
    }
    length = 128;
    ret = crypto_rsa_public_operation(&rsa_public, rsa_signed, 128,
                                      rsa_recovered, &length, 0);
    if (ret != SDR_OK || length != 128 ||
        memcmp(rsa_input, rsa_recovered, 128) != 0) {
        ret = ret == SDR_OK ? SDR_VERIFYERR : ret;
        goto cleanup;
    }

    {
        int written = snprintf((char *)output, *output_len,
            "{\"status\":\"passed\",\"random\":{\"status\":\"passed\","
            "\"bytes\":32},\"sm3\":{\"status\":\"passed\","
            "\"vector\":\"abc\"},\"sm4\":{\"status\":\"passed\","
            "\"mode\":\"ECB\",\"roundtrip_bytes\":16},"
            "\"sm2\":{\"status\":\"passed\","
            "\"operation\":\"ephemeral-sign-verify\"},"
            "\"rsa\":{\"status\":\"passed\","
            "\"bits\":1024,\"operation\":\"ephemeral-private-public-roundtrip\"}}");
        if (written < 0 || (uint32_t)written >= *output_len) {
            ret = SDR_NOBUFFER;
            goto cleanup;
        }
        *output_len = (uint32_t)written;
    }

cleanup:
    memset(random_bytes, 0, sizeof(random_bytes));
    memset(digest, 0, sizeof(digest));
    memset(cipher, 0, sizeof(cipher));
    memset(recovered, 0, sizeof(recovered));
    memset(signature, 0, sizeof(signature));
    memset(&private_key, 0, sizeof(private_key));
    memset(&rsa_private, 0, sizeof(rsa_private));
    memset(rsa_input, 0, sizeof(rsa_input));
    memset(rsa_signed, 0, sizeof(rsa_signed));
    memset(rsa_recovered, 0, sizeof(rsa_recovered));
    return ret;
}
