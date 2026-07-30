#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdf.h"

#define CHECK_OK(call) do { \
    LONG check_ret = (call); \
    if (check_ret != SDR_OK) { \
        fprintf(stderr, "%s failed: 0x%08x at line %d\n", \
                #call, (unsigned int)check_ret, __LINE__); \
        goto cleanup; \
    } \
} while (0)

int main(void)
{
    const char *password = getenv("SDFX_TEST_SM2_PASSWORD");
    if (password == NULL || password[0] == '\0') {
        fprintf(stderr, "SDFX_TEST_SM2_PASSWORD is required\n");
        return 1;
    }
    ULONG key_index = 1;
    const char *index_text = getenv("SDFX_TEST_KEY_INDEX");
    if (index_text != NULL && index_text[0] != '\0') {
        char *end = NULL;
        unsigned long parsed = strtoul(index_text, &end, 10);
        if (end == index_text || *end != '\0' || parsed < 1 || parsed > 1024) {
            fprintf(stderr, "SDFX_TEST_KEY_INDEX must be in 1..1024\n");
            return 1;
        }
        key_index = (ULONG)parsed;
    }

    int result = 1;
    HANDLE device = NULL;
    HANDLE session = NULL;
    HANDLE generated_key = NULL;
    HANDLE imported_key = NULL;
    ECCrefPublicKey sign_public;
    ECCrefPublicKey enc_public;
    ECCSignature signature;
    BYTE digest[32];
    BYTE plaintext[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    BYTE encrypted[32];
    ULONG encrypted_len = sizeof(encrypted);
    BYTE decrypted[32];
    ULONG decrypted_len = sizeof(decrypted);
    BYTE wrapped_storage[sizeof(ECCCipher) + 31];
    ECCCipher *wrapped = (ECCCipher *)wrapped_storage;
    memset(digest, 0x5a, sizeof(digest));
    memset(&signature, 0, sizeof(signature));
    memset(wrapped_storage, 0, sizeof(wrapped_storage));

    CHECK_OK(SDF_OpenDevice(&device));
    CHECK_OK(SDF_OpenSession(device, &session));
    CHECK_OK(SDF_ExportSignPublicKey_ECC(session, key_index, &sign_public));
    CHECK_OK(SDF_ExportEncPublicKey_ECC(session, key_index, &enc_public));
    if (memcmp(&sign_public, &enc_public, sizeof(sign_public)) == 0) {
        fprintf(stderr, "signing and encryption keys must be distinct\n");
        goto cleanup;
    }

    LONG ret = SDF_InternalSign_ECC(session, key_index, digest, sizeof(digest), &signature);
    if (ret != SDR_PARDENY) {
        fprintf(stderr, "sign without access returned 0x%08x\n", (unsigned int)ret);
        goto cleanup;
    }
    ret = SDF_GetPrivateKeyAccessRight(session, key_index, "definitely-wrong", 16);
    if (ret != SDR_PRKRERR) {
        fprintf(stderr, "wrong password returned 0x%08x\n", (unsigned int)ret);
        goto cleanup;
    }

    CHECK_OK(SDF_GetPrivateKeyAccessRight(session, key_index, (LPSTR)password,
                                          (ULONG)strlen(password)));
    CHECK_OK(SDF_InternalSign_ECC(session, key_index, digest, sizeof(digest), &signature));
    CHECK_OK(SDF_InternalVerify_ECC(session, key_index, digest, sizeof(digest), &signature));
    digest[0] ^= 1;
    ret = SDF_InternalVerify_ECC(session, key_index, digest, sizeof(digest), &signature);
    digest[0] ^= 1;
    if (ret != SDR_VERIFYERR) {
        fprintf(stderr, "tampered signature verification returned 0x%08x\n",
                (unsigned int)ret);
        goto cleanup;
    }

    CHECK_OK(SDF_GenerateKeyWithIPK_ECC(session, key_index, 128, wrapped,
                                        &generated_key));
    CHECK_OK(SDF_ImportKeyWithISK_ECC(session, key_index, wrapped, &imported_key));
    CHECK_OK(SDF_Encrypt(session, generated_key, SGD_SM4_ECB, NULL,
                         plaintext, sizeof(plaintext), encrypted, &encrypted_len));
    CHECK_OK(SDF_Decrypt(session, imported_key, SGD_SM4_ECB, NULL,
                         encrypted, encrypted_len, decrypted, &decrypted_len));
    if (decrypted_len != sizeof(plaintext) ||
        memcmp(plaintext, decrypted, sizeof(plaintext)) != 0) {
        fprintf(stderr, "internal key wrap/import round trip mismatch\n");
        goto cleanup;
    }

    CHECK_OK(SDF_ReleasePrivateKeyAccessRight(session, key_index));
    ret = SDF_InternalSign_ECC(session, key_index, digest, sizeof(digest), &signature);
    if (ret != SDR_PARDENY) {
        fprintf(stderr, "sign after release returned 0x%08x\n", (unsigned int)ret);
        goto cleanup;
    }
    ret = SDF_ImportKeyWithISK_ECC(session, key_index, wrapped, &imported_key);
    if (ret != SDR_PARDENY) {
        fprintf(stderr, "import after release returned 0x%08x\n", (unsigned int)ret);
        goto cleanup;
    }

    result = 0;
    printf("Internal SM2 key and permission tests passed\n");

cleanup:
    if (imported_key != NULL) {
        SDF_DestroyKey(session, imported_key);
    }
    if (generated_key != NULL) {
        SDF_DestroyKey(session, generated_key);
    }
    if (session != NULL) {
        SDF_CloseSession(session);
    }
    if (device != NULL) {
        SDF_CloseDevice(device);
    }
    return result;
}
