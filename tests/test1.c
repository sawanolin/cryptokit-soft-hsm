#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sdf.h"

#define DEFAULT_INTERNAL_ENCRYPTION_KEY_INDEX 1U
#define SESSION_KEY_BITS 128U
#define PLAINTEXT_BYTES 32U
#define WRAPPED_KEY_CAPACITY 32U

static HANDLE device_handle = NULL;
static HANDLE session_handle = NULL;
static HANDLE generated_key = NULL;
static HANDLE imported_key = NULL;
static int private_access_granted = 0;
static ULONG internal_key_index = DEFAULT_INTERNAL_ENCRYPTION_KEY_INDEX;

static void cleanup(void)
{
    if (imported_key != NULL && session_handle != NULL) {
        SDF_DestroyKey(session_handle, imported_key);
        imported_key = NULL;
    }
    if (generated_key != NULL && session_handle != NULL) {
        SDF_DestroyKey(session_handle, generated_key);
        generated_key = NULL;
    }
    if (private_access_granted && session_handle != NULL) {
        SDF_ReleasePrivateKeyAccessRight(session_handle, internal_key_index);
        private_access_granted = 0;
    }
    if (session_handle != NULL) {
        SDF_CloseSession(session_handle);
        session_handle = NULL;
    }
    if (device_handle != NULL) {
        SDF_CloseDevice(device_handle);
        device_handle = NULL;
    }
}

static int fail(const char *operation, LONG status)
{
    fprintf(stderr, "%s failed: 0x%08lX\n", operation, (unsigned long)status);
    cleanup();
    return (int)status;
}

int main(void)
{
    static const BYTE plaintext[PLAINTEXT_BYTES] = {
        0x53,0x44,0x46,0x58,0x2D,0x53,0x4D,0x34,0x2D,0x52,0x4F,0x55,0x4E,0x44,0x54,0x52,
        0x49,0x50,0x2D,0x54,0x45,0x53,0x54,0x2D,0x30,0x30,0x31,0x38,0x2D,0x32,0x30,0x32
    };
    BYTE wrapped_storage[sizeof(ECCCipher) + WRAPPED_KEY_CAPACITY - 1U];
    ECCCipher *wrapped = (ECCCipher *)wrapped_storage;
    BYTE ciphertext[PLAINTEXT_BYTES];
    BYTE recovered[PLAINTEXT_BYTES];
    ULONG ciphertext_length = (ULONG)sizeof(ciphertext);
    ULONG recovered_length = (ULONG)sizeof(recovered);
    const char *password = getenv("SDF_TEST_KEY_PASSWORD");
    const char *index_text = getenv("SDF_TEST_KEY_INDEX");
    LONG ret;

    if (index_text != NULL && index_text[0] != '\0') {
        char *end = NULL;
        unsigned long parsed = strtoul(index_text, &end, 10);
        if (end == index_text || *end != '\0' || parsed == 0 || parsed > 1024) {
            fprintf(stderr, "SDF_TEST_KEY_INDEX must be in 1..1024\n");
            return 2;
        }
        internal_key_index = (ULONG)parsed;
    }

    ret = SDF_OpenDevice(&device_handle);
    if (ret != SDR_OK) return fail("SDF_OpenDevice", ret);
    ret = SDF_OpenSession(device_handle, &session_handle);
    if (ret != SDR_OK) return fail("SDF_OpenSession", ret);

    /* Passwordless keys need no access-right call.  Set the environment
       variable only when the selected index was created with an access-control code. */
    if (password != NULL && password[0] != '\0') {
        ret = SDF_GetPrivateKeyAccessRight(
            session_handle, internal_key_index,
            (LPSTR)password, (ULONG)strlen(password));
        if (ret != SDR_OK) return fail("SDF_GetPrivateKeyAccessRight", ret);
        private_access_granted = 1;
    }

    memset(wrapped_storage, 0, sizeof(wrapped_storage));
    ret = SDF_GenerateKeyWithIPK_ECC(
        session_handle, internal_key_index, SESSION_KEY_BITS,
        wrapped, &generated_key);
    if (ret != SDR_OK) return fail("SDF_GenerateKeyWithIPK_ECC", ret);

    ret = SDF_Encrypt(session_handle, generated_key, SGD_SM4_ECB, NULL,
                      (BYTE *)plaintext, (ULONG)sizeof(plaintext),
                      ciphertext, &ciphertext_length);
    if (ret != SDR_OK) return fail("SDF_Encrypt", ret);
    ret = SDF_DestroyKey(session_handle, generated_key);
    generated_key = NULL;
    if (ret != SDR_OK) return fail("SDF_DestroyKey(generated)", ret);

    ret = SDF_ImportKeyWithISK_ECC(
        session_handle, internal_key_index, wrapped, &imported_key);
    if (ret != SDR_OK) return fail("SDF_ImportKeyWithISK_ECC", ret);
    ret = SDF_Decrypt(session_handle, imported_key, SGD_SM4_ECB, NULL,
                      ciphertext, ciphertext_length, recovered, &recovered_length);
    if (ret != SDR_OK) return fail("SDF_Decrypt", ret);
    if (recovered_length != sizeof(plaintext) ||
        memcmp(recovered, plaintext, sizeof(plaintext)) != 0) {
        fprintf(stderr, "SM4 round-trip comparison failed\n");
        cleanup();
        return 2;
    }

    printf("SM2 wrapped-key import and SM4 round-trip passed (index %u, %s).\n",
           internal_key_index,
           private_access_granted ? "password protected" : "passwordless");
    cleanup();
    return 0;
}
