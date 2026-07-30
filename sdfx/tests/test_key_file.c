/*
 * Integration coverage for GM/T 0018 session-key, MAC and user-file APIs.
 */
#include <stdio.h>
#include <string.h>
#include "sdf.h"

#define CHECK_OK(call) do {     ret = (call);     if (ret != SDR_OK) {         fprintf(stderr, "%s failed: 0x%08x at line %d\n", #call, (unsigned)ret, __LINE__);         goto cleanup;     } } while (0)

int main(void)
{
    HANDLE device = NULL;
    HANDLE session = NULL;
    HANDLE generated_key = NULL;
    HANDLE imported_key = NULL;
    LONG ret = SDR_OK;
    int exit_code = 1;

    BYTE wrapped[64];
    ULONG wrapped_len = sizeof(wrapped);
    BYTE iv[16] = {0};
    BYTE plain[32];
    BYTE encrypted[48];
    BYTE decrypted[48];
    ULONG encrypted_len = sizeof(encrypted);
    ULONG decrypted_len = sizeof(decrypted);
    BYTE mac[16];
    ULONG mac_len = sizeof(mac);

    char file_name[] = "sdfx-0018-integration.bin";
    BYTE file_data[] = "persistent user file round-trip";
    BYTE file_readback[64] = {0};
    ULONG file_readback_len = sizeof(file_data);

    for (ULONG i = 0; i < sizeof(plain); ++i) {
        plain[i] = (BYTE)i;
    }

    CHECK_OK(SDF_OpenDevice(&device));
    CHECK_OK(SDF_OpenSession(device, &session));

    CHECK_OK(SDF_GenerateKeyWithKEK(session, 128, SGD_SM4_ECB, 1,
                                    wrapped, &wrapped_len, &generated_key));
    CHECK_OK(SDF_Encrypt(session, generated_key, SGD_SM4_CBC, iv,
                         plain, sizeof(plain), encrypted, &encrypted_len));
    CHECK_OK(SDF_CalculateMAC(session, generated_key, SGD_SM4_MAC, iv,
                              plain, sizeof(plain), mac, &mac_len));

    CHECK_OK(SDF_ImportKeyWithKEK(session, SGD_SM4_ECB, 1,
                                  wrapped, wrapped_len, &imported_key));
    CHECK_OK(SDF_Decrypt(session, imported_key, SGD_SM4_CBC, iv,
                         encrypted, encrypted_len, decrypted, &decrypted_len));
    if (decrypted_len != sizeof(plain) ||
        memcmp(decrypted, plain, sizeof(plain)) != 0 ||
        mac_len != 16) {
        fprintf(stderr, "session key round-trip verification failed\n");
        goto cleanup;
    }

    (void)SDF_DeleteFile(session, file_name, (ULONG)strlen(file_name));
    CHECK_OK(SDF_CreateFile(session, file_name, (ULONG)strlen(file_name), 256));
    CHECK_OK(SDF_WriteFile(session, file_name, (ULONG)strlen(file_name), 17,
                           sizeof(file_data), file_data));
    CHECK_OK(SDF_ReadFile(session, file_name, (ULONG)strlen(file_name), 17,
                          &file_readback_len, file_readback));
    if (file_readback_len != sizeof(file_data) ||
        memcmp(file_readback, file_data, sizeof(file_data)) != 0) {
        fprintf(stderr, "user file round-trip verification failed\n");
        goto cleanup;
    }
    CHECK_OK(SDF_DeleteFile(session, file_name, (ULONG)strlen(file_name)));

    exit_code = 0;
    printf("GM/T 0018 key, MAC and file integration test passed\n");

cleanup:
    if (imported_key != NULL) {
        (void)SDF_DestroyKey(session, imported_key);
    }
    if (generated_key != NULL) {
        (void)SDF_DestroyKey(session, generated_key);
    }
    if (session != NULL) {
        (void)SDF_CloseSession(session);
    }
    if (device != NULL) {
        (void)SDF_CloseDevice(device);
    }
    return exit_code;
}
