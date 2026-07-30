#include <stdio.h>
#include <string.h>
#include "sdf.h"

#define CHECK(call) do { \
    result = (call); \
    if (result != SDR_OK) { \
        fprintf(stderr, "%s failed: 0x%08x\n", #call, (unsigned)result); \
        goto cleanup; \
    } \
} while (0)

int main(void)
{
    HANDLE device = NULL;
    HANDLE session = NULL;
    RSArefPublicKey public_key = {0};
    RSArefPrivateKey private_key = {0};
    BYTE representative[RSAref_MAX_LEN] = {0};
    BYTE private_result[RSAref_MAX_LEN] = {0};
    BYTE recovered[RSAref_MAX_LEN] = {0};
    ULONG length = 0;
    LONG result = SDR_OK;

    representative[sizeof(representative) - 1] = 0x2a;
    CHECK(SDF_OpenDevice(&device));
    CHECK(SDF_OpenSession(device, &session));
    CHECK(SDF_GenerateKeyPair_RSA(session, 2048, &public_key, &private_key));

    length = sizeof(private_result);
    CHECK(SDF_ExternalPrivateKeyOperation_RSA(
        session, &private_key, representative, sizeof(representative),
        private_result, &length));
    if (length != sizeof(private_result)) {
        result = SDR_KEYERR;
        goto cleanup;
    }

    length = sizeof(recovered);
    CHECK(SDF_ExternalPublicKeyOperation_RSA(
        session, &public_key, private_result, sizeof(private_result),
        recovered, &length));
    if (length != sizeof(representative) ||
        memcmp(representative, recovered, sizeof(representative)) != 0) {
        fprintf(stderr, "RSA external private/public round-trip mismatch\n");
        result = SDR_VERIFYERR;
        goto cleanup;
    }
    puts("RSA 2048 external private/public round-trip passed.");

cleanup:
    memset(&private_key, 0, sizeof(private_key));
    if (session != NULL) SDF_CloseSession(session);
    if (device != NULL) SDF_CloseDevice(device);
    return result == SDR_OK ? 0 : 1;
}