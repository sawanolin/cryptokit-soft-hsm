/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef __PROVIDER_TEST_UTILS_H__
#define __PROVIDER_TEST_UTILS_H__

#include <stdint.h>
#include <stdbool.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Group information
 */
typedef struct {
    char *name;           // group name
    int32_t paraId;             // parameter id CRYPT_PKEY_ParaId
    int32_t algId;              // algorithm id CRYPT_PKEY_AlgId
    int32_t secBits;           // security bits
    uint16_t groupId;           // iana group id, HITLS_NamedGroup
    int32_t pubkeyLen;         // public key length(CH keyshare / SH keyshare)
    int32_t sharedkeyLen;      // shared key length
    int32_t ciphertextLen;     // ciphertext length(SH keyshare)
    uint32_t versionBits;       // TLS_VERSION_MASK
    bool isKem;                // true: KEM, false: KEX
} Provider_Group;

BSL_Param *TestFindParam(BSL_Param *param, int32_t key);
const BSL_Param *TestFindConstParam(const BSL_Param *param, int32_t key);
int32_t TestParamInitValue(BSL_Param *param, int32_t key, uint32_t type, void *val, uint32_t valueLen);

int32_t TestCryptGetGroupCaps(const Provider_Group *tlsGroup, uint32_t groupCount,
    CRYPT_EAL_ProcessFuncCb cb, void *args);

#ifdef __cplusplus
}
#endif

#endif

