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

#include <stdint.h>
#include <string.h>
#include "bsl_params.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "crypt_eal_provider.h"
#include "provider_test_utils.h"

#define BSL_PARAM_MAX_NUMBER 1000
BSL_Param *TestFindParam(BSL_Param *param, int32_t key)
{
    if (key == 0) {
        return NULL;
    }
    if (param == NULL) {
        return NULL;
    }
    int32_t index = 0;
    while (param[index].key != 0 && index < BSL_PARAM_MAX_NUMBER) {
        if (param[index].key == key) {
            return &param[index];
        }
        index++;
    }
    return NULL;
}

const BSL_Param *TestFindConstParam(const BSL_Param *param, int32_t key)
{
    if (key == 0) {
        return NULL;
    }
    if (param == NULL) {
        return NULL;
    }
    int32_t index = 0;
    while (param[index].key != 0 && index < BSL_PARAM_MAX_NUMBER) {
        if (param[index].key == key) {
            return &param[index];
        }
        index++;
    }
    return NULL;
}

int32_t TestParamInitValue(BSL_Param *param, int32_t key, uint32_t type, void *val, uint32_t valueLen)
{
    if (key == 0) {
        return BSL_PARAMS_INVALID_KEY;
    }
    if (param == NULL) {
        return BSL_INVALID_ARG;
    }
    if (type != BSL_PARAM_TYPE_FUNC_PTR && type != BSL_PARAM_TYPE_CTX_PTR) {
        if (val == NULL && valueLen != 0) {
            return BSL_INVALID_ARG;
        }
    }

    switch (type) {
        case BSL_PARAM_TYPE_UINT8:
        case BSL_PARAM_TYPE_UINT16:
        case BSL_PARAM_TYPE_UINT32:
        case BSL_PARAM_TYPE_OCTETS:
        case BSL_PARAM_TYPE_BOOL:
        case BSL_PARAM_TYPE_UINT32_PTR:
        case BSL_PARAM_TYPE_FUNC_PTR:
        case BSL_PARAM_TYPE_CTX_PTR:
        case BSL_PARAM_TYPE_INT32:
        case BSL_PARAM_TYPE_OCTETS_PTR:
            param->value = val;
            param->valueLen = valueLen;
            param->valueType = type;
            param->key = key;
            param->useLen = 0;
            return BSL_SUCCESS;
        default:
            return BSL_PARAMS_INVALID_TYPE;
    }
}

#define TLS_GROUP_PARAM_COUNT 11
static int32_t BuildTlsGroupParam(const Provider_Group *groupInfo, BSL_Param *param)
{
    int32_t ret = TestParamInitValue(&param[0], CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_NAME, BSL_PARAM_TYPE_OCTETS_PTR,
        (void *)(uintptr_t)groupInfo->name, (uint32_t)strlen(groupInfo->name));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = TestParamInitValue(&param[1], CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_ID, BSL_PARAM_TYPE_UINT16,
        (void *)(uintptr_t)&(groupInfo->groupId), sizeof(groupInfo->groupId));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = TestParamInitValue(&param[2], CRYPT_PARAM_CAP_TLS_GROUP_PARA_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->paraId), sizeof(groupInfo->paraId));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = TestParamInitValue(&param[3], CRYPT_PARAM_CAP_TLS_GROUP_ALG_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->algId), sizeof(groupInfo->algId));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = TestParamInitValue(&param[4], CRYPT_PARAM_CAP_TLS_GROUP_SEC_BITS, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->secBits), sizeof(groupInfo->secBits));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = TestParamInitValue(&param[5], CRYPT_PARAM_CAP_TLS_GROUP_VERSION_BITS, BSL_PARAM_TYPE_UINT32,
        (void *)(uintptr_t)&(groupInfo->versionBits), sizeof(groupInfo->versionBits));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = TestParamInitValue(&param[6], CRYPT_PARAM_CAP_TLS_GROUP_IS_KEM, BSL_PARAM_TYPE_BOOL,
        (void *)(uintptr_t)&(groupInfo->isKem), sizeof(groupInfo->isKem));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = TestParamInitValue(&param[7], CRYPT_PARAM_CAP_TLS_GROUP_PUBKEY_LEN, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->pubkeyLen), sizeof(groupInfo->pubkeyLen));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = TestParamInitValue(&param[8], CRYPT_PARAM_CAP_TLS_GROUP_SHAREDKEY_LEN, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->sharedkeyLen), sizeof(groupInfo->sharedkeyLen));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = TestParamInitValue(&param[9], CRYPT_PARAM_CAP_TLS_GROUP_CIPHERTEXT_LEN, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->ciphertextLen), sizeof(groupInfo->ciphertextLen));
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    return BSL_SUCCESS;
}

int32_t TestCryptGetGroupCaps(const Provider_Group *tlsGroup, uint32_t groupCount,
    CRYPT_EAL_ProcessFuncCb cb, void *args)
{
    for (size_t i = 0; i < groupCount; i++) {
        BSL_Param param[TLS_GROUP_PARAM_COUNT] = {0};
        int32_t ret = BuildTlsGroupParam(&tlsGroup[i], param);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        ret = cb(param, args);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}