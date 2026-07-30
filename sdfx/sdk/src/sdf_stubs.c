/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file sdf_stubs.c
 * @brief Stub implementations for unimplemented SDF functions
 * @details This file provides stub implementations that return SDR_NOTSUPPORT
 *          for all SDF functions that are not yet implemented.
 */

#include "sdf_internal.h"
#include <stdio.h>

/************************************************************************
 * 6.2 设备管理类函数 - 私钥访问权限管理
 ************************************************************************/

static LONG sdf_stub_SDF_GetPrivateKeyAccessRight(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    LPSTR pucPassword,
    ULONG uiPwdLength)
{
    (void)hSessionHandle;
    (void)uiKeyIndex;
    (void)pucPassword;
    (void)uiPwdLength;

    fprintf(stderr, "[STUB] SDF_GetPrivateKeyAccessRight not implemented\n");
    return SDR_NOTSUPPORT;
}

static LONG sdf_stub_SDF_ReleasePrivateKeyAccessRight(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex)
{
    (void)hSessionHandle;
    (void)uiKeyIndex;

    fprintf(stderr, "[STUB] SDF_ReleasePrivateKeyAccessRight not implemented\n");
    return SDR_NOTSUPPORT;
}

/************************************************************************
 * 6.3 密钥管理类函数 - RSA
 ************************************************************************/






/************************************************************************
 * 6.3 密钥管理类函数 - ECC
 ************************************************************************/

static LONG sdf_stub_SDF_ExportSignPublicKey_ECC(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    ECCrefPublicKey *pucPublicKey)
{
    (void)hSessionHandle;
    (void)uiKeyIndex;
    (void)pucPublicKey;

    fprintf(stderr, "[STUB] SDF_ExportSignPublicKey_ECC not implemented\n");
    return SDR_NOTSUPPORT;
}

static LONG sdf_stub_SDF_ExportEncPublicKey_ECC(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    ECCrefPublicKey *pucPublicKey)
{
    (void)hSessionHandle;
    (void)uiKeyIndex;
    (void)pucPublicKey;

    fprintf(stderr, "[STUB] SDF_ExportEncPublicKey_ECC not implemented\n");
    return SDR_NOTSUPPORT;
}

static LONG sdf_stub_SDF_GenerateKeyWithIPK_ECC(
    HANDLE hSessionHandle,
    ULONG uiIPKIndex,
    ULONG uiKeyBits,
    ECCCipher *pucKey,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)uiIPKIndex;
    (void)uiKeyBits;
    (void)pucKey;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_GenerateKeyWithIPK_ECC not implemented\n");
    return SDR_NOTSUPPORT;
}

static LONG sdf_stub_SDF_GenerateKeyWithEPK_ECC(
    HANDLE hSessionHandle,
    ULONG uiKeyBits,
    ULONG uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucKey,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)uiKeyBits;
    (void)uiAlgID;
    (void)pucPublicKey;
    (void)pucKey;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_GenerateKeyWithEPK_ECC not implemented\n");
    return SDR_NOTSUPPORT;
}

static LONG sdf_stub_SDF_ImportKeyWithISK_ECC(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    ECCCipher *pucKey,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)uiISKIndex;
    (void)pucKey;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_ImportKeyWithISK_ECC not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_GenerateAgreementDataWithECC(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    ULONG uiKeyBits,
    BYTE *pucSponsorID,
    ULONG uiSponsorIDLength,
    ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey,
    HANDLE *phAgreementHandle)
{
    (void)hSessionHandle;
    (void)uiISKIndex;
    (void)uiKeyBits;
    (void)pucSponsorID;
    (void)uiSponsorIDLength;
    (void)pucSponsorPublicKey;
    (void)pucSponsorTmpPublicKey;
    (void)phAgreementHandle;

    fprintf(stderr, "[STUB] SDF_GenerateAgreementDataWithECC not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_GenerateKeyWithECC(
    HANDLE hSessionHandle,
    BYTE *pucResponseID,
    ULONG uiResponseIDLength,
    ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey,
    HANDLE hAgreementHandle,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)pucResponseID;
    (void)uiResponseIDLength;
    (void)pucResponsePublicKey;
    (void)pucResponseTmpPublicKey;
    (void)hAgreementHandle;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_GenerateKeyWithECC not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_GenerateAgreementDataAndKeyWithECC(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    ULONG uiKeyBits,
    BYTE *pucResponseID,
    ULONG uiResponseIDLength,
    BYTE *pucSponsorID,
    ULONG uiSponsorIDLength,
    ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey,
    ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)uiISKIndex;
    (void)uiKeyBits;
    (void)pucResponseID;
    (void)uiResponseIDLength;
    (void)pucSponsorID;
    (void)uiSponsorIDLength;
    (void)pucSponsorPublicKey;
    (void)pucSponsorTmpPublicKey;
    (void)pucResponsePublicKey;
    (void)pucResponseTmpPublicKey;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_GenerateAgreementDataAndKeyWithECC not implemented\n");
    return SDR_NOTSUPPORT;
}

/************************************************************************
 * 6.3 密钥管理类函数 - KEK
 ************************************************************************/

static LONG sdf_stub_SDF_GenerateKeyWithKEK(
    HANDLE hSessionHandle,
    ULONG uiKeyBits,
    ULONG uiAlgID,
    ULONG uiKEKIndex,
    BYTE *pucKey,
    ULONG *puiKeyLength,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)uiKeyBits;
    (void)uiAlgID;
    (void)uiKEKIndex;
    (void)pucKey;
    (void)puiKeyLength;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_GenerateKeyWithKEK not implemented\n");
    return SDR_NOTSUPPORT;
}

static LONG sdf_stub_SDF_ImportKeyWithKEK(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    ULONG uiKEKIndex,
    BYTE *pucKey,
    ULONG uiKeyLength,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)uiAlgID;
    (void)uiKEKIndex;
    (void)pucKey;
    (void)uiKeyLength;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_ImportKeyWithKEK not implemented\n");
    return SDR_NOTSUPPORT;
}

static LONG sdf_stub_SDF_DestroyKey(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle)
{
    (void)hSessionHandle;
    (void)hKeyHandle;

    fprintf(stderr, "[STUB] SDF_DestroyKey not implemented\n");
    return SDR_NOTSUPPORT;
}

/************************************************************************
 * 6.4 非对称算法运算类函数 - RSA
 ************************************************************************/




/************************************************************************
 * 6.5 对称算法运算类函数
 ************************************************************************/

static LONG sdf_stub_SDF_CalculateMAC(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucIV,
    BYTE *pucData,
    ULONG uiDataLength,
    BYTE *pucMac,
    ULONG *puiMacLength)
{
    (void)hSessionHandle;
    (void)hKeyHandle;
    (void)uiAlgID;
    (void)pucIV;
    (void)pucData;
    (void)uiDataLength;
    (void)pucMac;
    (void)puiMacLength;

    fprintf(stderr, "[STUB] SDF_CalculateMAC not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_AuthEnc(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucStartVar,
    ULONG uiStartVarLength,
    BYTE *pucAad,
    ULONG uiAadLength,
    BYTE *pucData,
    ULONG uiDataLength,
    BYTE *pucEncData,
    ULONG *puiEncDataLength,
    BYTE *pucAuthData,
    ULONG *puiAuthDataLength)
{
    (void)hSessionHandle;
    (void)hKeyHandle;
    (void)uiAlgID;
    (void)pucStartVar;
    (void)uiStartVarLength;
    (void)pucAad;
    (void)uiAadLength;
    (void)pucData;
    (void)uiDataLength;
    (void)pucEncData;
    (void)puiEncDataLength;
    (void)pucAuthData;
    (void)puiAuthDataLength;

    fprintf(stderr, "[STUB] SDF_AuthEnc not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_AuthDec(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucStartVar,
    ULONG uiStartVarLength,
    BYTE *pucAad,
    ULONG uiAadLength,
    BYTE *pucAuthData,
    ULONG uiAuthDataLength,
    BYTE *pucEncData,
    ULONG uiEncDataLength,
    BYTE *pucData,
    ULONG *puiDataLength)
{
    (void)hSessionHandle;
    (void)hKeyHandle;
    (void)uiAlgID;
    (void)pucStartVar;
    (void)uiStartVarLength;
    (void)pucAad;
    (void)uiAadLength;
    (void)pucAuthData;
    (void)uiAuthDataLength;
    (void)pucEncData;
    (void)uiEncDataLength;
    (void)pucData;
    (void)puiDataLength;

    fprintf(stderr, "[STUB] SDF_AuthDec not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_EncryptInit(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucIV,
    ULONG uiIVLength)
{
    (void)hSessionHandle;
    (void)hKeyHandle;
    (void)uiAlgID;
    (void)pucIV;
    (void)uiIVLength;

    fprintf(stderr, "[STUB] SDF_EncryptInit not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_EncryptUpdate(
    HANDLE hSessionHandle,
    BYTE *pucData,
    ULONG uiDataLength,
    BYTE *pucEncData,
    ULONG *puiEncDataLength)
{
    (void)hSessionHandle;
    (void)pucData;
    (void)uiDataLength;
    (void)pucEncData;
    (void)puiEncDataLength;

    fprintf(stderr, "[STUB] SDF_EncryptUpdate not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_EncryptFinal(
    HANDLE hSessionHandle,
    BYTE *pucLastEncData,
    ULONG *puiLastEncDataLength)
{
    (void)hSessionHandle;
    (void)pucLastEncData;
    (void)puiLastEncDataLength;

    fprintf(stderr, "[STUB] SDF_EncryptFinal not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_DecryptInit(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucIV,
    ULONG uiIVLength)
{
    (void)hSessionHandle;
    (void)hKeyHandle;
    (void)uiAlgID;
    (void)pucIV;
    (void)uiIVLength;

    fprintf(stderr, "[STUB] SDF_DecryptInit not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_DecryptUpdate(
    HANDLE hSessionHandle,
    BYTE *pucEncData,
    ULONG uiEncDataLength,
    BYTE *pucData,
    ULONG *puiDataLength)
{
    (void)hSessionHandle;
    (void)pucEncData;
    (void)uiEncDataLength;
    (void)pucData;
    (void)puiDataLength;

    fprintf(stderr, "[STUB] SDF_DecryptUpdate not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_DecryptFinal(
    HANDLE hSessionHandle,
    BYTE *pucLastData,
    ULONG *puiLastDataLength)
{
    (void)hSessionHandle;
    (void)pucLastData;
    (void)puiLastDataLength;

    fprintf(stderr, "[STUB] SDF_DecryptFinal not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_CalculateMACInit(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucIV,
    ULONG uiIVLength)
{
    (void)hSessionHandle;
    (void)hKeyHandle;
    (void)uiAlgID;
    (void)pucIV;
    (void)uiIVLength;

    fprintf(stderr, "[STUB] SDF_CalculateMACInit not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_CalculateMACUpdate(
    HANDLE hSessionHandle,
    BYTE *pucData,
    ULONG uiDataLength)
{
    (void)hSessionHandle;
    (void)pucData;
    (void)uiDataLength;

    fprintf(stderr, "[STUB] SDF_CalculateMACUpdate not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_CalculateMACFinal(
    HANDLE hSessionHandle,
    BYTE *pucMac,
    ULONG *puiMacLength)
{
    (void)hSessionHandle;
    (void)pucMac;
    (void)puiMacLength;

    fprintf(stderr, "[STUB] SDF_CalculateMACFinal not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_AuthEncInit(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucStartVar,
    ULONG uiStartVarLength,
    BYTE *pucAad,
    ULONG uiAadLength,
    ULONG uiDataLength)
{
    (void)hSessionHandle;
    (void)hKeyHandle;
    (void)uiAlgID;
    (void)pucStartVar;
    (void)uiStartVarLength;
    (void)pucAad;
    (void)uiAadLength;
    (void)uiDataLength;

    fprintf(stderr, "[STUB] SDF_AuthEncInit not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_AuthEncUpdate(
    HANDLE hSessionHandle,
    BYTE *pucData,
    ULONG uiDataLength,
    BYTE *pucEncData,
    ULONG *puiEncDataLength)
{
    (void)hSessionHandle;
    (void)pucData;
    (void)uiDataLength;
    (void)pucEncData;
    (void)puiEncDataLength;

    fprintf(stderr, "[STUB] SDF_AuthEncUpdate not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_AuthEncFinal(
    HANDLE hSessionHandle,
    BYTE *pucLastEncData,
    ULONG *puiLastEncDataLength,
    BYTE *pucAuthData,
    ULONG *puiAuthDataLength)
{
    (void)hSessionHandle;
    (void)pucLastEncData;
    (void)puiLastEncDataLength;
    (void)pucAuthData;
    (void)puiAuthDataLength;

    fprintf(stderr, "[STUB] SDF_AuthEncFinal not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_AuthDecInit(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucStartVar,
    ULONG uiStartVarLength,
    BYTE *pucAad,
    ULONG uiAadLength,
    BYTE *pucAuthData,
    ULONG uiAuthDataLength,
    ULONG uiDataLength)
{
    (void)hSessionHandle;
    (void)hKeyHandle;
    (void)uiAlgID;
    (void)pucStartVar;
    (void)uiStartVarLength;
    (void)pucAad;
    (void)uiAadLength;
    (void)pucAuthData;
    (void)uiAuthDataLength;
    (void)uiDataLength;

    fprintf(stderr, "[STUB] SDF_AuthDecInit not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_AuthDecUpdate(
    HANDLE hSessionHandle,
    BYTE *pucEncData,
    ULONG uiEncDataLength,
    BYTE *pucData,
    ULONG *puiDataLength)
{
    (void)hSessionHandle;
    (void)pucEncData;
    (void)uiEncDataLength;
    (void)pucData;
    (void)puiDataLength;

    fprintf(stderr, "[STUB] SDF_AuthDecUpdate not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_AuthDecFinal(
    HANDLE hSessionHandle,
    BYTE *pucLastData,
    ULONG *puiLastDataLength)
{
    (void)hSessionHandle;
    (void)pucLastData;
    (void)puiLastDataLength;

    fprintf(stderr, "[STUB] SDF_AuthDecFinal not implemented\n");
    return SDR_NOTSUPPORT;
}

/************************************************************************
 * 6.6 杂凑运算类函数 - HMAC
 ************************************************************************/

LONG SDF_HMACInit(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID)
{
    (void)hSessionHandle;
    (void)hKeyHandle;
    (void)uiAlgID;

    fprintf(stderr, "[STUB] SDF_HMACInit not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_HMACUpdate(
    HANDLE hSessionHandle,
    BYTE *pucData,
    ULONG uiDataLength)
{
    (void)hSessionHandle;
    (void)pucData;
    (void)uiDataLength;

    fprintf(stderr, "[STUB] SDF_HMACUpdate not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_HMACFinal(
    HANDLE hSessionHandle,
    BYTE *pucHMac,
    ULONG *puiHMacLength)
{
    (void)hSessionHandle;
    (void)pucHMac;
    (void)puiHMacLength;

    fprintf(stderr, "[STUB] SDF_HMACFinal not implemented\n");
    return SDR_NOTSUPPORT;
}

/************************************************************************
 * 6.7 用户文件操作类函数
 ************************************************************************/

static LONG sdf_stub_SDF_CreateFile(
    HANDLE hSessionHandle,
    LPSTR pucFileName,
    ULONG uiNameLen,
    ULONG uiFileSize)
{
    (void)hSessionHandle;
    (void)pucFileName;
    (void)uiNameLen;
    (void)uiFileSize;

    fprintf(stderr, "[STUB] SDF_CreateFile not implemented\n");
    return SDR_NOTSUPPORT;
}

static LONG sdf_stub_SDF_ReadFile(
    HANDLE hSessionHandle,
    LPSTR pucFileName,
    ULONG uiNameLen,
    ULONG uiOffset,
    ULONG *puiFileLength,
    BYTE *pucBuffer)
{
    (void)hSessionHandle;
    (void)pucFileName;
    (void)uiNameLen;
    (void)uiOffset;
    (void)puiFileLength;
    (void)pucBuffer;

    fprintf(stderr, "[STUB] SDF_ReadFile not implemented\n");
    return SDR_NOTSUPPORT;
}

static LONG sdf_stub_SDF_WriteFile(
    HANDLE hSessionHandle,
    LPSTR pucFileName,
    ULONG uiNameLen,
    ULONG uiOffset,
    ULONG uiFileLength,
    BYTE *pucBuffer)
{
    (void)hSessionHandle;
    (void)pucFileName;
    (void)uiNameLen;
    (void)uiOffset;
    (void)uiFileLength;
    (void)pucBuffer;

    fprintf(stderr, "[STUB] SDF_WriteFile not implemented\n");
    return SDR_NOTSUPPORT;
}

static LONG sdf_stub_SDF_DeleteFile(
    HANDLE hSessionHandle,
    LPSTR pucFileName,
    ULONG uiNameLen)
{
    (void)hSessionHandle;
    (void)pucFileName;
    (void)uiNameLen;

    fprintf(stderr, "[STUB] SDF_DeleteFile not implemented\n");
    return SDR_NOTSUPPORT;
}

/************************************************************************
 * 6.8 验证调试类函数
 ************************************************************************/



LONG SDF_ExternalKeyEncrypt(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    BYTE *pucKey,
    ULONG uiKeyLength,
    BYTE *pucIV,
    ULONG uiIVLength,
    BYTE *pucData,
    ULONG uiDataLength,
    BYTE *pucEncData,
    ULONG *puiEncDataLength)
{
    (void)hSessionHandle;
    (void)uiAlgID;
    (void)pucKey;
    (void)uiKeyLength;
    (void)pucIV;
    (void)uiIVLength;
    (void)pucData;
    (void)uiDataLength;
    (void)pucEncData;
    (void)puiEncDataLength;

    fprintf(stderr, "[STUB] SDF_ExternalKeyEncrypt not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_ExternalKeyDecrypt(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    BYTE *pucKey,
    ULONG uiKeyLength,
    BYTE *pucIV,
    ULONG uiIVLength,
    BYTE *pucEncData,
    ULONG uiEncDataLength,
    BYTE *pucData,
    ULONG *puiDataLength)
{
    (void)hSessionHandle;
    (void)uiAlgID;
    (void)pucKey;
    (void)uiKeyLength;
    (void)pucIV;
    (void)uiIVLength;
    (void)pucEncData;
    (void)uiEncDataLength;
    (void)pucData;
    (void)puiDataLength;

    fprintf(stderr, "[STUB] SDF_ExternalKeyDecrypt not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_ExternalKeyEncryptInit(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    BYTE *pucKey,
    ULONG uiKeyLength,
    BYTE *pucIV,
    ULONG uiIVLength)
{
    (void)hSessionHandle;
    (void)uiAlgID;
    (void)pucKey;
    (void)uiKeyLength;
    (void)pucIV;
    (void)uiIVLength;

    fprintf(stderr, "[STUB] SDF_ExternalKeyEncryptInit not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_ExternalKeyDecryptInit(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    BYTE *pucKey,
    ULONG uiKeyLength,
    BYTE *pucIV,
    ULONG uiIVLength)
{
    (void)hSessionHandle;
    (void)uiAlgID;
    (void)pucKey;
    (void)uiKeyLength;
    (void)pucIV;
    (void)uiIVLength;

    fprintf(stderr, "[STUB] SDF_ExternalKeyDecryptInit not implemented\n");
    return SDR_NOTSUPPORT;
}

LONG SDF_ExternalKeyHMACInit(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    BYTE *pucKey,
    ULONG uiKeyLength)
{
    (void)hSessionHandle;
    (void)uiAlgID;
    (void)pucKey;
    (void)uiKeyLength;

    fprintf(stderr, "[STUB] SDF_ExternalKeyHMACInit not implemented\n");
    return SDR_NOTSUPPORT;
}

