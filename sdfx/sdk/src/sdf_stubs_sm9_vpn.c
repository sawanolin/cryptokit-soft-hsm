/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file sdf_stubs_sm9_vpn.c
 * @brief Stub implementations for SM9 and VPN-related SDF functions
 * @details This file provides stub implementations for SM9 algorithms
 *          and VPN protocol support functions.
 */

#include "sdf_internal.h"
#include <stdio.h>

/************************************************************************
 * 附录B.2 SM9算法相关接口函数
 ************************************************************************/

int SDF_ExportUserID_SM9(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    BYTE *pucUserID,
    ULONG *puiUserIDLen)
{
    (void)hSessionHandle;
    (void)uiKeyIndex;
    (void)pucUserID;
    (void)puiUserIDLen;

    fprintf(stderr, "[STUB] SDF_ExportUserID_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_GenerateEncMasterKeyPair_SM9(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    ULONG *uiMasterKeyIndex,
    SM9EncMasterPublicKey *pEncMasterPublicKey)
{
    (void)hSessionHandle;
    (void)uiAlgID;
    (void)uiMasterKeyIndex;
    (void)pEncMasterPublicKey;

    fprintf(stderr, "[STUB] SDF_GenerateEncMasterKeyPair_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyWithEMK_SM9(
    HANDLE hSessionHandle,
    ULONG uiKeyLen,
    SM9EncMasterPublicKey *pEncMasterPublicKey,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    SM9KeyPackage *pKeyPackage,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)uiKeyLen;
    (void)pEncMasterPublicKey;
    (void)pucUserID;
    (void)uiUserIDLen;
    (void)pKeyPackage;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_GenerateKeyWithEMK_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyWithIMK_SM9(
    HANDLE hSessionHandle,
    ULONG uiKeyLen,
    ULONG uiMasterKeyIndex,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    SM9KeyPackage *pKeyPackage,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)uiKeyLen;
    (void)uiMasterKeyIndex;
    (void)pucUserID;
    (void)uiUserIDLen;
    (void)pKeyPackage;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_GenerateKeyWithIMK_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_ImportKeyWithISK_SM9(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    ULONG uiKeyLen,
    SM9KeyPackage *pKeyPackage,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)uiISKIndex;
    (void)uiKeyLen;
    (void)pKeyPackage;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_ImportKeyWithISK_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_GenerateAgreementDataWithSM9(
    HANDLE hSessionHandle,
    ULONG uiMasterKeyIndex,
    ULONG uiISKIndex,
    ULONG uiKeyBits,
    BYTE *pResponseID,
    ULONG ulResponseIDLen,
    BYTE *pSponsorID,
    ULONG ulSponsorIDLen,
    SM9EncMasterPublicKey *pPublicKey,
    SM9EncMasterPublicKey *pSponsorTempPublicKey,
    HANDLE *phAgreementHandle)
{
    (void)hSessionHandle;
    (void)uiMasterKeyIndex;
    (void)uiISKIndex;
    (void)uiKeyBits;
    (void)pResponseID;
    (void)ulResponseIDLen;
    (void)pSponsorID;
    (void)ulSponsorIDLen;
    (void)pPublicKey;
    (void)pSponsorTempPublicKey;
    (void)phAgreementHandle;

    fprintf(stderr, "[STUB] SDF_GenerateAgreementDataWithSM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyWithSM9(
    HANDLE hSessionHandle,
    HANDLE hAgreementHandle,
    SM9EncMasterPublicKey *pTempPublicKey,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)hAgreementHandle;
    (void)pTempPublicKey;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_GenerateKeyWithSM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_GenerateAgreementDataAndKeyWithSM9(
    HANDLE hSessionHandle,
    ULONG uiMasterKeyIndex,
    ULONG uiISKIndex,
    ULONG uiKeyBits,
    BYTE *pResponseID,
    ULONG ulResponseIDLen,
    BYTE *pSponsorID,
    ULONG ulSponsorIDLen,
    SM9EncMasterPublicKey *pPublicKey,
    SM9EncMasterPublicKey *pSponsorTempPublicKey,
    SM9EncMasterPublicKey *pResponseTempPublicKey,
    HANDLE *phKeyHandle)
{
    (void)hSessionHandle;
    (void)uiMasterKeyIndex;
    (void)uiISKIndex;
    (void)uiKeyBits;
    (void)pResponseID;
    (void)ulResponseIDLen;
    (void)pSponsorID;
    (void)ulSponsorIDLen;
    (void)pPublicKey;
    (void)pSponsorTempPublicKey;
    (void)pResponseTempPublicKey;
    (void)phKeyHandle;

    fprintf(stderr, "[STUB] SDF_GenerateAgreementDataAndKeyWithSM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_VerifyWithMasterEPK_SM9(
    HANDLE hSessionHandle,
    SM9SignMasterPublicKey *pSignPublicKey,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Signature *pSignature)
{
    (void)hSessionHandle;
    (void)pSignPublicKey;
    (void)pucUserID;
    (void)uiUserIDLen;
    (void)pucData;
    (void)uiDataLength;
    (void)pSignature;

    fprintf(stderr, "[STUB] SDF_VerifyWithMasterEPK_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_VerifyWithMasterIPK_SM9(
    HANDLE hSessionHandle,
    ULONG uiSignMasterKeyIndex,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Signature *pSignature)
{
    (void)hSessionHandle;
    (void)uiSignMasterKeyIndex;
    (void)pucUserID;
    (void)uiUserIDLen;
    (void)pucData;
    (void)uiDataLength;
    (void)pSignature;

    fprintf(stderr, "[STUB] SDF_VerifyWithMasterIPK_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_InternalSignWithMasterEPK_SM9(
    HANDLE hSessionHandle,
    SM9SignMasterPublicKey *pSignPublicKey,
    ULONG uiISKIndex,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Signature *pSignature)
{
    (void)hSessionHandle;
    (void)pSignPublicKey;
    (void)uiISKIndex;
    (void)pucData;
    (void)uiDataLength;
    (void)pSignature;

    fprintf(stderr, "[STUB] SDF_InternalSignWithMasterEPK_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_InternalSignWithMasterIPK_SM9(
    HANDLE hSessionHandle,
    ULONG uiMasterKeyIndex,
    ULONG uiISKIndex,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Signature *pSignature)
{
    (void)hSessionHandle;
    (void)uiMasterKeyIndex;
    (void)uiISKIndex;
    (void)pucData;
    (void)uiDataLength;
    (void)pSignature;

    fprintf(stderr, "[STUB] SDF_InternalSignWithMasterIPK_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_EncryptWithMasterEPK_SM9(
    HANDLE hSessionHandle,
    SM9EncMasterPublicKey *pEncPublicKey,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    ULONG ulAlgID,
    BYTE *pucIV,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Cipher *pEncData)
{
    (void)hSessionHandle;
    (void)pEncPublicKey;
    (void)pucUserID;
    (void)uiUserIDLen;
    (void)ulAlgID;
    (void)pucIV;
    (void)pucData;
    (void)uiDataLength;
    (void)pEncData;

    fprintf(stderr, "[STUB] SDF_EncryptWithMasterEPK_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_EncryptWithMasterIPK_SM9(
    HANDLE hSessionHandle,
    ULONG uiMasterKeyIndex,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    ULONG ulAlgID,
    BYTE *pucIV,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Cipher *pEncData)
{
    (void)hSessionHandle;
    (void)uiMasterKeyIndex;
    (void)pucUserID;
    (void)uiUserIDLen;
    (void)ulAlgID;
    (void)pucIV;
    (void)pucData;
    (void)uiDataLength;
    (void)pEncData;

    fprintf(stderr, "[STUB] SDF_EncryptWithMasterIPK_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_DecryptWithISK_SM9(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    ULONG ulAlgID,
    BYTE *pucIV,
    SM9Cipher *pEncData,
    ULONG *puiDataLength,
    BYTE *pucData)
{
    (void)hSessionHandle;
    (void)uiISKIndex;
    (void)pucUserID;
    (void)uiUserIDLen;
    (void)ulAlgID;
    (void)pucIV;
    (void)pEncData;
    (void)puiDataLength;
    (void)pucData;

    fprintf(stderr, "[STUB] SDF_DecryptWithISK_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_ExternalSign_SM9(
    HANDLE hSessionHandle,
    SM9SignMasterPublicKey *pSignMastPublicKey,
    SM9SignUserPrivateKey *pSignUserPrivateKey,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Signature *pSignature)
{
    (void)hSessionHandle;
    (void)pSignMastPublicKey;
    (void)pSignUserPrivateKey;
    (void)pucData;
    (void)uiDataLength;
    (void)pSignature;

    fprintf(stderr, "[STUB] SDF_ExternalSign_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}

int SDF_ExternalDecrypt_SM9(
    HANDLE hSessionHandle,
    SM9EncUserPrivateKey *pEncUserPrivateKey,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    ULONG uiAlgID,
    BYTE *pucIV,
    SM9Cipher *pEncData,
    BYTE *pucData,
    ULONG *puiDataLength)
{
    (void)hSessionHandle;
    (void)pEncUserPrivateKey;
    (void)pucUserID;
    (void)uiUserIDLen;
    (void)uiAlgID;
    (void)pucIV;
    (void)pEncData;
    (void)pucData;
    (void)puiDataLength;

    fprintf(stderr, "[STUB] SDF_ExternalDecrypt_SM9 not implemented\n");
    return SDR_NOTSUPPORT;
}
