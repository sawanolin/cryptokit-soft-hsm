#ifndef __SDF_H__
#define __SDF_H__

#include "sdf_types.h"
#include "sdf_err.h"

#if defined(_WIN32)
# if defined(SDFAPI_EXPORTS)
#  define SDF_API __declspec(dllexport)
# else
#  define SDF_API __declspec(dllimport)
# endif
#else
# define SDF_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/************************************************************************
 * 6.2 设备管理类函数 (Device Management Functions)
 ************************************************************************/

/* 6.2.2 打开设备 */
LONG SDF_OpenDevice(
    HANDLE *phDeviceHandle
);

/* 6.2.3 关闭设备 */
LONG SDF_CloseDevice(
    HANDLE hDeviceHandle
);

/* 6.2.4 创建会话 */
LONG SDF_OpenSession(
    HANDLE hDeviceHandle,
    HANDLE *phSessionHandle
);

/* 6.2.5 关闭会话 */
LONG SDF_CloseSession(
    HANDLE hSessionHandle
);

/* 6.2.6 获取设备信息 */
LONG SDF_GetDeviceInfo(
    HANDLE hSessionHandle,
    DEVICEINFO *pstDeviceInfo
);

/* 6.2.7 产生随机数 */
LONG SDF_GenerateRandom(
    HANDLE hSessionHandle,
    ULONG uiLength,
    BYTE *pucRandom
);

/* 6.2.8 获取私钥使用权限 */
LONG SDF_GetPrivateKeyAccessRight(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    LPSTR pucPassword,
    ULONG uiPwdLength
);

/* 6.2.9 释放私钥使用权限 */
LONG SDF_ReleasePrivateKeyAccessRight(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex
);


/************************************************************************
 * 6.3 密钥管理类函数 (Key Management Functions)
 ************************************************************************/

/* 6.3.2 导出 RSA 签名公钥 */
LONG SDF_ExportSignPublicKey_RSA(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    RSArefPublicKey *pucPublicKey
);

/* 6.3.3 导出 RSA 加密公钥 */
LONG SDF_ExportEncPublicKey_RSA(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    RSArefPublicKey *pucPublicKey
);

/* 6.3.4 生成会话密钥并用内部RSA公钥加密输出 */
LONG SDF_GenerateKeyWithIPK_RSA(
    HANDLE hSessionHandle,
    ULONG uiIPKIndex,
    ULONG uiKeyBits,
    BYTE *pucKey,
    ULONG *puiKeyLength,
    HANDLE *phKeyHandle
);

/* 6.3.5 生成会话密钥并用外部RSA公钥加密输出 */
LONG SDF_GenerateKeyWithEPK_RSA(
    HANDLE hSessionHandle,
    ULONG uiKeyBits,
    RSArefPublicKey *pucPublicKey,
    BYTE *pucKey,
    ULONG *puiKeyLength,
    HANDLE *phKeyHandle
);

/* 6.3.6 导入会话密钥并用内部RSA 私钥解密 */
LONG SDF_ImportKeyWithISK_RSA(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    BYTE *pucKey,
    ULONG uiKeyLength,
    HANDLE *phKeyHandle
);

/* 6.3.7 导出ECC签名公钥 */
LONG SDF_ExportSignPublicKey_ECC(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    ECCrefPublicKey *pucPublicKey
);

/* 6.3.8 导出ECC 加密公钥 */
LONG SDF_ExportEncPublicKey_ECC(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    ECCrefPublicKey *pucPublicKey
);

/* 6.3.9 生成会话密钥并用内部ECC公钥加密输出 */
LONG SDF_GenerateKeyWithIPK_ECC(
    HANDLE hSessionHandle,
    ULONG uiIPKIndex,
    ULONG uiKeyBits,
    ECCCipher *pucKey,
    HANDLE *phKeyHandle
);

/* 6.3.10 生成会话密钥并用外部ECC公钥加密输出 */
LONG SDF_GenerateKeyWithEPK_ECC(
    HANDLE hSessionHandle,
    ULONG uiKeyBits,
    ULONG uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucKey,
    HANDLE *phKeyHandle
);

/* 6.3.11 导入会话密钥并用内部ECC私钥解密 */
LONG SDF_ImportKeyWithISK_ECC(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    ECCCipher *pucKey,
    HANDLE *phKeyHandle
);

/* 6.3.12 生成密钥协商参数并输出 */
LONG SDF_GenerateAgreementDataWithECC(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    ULONG uiKeyBits,
    BYTE *pucSponsorID,
    ULONG uiSponsorIDLength,
    ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey,
    HANDLE *phAgreementHandle
);

/* 6.3.13 计算会话密钥 */
LONG SDF_GenerateKeyWithECC(
    HANDLE hSessionHandle,
    BYTE *pucResponseID,
    ULONG uiResponseIDLength,
    ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey,
    HANDLE hAgreementHandle,
    HANDLE *phKeyHandle
);

/* 6.3.14 产生协商数据并计算会话密钥 */
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
    HANDLE *phKeyHandle
);

/* 6.3.15 生成会话密钥并用密钥加密密钥加密输出 */
LONG SDF_GenerateKeyWithKEK(
    HANDLE hSessionHandle,
    ULONG uiKeyBits,
    ULONG uiAlgID,
    ULONG uiKEKIndex,
    BYTE *pucKey,
    ULONG *puiKeyLength,
    HANDLE *phKeyHandle
);

/* 6.3.16 导入会话密钥并用密钥加密密钥解密 */
LONG SDF_ImportKeyWithKEK(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    ULONG uiKEKIndex,
    BYTE *pucKey,
    ULONG uiKeyLength,
    HANDLE *phKeyHandle
);

/* 6.3.17 销毁会话密钥 */
LONG SDF_DestroyKey(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle
);


/************************************************************************
 * 6.4 非对称算法运算类函数 (Asymmetric Algorithm Functions)
 ************************************************************************/

/* 6.4.2 外部公钥 RSA 运算 */
LONG SDF_ExternalPublicKeyOperation_RSA(
    HANDLE hSessionHandle,
    RSArefPublicKey *pucPublicKey,
    BYTE *pucDataInput,
    ULONG uiInputLength,
    BYTE *pucDataOutput,
    ULONG *puiOutputLength
);

/* 6.4.3 内部公钥 RSA 运算 */
LONG SDF_InternalPublicKeyOperation_RSA(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    BYTE *pucDataInput,
    ULONG uiInputLength,
    BYTE *pucDataOutput,
    ULONG *puiOutputLength
);

/* 6.4.4 内部私钥 RSA 运算 */
LONG SDF_InternalPrivateKeyOperation_RSA(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    BYTE *pucDataInput,
    ULONG uiInputLength,
    BYTE *pucDataOutput,
    ULONG *puiOutputLength
);

/* 6.4.5 外部公钥 ECC 验证 */
LONG SDF_ExternalVerify_ECC(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    BYTE *pucDataInput,
    ULONG uiInputLength,
    ECCSignature *pucSignature
);

/* 6.4.6 内部私钥ECC签名 */
LONG SDF_InternalSign_ECC(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    BYTE *pucData,
    ULONG uiDataLength,
    ECCSignature *pucSignature
);

/* 6.4.7 内部公钥 ECC 验证 */
LONG SDF_InternalVerify_ECC(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    BYTE *pucData,
    ULONG uiDataLength,
    ECCSignature *pucSignature
);

/* 6.4.8 外部公钥 ECC 加密 */
LONG SDF_ExternalEncrypt_ECC(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    BYTE *pucData,
    ULONG uiDataLength,
    ECCCipher *pucEncData
);


/************************************************************************
 * 6.5 对称算法运算类函数 (Symmetric Algorithm Functions)
 ************************************************************************/

/* 6.5.2 单包对称加密 */
LONG SDF_Encrypt(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucIV,
    BYTE *pucData,
    ULONG uiDataLength,
    BYTE *pucEncData,
    ULONG *puiEncDataLength
);

/* 6.5.3 单包对称解密 */
LONG SDF_Decrypt(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucIV,
    BYTE *pucEncData,
    ULONG uiEncDataLength,
    BYTE *pucData,
    ULONG *puiDataLength
);

/* 6.5.4 计算单包 MAC */
LONG SDF_CalculateMAC(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucIV,
    BYTE *pucData,
    ULONG uiDataLength,
    BYTE *pucMac,
    ULONG *puiMacLength
);

/* 6.5.5 单包可鉴别加密 */
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
    ULONG *puiAuthDataLength
);

/* 6.5.6 单包可鉴别解密 */
LONG SDF_AuthDec(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucStartVar,
    ULONG uiStartVarLength,
    BYTE *pucAad,
    ULONG uiAadLength,
    BYTE *pucAuthData,
    ULONG uiAuthDataLength, // 规范中为 puiAuthDataLength，疑为笔误
    BYTE *pucEncData,
    ULONG uiEncDataLength,
    BYTE *pucData,
    ULONG *puiDataLength
);

/* 6.5.7 多包对称加密初始化 */
LONG SDF_EncryptInit(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucIV,
    ULONG uiIVLength
);

/* 6.5.8 多包对称加密 */
LONG SDF_EncryptUpdate(
    HANDLE hSessionHandle,
    BYTE *pucData,
    ULONG uiDataLength,
    BYTE *pucEncData,
    ULONG *puiEncDataLength
);

/* 6.5.9 多包对称加密结束 */
LONG SDF_EncryptFinal(
    HANDLE hSessionHandle,
    BYTE *pucLastEncData,
    ULONG *puiLastEncDataLength
);

/* 6.5.10 多包对称解密初始化 */
LONG SDF_DecryptInit(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucIV,
    ULONG uiIVLength
);

/* 6.5.11 多包对称解密 */
LONG SDF_DecryptUpdate(
    HANDLE hSessionHandle,
    BYTE *pucEncData,
    ULONG uiEncDataLength,
    BYTE *pucData,
    ULONG *puiDataLength
);

/* 6.5.12 多包对称解密结束 */
LONG SDF_DecryptFinal(
    HANDLE hSessionHandle,
    BYTE *pucLastData,
    ULONG *puiLastDataLength
);

/* 6.5.13 多包 MAC 初始化 */
LONG SDF_CalculateMACInit(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucIV,
    ULONG uiIVLength
);

/* 6.5.14 多包MAC计算 */
LONG SDF_CalculateMACUpdate(
    HANDLE hSessionHandle,
    BYTE *pucData,
    ULONG uiDataLength
);

/* 6.5.15 多包MAC结束 */
LONG SDF_CalculateMACFinal(
    HANDLE hSessionHandle,
    BYTE *pucMac,
    ULONG *puiMacLength
);

/* 6.5.16 多包可鉴别加密初始化 */
LONG SDF_AuthEncInit(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID,
    BYTE *pucStartVar,
    ULONG uiStartVarLength,
    BYTE *pucAad,
    ULONG uiAadLength,
    ULONG uiDataLength
);

/* 6.5.17 多包可鉴别加密 */
LONG SDF_AuthEncUpdate(
    HANDLE hSessionHandle,
    BYTE *pucData,
    ULONG uiDataLength,
    BYTE *pucEncData,
    ULONG *puiEncDataLength
);

/* 6.5.18 多包可鉴别加密结束 */
LONG SDF_AuthEncFinal(
    HANDLE hSessionHandle,
    BYTE *pucLastEncData,
    ULONG *puiLastEncDataLength,
    BYTE *pucAuthData,
    ULONG *puiAuthDataLength
);

/* 6.5.19 多包可鉴别解密初始化 */
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
    ULONG uiDataLength
);

/* 6.5.20 多包可鉴别解密 */
LONG SDF_AuthDecUpdate(
    HANDLE hSessionHandle,
    BYTE *pucEncData,
    ULONG uiEncDataLength,
    BYTE *pucData,
    ULONG *puiDataLength
);

/* 6.5.21 多包可鉴别解密结束 */
LONG SDF_AuthDecFinal(
    HANDLE hSessionHandle,
    BYTE *pucLastData,
    ULONG *puiLastDataLength
);


/************************************************************************
 * 6.6 杂凑运算类函数 (Hash Operation Functions)
 ************************************************************************/

/* 6.6.2 带密钥的杂凑运算初始化 */
LONG SDF_HMACInit(
    HANDLE hSessionHandle,
    HANDLE hKeyHandle,
    ULONG uiAlgID
);

/* 6.6.3 带密钥的多包杂凑运算 */
LONG SDF_HMACUpdate(
    HANDLE hSessionHandle,
    BYTE *pucData,
    ULONG uiDataLength
);

/* 6.6.4 带密钥的杂凑运算结束 */
LONG SDF_HMACFinal(
    HANDLE hSessionHandle,
    BYTE *pucHMac,
    ULONG *puiHMacLength
);

/* 6.6.5 杂凑运算初始化 */
LONG SDF_HashInit(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    BYTE *pucID,
    ULONG uiIDLength
);

/* 6.6.6 多包杂凑运算 */
LONG SDF_HashUpdate(
    HANDLE hSessionHandle,
    BYTE *pucData,
    ULONG uiDataLength
);

/* 6.6.7 杂凑运算结束 */
LONG SDF_HashFinal(
    HANDLE hSessionHandle,
    BYTE *pucHash,
    ULONG *puiHashLength
);


/************************************************************************
 * 6.7 用户文件操作类函数 (User File Operation Functions)
 ************************************************************************/

/* 6.7.2 创建文件 */
LONG SDF_CreateFile(
    HANDLE hSessionHandle,
    LPSTR pucFileName,
    ULONG uiNameLen,
    ULONG uiFileSize
);

/* 6.7.3 读取文件 */
LONG SDF_ReadFile(
    HANDLE hSessionHandle,
    LPSTR pucFileName,
    ULONG uiNameLen,
    ULONG uiOffset,
    ULONG *puiFileLength,
    BYTE *pucBuffer
);

/* 6.7.4 写文件 */
LONG SDF_WriteFile(
    HANDLE hSessionHandle,
    LPSTR pucFileName,
    ULONG uiNameLen,
    ULONG uiOffset,
    ULONG uiFileLength,
    BYTE *pucBuffer
);

/* 6.7.5 删除文件 */
LONG SDF_DeleteFile(
    HANDLE hSessionHandle,
    LPSTR pucFileName,
    ULONG uiNameLen
);


/************************************************************************
 * 6.8 验证调试类函数 (Validation and Debug Functions)
 ************************************************************************/

/* 6.8.2 产生 RSA 非对称密钥对并输出 */
LONG SDF_GenerateKeyPair_RSA(
    HANDLE hSessionHandle, // 规范中缺少 hSessionHandle，但调试函数通常需要
    ULONG uiKeyBits,
    RSArefPublicKey *pucPublicKey,
    RSArefPrivateKey *pucPrivateKey
);

/* 6.8.3 产生ECC非对称密钥对并输出 */
LONG SDF_GenerateKeyPair_ECC(
    HANDLE hSessionHandle, // 规范中缺少 hSessionHandle
    ULONG uiAlgID,
    ULONG uiKeyBits,
    ECCrefPublicKey *pucPublicKey,
    ECCrefPrivateKey *pucPrivateKey
);

/* 6.8.4 外部私钥 RSA 运算 */
LONG SDF_ExternalPrivateKeyOperation_RSA(
    HANDLE hSessionHandle, // 规范中缺少 hSessionHandle
    RSArefPrivateKey *pucPrivateKey,
    BYTE *pucDataInput,
    ULONG uiInputLength,
    BYTE *pucDataOutput,
    ULONG *puiOutputLength
);

/* 6.8.5 外部私钥 ECC签名 */
LONG SDF_ExternalSign_ECC(
    HANDLE hSessionHandle, // 规范中缺少 hSessionHandle
    ULONG uiAlgID,
    ECCrefPrivateKey *pucPrivateKey,
    BYTE *pucDataInput,
    ULONG uiInputLength,
    ECCSignature *pucSignature
);

/* 6.8.6 外部私钥 ECC 解密 */
LONG SDF_ExternalDecrypt_ECC(
    HANDLE hSessionHandle, // 规范中缺少 hSessionHandle
    ULONG uiAlgID,
    ECCrefPrivateKey *pucPrivateKey,
    ECCCipher *pucEncData,
    BYTE *pucData,
    ULONG *uiDataLength // 规范中为 uiDataLength，应为指针 *puiDataLength
);

/* 6.8.7 外部私钥SM9签名 */
int SDF_ExternalSign_SM9(
    HANDLE hSessionHandle, // 规范中缺少 hSessionHandle
    SM9SignMasterPublicKey *pSignMastPublicKey,
    SM9SignUserPrivateKey *pSignUserPrivateKey,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Signature *pSignature
);

/* 6.8.8 外部私钥SM9 解密 */
int SDF_ExternalDecrypt_SM9(
    HANDLE hSessionHandle, // 规范中缺少 hSessionHandle
    SM9EncUserPrivateKey *pEncUserPrivateKey,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    ULONG uiAlgID, // 规范中参数列表缺少此项，但描述中提及
    BYTE *pucIV,
    SM9Cipher *pEncData, // 规范中参数顺序颠倒
    BYTE *pucData,
    ULONG *puiDataLength // 规范中为 pEncData, ULONG uiDataLength, SM9Cipher pEncData
                        // 参照 6.8.6 和 B.2.16 修正了参数列表和顺序
);

/* 6.8.9 外部密钥单包对称加密 */
LONG SDF_ExternalKeyEncrypt(
    HANDLE hSessionHandle, // 规范中缺少 hSessionHandle
    ULONG uiAlgID,
    BYTE *pucKey,
    ULONG uiKeyLength,
    BYTE *pucIV,
    ULONG uiIVLength,
    BYTE *pucData,
    ULONG uiDataLength,
    BYTE *pucEncData,
    ULONG *puiEncDataLength
);

/* 6.8.10 外部密钥单包对称解密 */
LONG SDF_ExternalKeyDecrypt(
    HANDLE hSessionHandle, // 规范中缺少 hSessionHandle
    ULONG uiAlgID,
    BYTE *pucKey,
    ULONG uiKeyLength,
    BYTE *pucIV,
    ULONG uiIVLength,
    BYTE *pucEncData,
    ULONG uiEncDataLength,
    BYTE *pucData,
    ULONG *puiDataLength
);

/* 6.8.11 外部密钥多包对称加密初始化 */
LONG SDF_ExternalKeyEncryptInit(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    BYTE *pucKey,
    ULONG uiKeyLength,
    BYTE *pucIV,
    ULONG uiIVLength
);

/* 6.8.12 外部密钥多包对称解密初始化 */
LONG SDF_ExternalKeyDecryptInit(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    BYTE *pucKey,
    ULONG uiKeyLength,
    BYTE *pucIV,
    ULONG uiIVLength
);

/* 6.8.13 带外部密钥的杂凑运算初始化 */
LONG SDF_ExternalKeyHMACInit(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    BYTE *pucKey,
    ULONG uiKeyLength
);


/************************************************************************
 * 附录B.2 SM9算法相关接口函数 (SM9 Algorithm Interface Functions)
 ************************************************************************/

/* B.2.2 导出SM9用户标识 */
int SDF_ExportUserID_SM9(
    HANDLE hSessionHandle,
    ULONG uiKeyIndex,
    BYTE *pucUserID,
    ULONG *puiUserIDLen
);

/* B.2.3 产生SM9临时加密主密钥对 */
int SDF_GenerateEncMasterKeyPair_SM9(
    HANDLE hSessionHandle,
    ULONG uiAlgID,
    ULONG *uiMasterKeyIndex, // 规范中为 ULONG uiMasterKeyIndex
    SM9EncMasterPublicKey *pEncMasterPublicKey
);

/* B.2.4 生成会话密钥并用SM9外部加密主公钥和用户标识进行密钥封装并输出 */
int SDF_GenerateKeyWithEMK_SM9(
    HANDLE hSessionHandle,
    ULONG uiKeyLen,
    SM9EncMasterPublicKey *pEncMasterPublicKey,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    SM9KeyPackage *pKeyPackage,
    HANDLE *phKeyHandle
);

/* B.2.5 生成会话密钥并用SM9 内部加密主公钥和用户标识进行密钥封装并输出 */
int SDF_GenerateKeyWithIMK_SM9(
    HANDLE hSessionHandle,
    ULONG uiKeyLen,
    ULONG uiMasterKeyIndex,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    SM9KeyPackage *pKeyPackage,
    HANDLE *phKeyHandle
);

/* B.2.6 使用SM9密钥封装结构导入会话密钥并用内部SM9 加密密钥对解封装 */
int SDF_ImportKeyWithISK_SM9(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    ULONG uiKeyLen,
    SM9KeyPackage *pKeyPackage,
    HANDLE *phKeyHandle
);

/* B.2.7 SM9生成密钥协商参数并输出 */
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
    HANDLE *phAgreementHandle
);

/* B.2.8 SM9 计算会话密钥 */
int SDF_GenerateKeyWithSM9(
    HANDLE hSessionHandle,
    HANDLE hAgreementHandle,
    SM9EncMasterPublicKey *pTempPublicKey,
    HANDLE *phKeyHandle
);

/* B.2.9 SM9产生协商数据并计算会话密钥 */
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
    HANDLE *phKeyHandle
);

/* B.2.10 外部主公钥SM9验证 */
int SDF_VerifyWithMasterEPK_SM9(
    HANDLE hSessionHandle,
    SM9SignMasterPublicKey *pSignPublicKey,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Signature *pSignature
);

/* B.2.11 内部主公钥SM9验证 */
int SDF_VerifyWithMasterIPK_SM9(
    HANDLE hSessionHandle,
    ULONG uiSignMasterKeyIndex,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Signature *pSignature
);

/* B.2.12 外部主公钥SM9签名 */
int SDF_InternalSignWithMasterEPK_SM9(
    HANDLE hSessionHandle,
    SM9SignMasterPublicKey *pSignPublicKey,
    ULONG uiISKIndex,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Signature *pSignature
);

/* B.2.13 内部主公钥SM9签名 */
int SDF_InternalSignWithMasterIPK_SM9(
    HANDLE hSessionHandle,
    ULONG uiMasterKeyIndex,
    ULONG uiISKIndex,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Signature *pSignature
);

/* B.2.14 外部主公钥SM9加密 */
int SDF_EncryptWithMasterEPK_SM9(
    HANDLE hSessionHandle,
    SM9EncMasterPublicKey *pEncPublicKey,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    ULONG ulAlgID,
    BYTE *pucIV,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Cipher *pEncData
);

/* B.2.15 内部主公钥SM9加密 */
int SDF_EncryptWithMasterIPK_SM9(
    HANDLE hSessionHandle,
    ULONG uiMasterKeyIndex,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    ULONG ulAlgID,
    BYTE *pucIV,
    BYTE *pucData,
    ULONG uiDataLength,
    SM9Cipher *pEncData
);

/* B.2.16 用户密钥对SM9解密 */
int SDF_DecryptWithISK_SM9(
    HANDLE hSessionHandle,
    ULONG uiISKIndex,
    BYTE *pucUserID,
    ULONG uiUserIDLen,
    ULONG ulAlgID,
    BYTE *pucIV,
    SM9Cipher *pEncData,
    ULONG *puiDataLength,
    BYTE *pucData
);


/************************************************************************
 * 附录C VPN设备相关接口函数 (VPN Device Interface Functions)
 ************************************************************************/

/* C.2 计算 IKE 工作密钥 */
LONG SDF_GenerateKeywithIKE(
    HANDLE hSessionHandle,
    BYTE *pucSponsorNonce,
    ULONG uiSponsorNonceLength,
    BYTE *pucResponseNonce,
    ULONG uiResponseNonceLength,
    BYTE *pucSponsorCookie,
    ULONG uiSponsorCookieLength,
    BYTE *pucResponseCookie,
    ULONG uiResponseCookieLength,
    ULONG uiPrfAlgID,
    HANDLE *phKeyHandleD,
    ULONG uiKeyBitsD,
    HANDLE *phKeyHandleA,
    ULONG uiKeyBitsA,
    HANDLE *phKeyHandleE,
    ULONG uiKeyBitsE
);

/* C.3 计算 IKE工作密钥并用外部ECC公钥加密输出 */
LONG SDF_GenerateKeywithEPK_IKE(
    HANDLE hSessionHandle,
    BYTE *pucSponsorNonce,
    ULONG uiSponsorNonceLength,
    BYTE *pucResponseNonce,
    ULONG uiResponseNonceLength,
    BYTE *pucSponsorCookie,
    ULONG uiSponsorCookieLength,
    BYTE *pucResponseCookie,
    ULONG uiResponseCookieLength,
    ULONG uiPrfAlgID,
    ULONG uiEccAlgID,
    ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucKeyD,
    ULONG uiKeyBitsD,
    ECCCipher *pucKeyA,
    ULONG uiKeyBitsA,
    ECCCipher *pucKeyE,
    ULONG uiKeyBitsE
);

/* C.4 计算 IPSEC 会话密钥 */
LONG SDF_GenerateKeywithIPSEC(
    HANDLE hSessionHandle,
    BYTE *pucProtocolID,
    ULONG uiProtocolIDLength,
    BYTE *pucSpi,
    ULONG uiSpiLength,
    BYTE *pucSponsorNonce,
    ULONG uiSponsorNonceLength,
    BYTE *pucResponseNonce,
    ULONG uiResponseNonceLength,
    HANDLE hKeyHandle,
    ULONG uiPrfAlgID,
    HANDLE *phKeyHandleEnc,
    ULONG uiKeyBitsEnc,
    HANDLE *phKeyHandleMac,
    ULONG uiKeyBitsMac,
    BYTE *pucSalt,
    ULONG uiSaltLength
);

/* C.5 计算 IPSEC 会话密钥并用外部ECC公钥加密输出 */
LONG SDF_GenerateKeywithEPK_IPSEC(
    HANDLE hSessionHandle,
    BYTE *pucProtocolID,
    ULONG uiProtocolIDLength,
    BYTE *pucSpi,
    ULONG uiSpiLength,
    BYTE *pucSponsorNonce,
    ULONG uiSponsorNonceLength,
    BYTE *pucResponseNonce,
    ULONG uiResponseNonceLength,
    HANDLE hKeyHandle,
    ULONG uiPrfAlgID,
    ULONG uiEccAlgID,
    ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucKeyEnc,
    ULONG uiKeyBitsEnc,
    ECCCipher *pucKeyMac,
    ULONG uiKeyBitsMac,
    BYTE *pucSalt,
    ULONG uiSaltLength
);

/* C.6 计算 SSL 工作密钥 */
LONG SDF_GenerateKeywithSSL(
    HANDLE hSessionHandle,
    HANDLE hKeyHandlePreMaster,
    BYTE *pucClientRandom,
    ULONG uiClientRandomLength,
    BYTE *pucServerRandom,
    ULONG uiServerRandomLength,
    ULONG uiPrfAlgID,
    HANDLE *phKeyHandleClientMac,
    ULONG uiKeyBitsClientMac,
    HANDLE *phKeyHandleServerMac,
    ULONG uiKeyBitsServerMac,
    HANDLE *phKeyHandleClientEnc,
    ULONG uiKeyBitsClientEnc,
    HANDLE *phKeyHandleServerEnc,
    ULONG uiKeyBitsServerEnc,
    BYTE *pucClientIV,
    ULONG uiClientIVLength,
    BYTE *pucServerIV,
    ULONG uiServerIVLength
);

/* C.7 计算 SSL 工作密钥并用外部ECC公钥加密输出 */
LONG SDF_GenerateKeywithEPK_SSL(
    HANDLE hSessionHandle,
    HANDLE hKeyHandlePreMaster,
    BYTE *pucClientRandom,
    ULONG uiClientRandomLength,
    BYTE *pucServerRandom,
    ULONG uiServerRandomLength,
    ULONG uiPrfAlgID,
    ULONG uiEccAlgID,
    ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucKeyClientMac,
    ULONG uiKeyBitsClientMac,
    ECCCipher *pucKeyServerMac,
    ULONG uiKeyBitsServerMac,
    ECCCipher *pucKeyClientEnc,
    ULONG uiKeyBitsClientEnc,
    ECCCipher *pucKeyServerEnc,
    ULONG uiKeyBitsServerEnc,
    BYTE *pucClientIV,
    ULONG uiClientIVLength,
    BYTE *pucServerIV,
    ULONG uiServerIVLength
);

#ifdef __cplusplus
}
#endif

#endif /* __SDF_H__ */

