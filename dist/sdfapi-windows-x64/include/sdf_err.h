#ifndef __SDF_ERR_H__
#define __SDF_ERR_H__

/* 附录A (规范性) 函数返回代码定义 */
/* A.1 Function Return Code Definitions */

#define SDR_OK                      0x00000000      // 操作成功 (Success)
#define SDR_BASE                    0x01000000      // 错误码基础值 (Base value for error codes)
#define SDR_UNKNOWERR               (SDR_BASE + 0x00000001) // 未知错误 (Unknown error)
#define SDR_NOTSUPPORT              (SDR_BASE + 0x00000002) // 不支持的接口调用 (Unsupported interface)
#define SDR_COMMFAIL                (SDR_BASE + 0x00000003) // 与设备通信失败 (Communication failure)
#define SDR_HARDFAIL                (SDR_BASE + 0x00000004) // 运算模块无响应 (Hardware failure/no response)
#define SDR_OPENDEVICE              (SDR_BASE + 0x00000005) // 打开设备失败 (Failed to open device)
#define SDR_OPENSESSION             (SDR_BASE + 0x00000006) // 创建会话失败 (Failed to open session)
#define SDR_PARDENY                 (SDR_BASE + 0x00000007) // 无私钥使用权限 (Private key access denied)
#define SDR_KEYNOTEXIST             (SDR_BASE + 0x00000008) // 不存在的密钥调用 (Key does not exist)
#define SDR_ALGNOTSUPPORT           (SDR_BASE + 0x00000009) // 不支持的算法调用 (Algorithm not supported)
#define SDR_ALGMODNOTSUPPORT        (SDR_BASE + 0x0000000A) // 不支持的算法模式调用 (Algorithm mode not supported)
#define SDR_PKOPERR                 (SDR_BASE + 0x0000000B) // 公钥运算失败 (Public key operation error)
#define SDR_SKOPERR                 (SDR_BASE + 0x0000000C) // 私钥运算失败 (Private key operation error)
#define SDR_SIGNERR                 (SDR_BASE + 0x0000000D) // 签名运算失败 (Sign operation error)
#define SDR_VERIFYERR               (SDR_BASE + 0x0000000E) // 验证签名失败 (Verify operation error)
#define SDR_SYMOPERR                (SDR_BASE + 0x0000000F) // 对称算法运算失败 (Symmetric operation error)
#define SDR_STEPERR                 (SDR_BASE + 0x00000010) // 多步运算步骤错误 (Multi-step operation sequence error)
#define SDR_FILESIZEERR             (SDR_BASE + 0x00000011) // 文件长度超出限制 (File size error)
#define SDR_FILENOEXIST             (SDR_BASE + 0x00000012) // 指定的文件不存在 (File does not exist)
#define SDR_FILEOFSERR              (SDR_BASE + 0x00000013) // 文件起始位置错误 (File offset error)
#define SDR_KEYTYPEERR              (SDR_BASE + 0x00000014) // 密钥类型错误 (Key type error)
#define SDR_KEYERR                  (SDR_BASE + 0x00000015) // 密钥错误 (Key error)
#define SDR_ENCDATAERR              (SDR_BASE + 0x00000016) // ECC 加密数据错误 (ECC encrypted data error)
#define SDR_RANDERR                 (SDR_BASE + 0x00000017) // 随机数产生失败 (Random generation error)
#define SDR_PRKRERR                 (SDR_BASE + 0x00000018) // 私钥使用权限获取失败 (Failed to get private key access right)
#define SDR_MACERR                  (SDR_BASE + 0x00000019) // MAC 运算失败 (MAC operation error)
#define SDR_FILEEXISTS              (SDR_BASE + 0x0000001A) // 指定文件已存在 (File already exists)
#define SDR_FILEWERR                (SDR_BASE + 0x0000001B) // 文件写入失败 (File write error)
#define SDR_NOBUFFER                (SDR_BASE + 0x0000001C) // 存储空间不足 (Insufficient buffer space)
#define SDR_INARGERR                (SDR_BASE + 0x0000001D) // 输入参数错误 (Invalid input argument)
#define SDR_OUTARGERR               (SDR_BASE + 0x0000001E) // 输出参数错误 (Invalid output argument)
#define SDR_USERIDERR               (SDR_BASE + 0x0000001F) // 用户标识错误 (User ID error)

#endif /* __SDF_ERR_H__ */

