# GM/T 0018-2023 API 实现矩阵

更新时间：2026-07-31

本矩阵对应当前源码和 Docker 端到端测试结果。项目定位是学习、开发和接口联调用的软件密码设备模拟器，不代表经过商用密码检测认证的硬件服务器密码机。未实现接口明确返回 `SDR_NOTSUPPORT`，不会伪造成功。

## 已实现并通过端到端测试


| 分类         | 接口                                                                                                                              | 当前能力                                                                          |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| 设备/会话    | `SDF_OpenDevice`、`SDF_CloseDevice`、`SDF_OpenSession`、`SDF_CloseSession`                                                        | 远程 ID、本地不透明句柄、服务端引用计数和并发保护                                 |
| 设备信息     | `SDF_GetDeviceInfo`                                                                                                               | 能力位只声明当前实际提供的算法；Web 设置的厂商、设备名和序列号持久化并由 SDF 返回 |
| 随机数       | `SDF_GenerateRandom`                                                                                                              | openHiTLS 随机数，单次最多 4096 字节                                              |
| SM2 外部运算 | `SDF_GenerateKeyPair_ECC`、`SDF_ExternalEncrypt_ECC`、`SDF_ExternalDecrypt_ECC`、`SDF_ExternalSign_ECC`、`SDF_ExternalVerify_ECC` | 真实 256 位 SM2；标准`ECCCipher` C1/C3/C2 与定长 r/s 映射                         |
| RSA 密钥与运算 | `SDF_GenerateKeyPair_RSA`、`SDF_ExternalPublicKeyOperation_RSA`、`SDF_ExternalPrivateKeyOperation_RSA`、`SDF_InternalPublicKeyOperation_RSA`、`SDF_InternalPrivateKeyOperation_RSA` | 1024–2048 位 RSA，支持内外部无填充公私钥运算 |
| RSA 会话密钥 | `SDF_ExportSignPublicKey_RSA`、`SDF_ExportEncPublicKey_RSA`、`SDF_GenerateKeyWithIPK_RSA`、`SDF_GenerateKeyWithEPK_RSA`、`SDF_ImportKeyWithISK_RSA` | PKCS#1 v1.5 包装 128/256 位会话密钥 |
| SM2 内部密钥 | `SDF_ExportSignPublicKey_ECC`、`SDF_ExportEncPublicKey_ECC`                                                                       | 签名、加密为独立密钥对，可使用不同索引；只导出公钥                                |
| 私钥权限     | `SDF_GetPrivateKeyAccessRight`、`SDF_ReleasePrivateKeyAccessRight`                                                                | 权限属于具体会话；错误口令、未授权和释放后调用均拒绝                              |
| SM2 内部运算 | `SDF_InternalSign_ECC`、`SDF_InternalVerify_ECC`                                                                                  | 使用内部签名密钥；签名需要会话权限，验签使用内部公钥                              |
| ECC 会话密钥 | `SDF_GenerateKeyWithIPK_ECC`、`SDF_GenerateKeyWithEPK_ECC`、`SDF_ImportKeyWithISK_ECC`                                            | 128/256 位会话密钥经 SM2 加密密钥封装；私钥导入需要权限                           |
| KEK 会话密钥 | `SDF_GenerateKeyWithKEK`、`SDF_ImportKeyWithKEK`、`SDF_DestroyKey`                                                                | SM4-ECB 包装、KEK 按索引持久化、客户端仅持有不透明句柄                            |
| 对称运算     | `SDF_Encrypt`、`SDF_Decrypt`                                                                                                      | SM4-ECB/CBC/CFB/OFB/CTR；ECB/CBC 不自动填充                                       |
| MAC          | `SDF_CalculateMAC`                                                                                                                | SM4 CBC-MAC，16 字节输出                                                          |
| 摘要         | `SDF_HashInit`、`SDF_HashUpdate`、`SDF_HashFinal`                                                                                 | SM3 分段摘要                                                                      |
| 文件         | `SDF_CreateFile`、`SDF_ReadFile`、`SDF_WriteFile`、`SDF_DeleteFile`                                                               | 持久化、偏移读写、文件名十六进制编码，最大 1 MiB                                  |

## 内部密钥安全状态

- SM2 和 RSA 的签名/加密密钥分别存放在独立目录，索引范围为 1–1024。
- 私钥访问控制码可以为空；非空口令使用随机盐和 20000 轮 SM3 派生，空口令使用设备根秘密派生，私钥均以 SM4-CTR 加密持久化。
- 每条 SM2/RSA 记录把算法、类型、索引、公钥、加密私钥和元数据纳入 HMAC-SM3；每条 SM4 对称密钥记录把版本、算法、位数、索引和密钥材料纳入 HMAC-SM3。设备 HMAC 密钥在初始化时自动生成且无修改/导出接口。
- 旧版 16 字节对称密钥文件在首次读取时自动迁移为带 HMAC-SM3 的版本化记录；校验失败的记录不能参与 KEK 密钥封装或导入。
- 改索引时重新计算 HMAC；空口令私钥还会按新索引重新派生加密密钥。Web 提供显式完整性校验。
- 口令明文、派生秘密、内部私钥、对称密钥和会话密钥均不通过管理 API 返回。

## 部分实现


| 接口/能力                        | 已有部分                                                                                                            | 当前限制                                                       |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `SDF_HashInit` 的 SM2 Z 值预处理 | 普通摘要流程完整                                                                                                    | 传入公钥、身份或非零身份长度时明确返回`SDR_NOTSUPPORT`         |
| SM4-GCM                          | 服务端密码引擎有算法映射                                                                                            | `SDF_AuthEnc*` / `SDF_AuthDec*` 的 AAD、标签和流式状态尚未接入 |
| TCP 协议                         | Linux 与 Windows x64 客户端均已验证；固定宽度、网络字节序、64 位远程句柄                                            | 业务通道当前未启用 TLS，部署时应限制在受控网络                 |
| 持久化                           | 对称密钥、内部 SM2/RSA 密钥、设备完整性密钥、用户文件、Web 状态、审计和备份均持久化；支持恢复与完全重置 | 数据卷属于软件安全边界，备份包未整包加密 |
| 管理功能                         | 四角色 RBAC、管理员管理、设备信息、SM2/RSA/对称密钥、索引修改、HMAC 校验、RSA 自检、会话、备份恢复和 TXT 审计 | 按交付决定不提供独立 Unix 管理接口 |

## 未实现，明确返回 `SDR_NOTSUPPORT`


| 分类            | 接口                                                                                                                                                                                |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ECC 协商        | `SDF_GenerateAgreementDataWithECC`、`SDF_GenerateKeyWithECC`、`SDF_GenerateAgreementDataAndKeyWithECC`                                                                              |
| 认证加密        | `SDF_AuthEnc`、`SDF_AuthDec` 及其 Init/Update/Final 接口                                                                                                                            |
| 流式对称运算    | `SDF_EncryptInit/Update/Final`、`SDF_DecryptInit/Update/Final`                                                                                                                      |
| 流式 MAC/HMAC   | `SDF_CalculateMACInit/Update/Final`、`SDF_HMACInit/Update/Final`                                                                                                                    |
| 外部密钥扩展    | `SDF_ExternalKeyEncrypt`、`SDF_ExternalKeyDecrypt` 及 Init 接口、`SDF_ExternalKeyHMACInit`                                                                                          |
| SM9 与 VPN 扩展 | `sdf.h` 中全部 SM9、IKE、IPSEC、SSL 扩展接口                                                                                                                                        |

## 协议、容器和安全检查

- 协议版本为 2.0；服务端在解析变长请求前验证结构体长度、声明长度、总长度和上限。
- TCP 收发处理短读、短写、EOF、过长响应和错误响应头。
- 会话密钥只存在于服务端内存；关闭会话时清理，`SDF_DestroyKey` 可提前销毁。
- 用户文件名不直接用于路径拼接；对称密钥、内部密钥和用户文件目录均位于 `SDFX_DATA_DIR`。
- Docker 运行镜像包含 `sdfxd`、openHiTLS 运行库、Web 后端/静态资源和 supervisord，不包含 Linux SDK、头文件或静态库。
- Docker 健康检查同时探测 TCP 18081 和 Web `/api/health`，当前验证结果为 `healthy`。
- 当前业务 TCP 通道没有 TLS 或双向认证，应只绑定本机或部署在受控网络中。

## 当前测试门禁

Docker Linux 端到端测试共 6 组：

1. 设备和会话生命周期。
2. 随机数和边界长度。
3. SM3 分段摘要。
4. SM2 外部密钥生成、加解密、签名验签和非法输入。
5. 对称密钥包装/导入、SM4-CBC、SM4-MAC、会话密钥销毁和用户文件。
6. 内部签名/验签、独立签名/加密索引、私钥访问权限、SM2 会话密钥封装/导入。
7. 四角色 RBAC、空口令、SM2/RSA 改索引、非对称/对称密钥 HMAC-SM3 完整性校验、审计配置与 TXT 导出。
8. Windows `tests/test1.c` SM2 回环和 `tests/rsa_e2e.c` RSA 内外部运算、IPK/ISK 会话密钥回环。

当前 CTest 结果：**6/6 通过**。综合 RBAC/密钥完整性端到端测试、无令牌管理命令拒绝测试通过，容器重启后管理员状态、设备标识和内部密钥仍存在。Windows x64 SDK 已生成 DLL、导入库、头文件、配置和示例，并完成 Windows 到 Docker 的真实连接测试；模糊输入门禁仍待完成。
## 项目授权

CryptoKit SoftHSM 原创代码与修改采用 GNU AGPL v3.0 only
（`AGPL-3.0-only`），源码仓库为
<https://github.com/sawanolin/cryptokit-soft-hsm>。SDFX 和 openHiTLS 原始
材料保留各自许可证；详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
