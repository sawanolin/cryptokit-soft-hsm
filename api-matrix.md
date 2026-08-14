# GM/T 0018-2023 API 实现矩阵

更新时间：2026-08-03

本矩阵以当前源码、动态库导出和 Docker 客户端—服务端回归为准。项目用于学习、开发和接口联调，不代表通过商用密码产品检测、GM/T 0018 一致性检测或硬件安全认证。

## 实现范围

除附录 B 的 SM9 接口外，当前 `sdf.h` 中的基础接口、扩展接口和附录 C VPN 接口均已有客户端、TCP 协议和服务端实现。SM9 符号保留导出，但明确返回 `SDR_NOTSUPPORT`。

| 分类 | 接口与能力 | 已处理的主要情况 |
| --- | --- | --- |
| 设备和会话 | Open/Close Device、Open/Close Session、GetDeviceInfo | 不透明句柄、远端 ID、引用计数、无效/跨会话句柄拒绝、关闭会话清理 |
| 随机数 | `SDF_GenerateRandom` | 1–4096 字节及非法参数 |
| 摘要及 SM2 预处理 | HashInit/Update/Final | GM/T 0006 标准 SM3/SHA-256；`SDFX_*` 扩展 SHA-1/224/384/512；`SM3 + 公钥 + 非空 ID` 计算 `ZA` 后执行 `SM3(ZA||M)`；ID 最长 8191 字节，单次 Update 最长 32 KiB |
| SM2 外部运算 | KeyPair、Encrypt/Decrypt、Sign/Verify | 256 位；`SM2_1` 签名，`SM2_2` 协商，`SM2_3` 加密；签名输入严格为 32 字节摘要 |
| SM2 内部密钥 | 公钥导出、私钥权限、内部签名/验签、IPK/EPK/ISK | 签名/加密密钥分离；空口令和会话权限；禁用、损坏、无权限和错误索引拒绝 |
| SM2 密钥协商 | 三个 ECC Agreement 接口 | 静态/临时密钥、双方 ID、64–512 位派生密钥、一次性协商句柄 |
| RSA | 密钥生成、内外部运算、公钥导出、IPK/EPK/ISK | 1024–2048 位、索引/权限/缓冲区校验 |
| 对称密钥 | KEK 生成/导入、DestroyKey | SM4-ECB 包装、不透明会话句柄、跨会话和重复销毁拒绝 |
| 对称加解密 | 单包、Init/Update/Final、ExternalKey | SM4 ECB/CBC/CFB/OFB/CTR/XTS；ECB/CBC 无填充；XTS 双密钥和密文窃取 |
| MAC/HMAC | MAC 单包/流式、HMAC 流式、ExternalKeyHMACInit | SM4 CBC-MAC；标准 `SGD_SM3_HMAC`/`SGD_SHA256_HMAC`；兼容以基础杂凑标识选择 HMAC；会话密钥或外部密钥 |
| 可鉴别加解密 | AuthEnc/AuthDec 单包及流式 | SM4-GCM/CCM；AAD、Nonce/IV、标签和总长度；篡改标签返回 `SDR_VERIFYERR` |
| 用户文件 | Create/Read/Write/Delete | 持久化、偏移读写、名称/大小/边界校验 |
| 附录 C VPN | IKE、EPK_IKE、IPSEC、EPK_IPSEC、SSL、EPK_SSL | HMAC PRF；普通接口返回会话密钥句柄，EPK 接口以 `SM2_3` 公钥包装；Salt 和 IV 情况 |

## 尚未实现

仅附录 B 的 SM9 接口未实现。为保持 ABI 兼容仍导出相关符号，调用返回 `SDR_NOTSUPPORT`，不会伪造成功。

## 密钥持久化和完整性

- SM2/RSA 签名密钥与加密密钥独立，索引范围 1–1024。
- 私钥访问控制码允许为空；私钥始终以 SM4-CTR 加密持久化。
- SM2/RSA 和 SM4 对称密钥记录连同算法、类型、索引及元数据使用 HMAC-SM3 完整性保护。
- HMAC 密钥来自初始化自动生成且不可经 Web 修改或导出的设备完整性密钥。
- 改索引会重新保护记录；校验失败的记录不能参与密码运算。

## 当前验证

已完成全量构建和共享库导出检查，并通过设备/会话、随机数、4096 字节摘要单包、SM2 `ZA` 标准向量、SM2 外部运算、SM4 ECB/CBC/XTS、流式 CBC、CBC-MAC、HMAC-SM3、GCM/CCM 单包和流式及篡改标签错误分支。六个附录 C 接口均已执行；EPK 输出已使用对应 SM2 私钥成功解封装。

算法标识按 GM/T 0006-2023 固定：`SGD_SM2=0x00020100`、签名
`SGD_SM2_1=0x00020200`、密钥交换 `SGD_SM2_2=0x00020400`、加密
`SGD_SM2_3=0x00020800`、`SGD_SM4_XTS=0x01000400`。公共头文件包含
编译期断言，基础回归同时检查设备返回的标准杂凑与 HMAC 能力字段。

ECC 密钥协商依赖安全管理员预置并授权内部 SM2 加密密钥。实现已通过构建和接口状态审查，正式发布前仍建议在隔离卷中补充双方权威标准向量。

## 已知边界

- 附录 C 当前采用项目实现的 HMAC PRF 配置；尚未取得 GM/T 0022/0024 权威向量验证，不能宣称通过 VPN 标准检测。
- 规范 JSON 有少量 OCR 名称错误；实现和导出以函数描述及公开 `sdf.h` 为准。
- TCP 18081 和 Web 18080 默认无 TLS/双向认证，只应部署在受控网络。
- 软件数据卷和宿主机管理员属于安全边界，不具备硬件防拆能力。

## 授权

原创代码和修改采用 GNU AGPL v3.0 only（`AGPL-3.0-only`）；SDFX、openHiTLS 原始材料保留各自许可证，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
