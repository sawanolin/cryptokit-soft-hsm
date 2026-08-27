# CryptoKit SoftHSM Windows x64 SDF SDK

该 SDK 通过 TCP `服务器IP:18081` 调用 Docker 中的 `sdfxd`。客户端 DLL 不链接 openHiTLS，随机数和密码运算都在 Linux 服务端执行。

## 最小化包内容

```text
bin/sdfapi_x64.dll              唯一需要随应用部署的 SDK DLL
lib/sdfapi_x64.lib              MSVC x64 导入库
lib/sdfapi_x64.dll.a            MinGW x64 导入库
include/sdf.h                   SDF 公开接口
include/sdf_types.h             公开类型定义
include/sdf_err.h               公开错误码
config/sdfapi.ini               唯一配置模板
licenses/                       必须保留的许可证与第三方声明
SHA256SUMS                      包内文件校验和
```

SDK 不再包含 `libwinpthread-1.dll`：线程运行库已经静态链接进 `sdfapi_x64.dll`。包内也不包含测试 EXE、OBJ、示例源码、CMake/pkg-config 文件或重复 INI。测试源码仍保留在仓库 `tests/` 中，供发布前验证使用。

## 配置

将 `config/sdfapi.ini` 复制到应用程序的工作目录，命名为 `sdfapi.ini`：

```ini
[transport]
tcp_host = 192.168.1.20
tcp_port = 18081

[client]
connect_timeout = 3000
request_timeout = 10000
retry_count = 2
```

`tcp_host` 必须是密码机服务器的实际地址；`0.0.0.0` 只能用于服务端监听，不能作为客户端目标。若程序和 Docker 位于同一台 Windows 主机，可使用 `127.0.0.1`。

发行包只保留 `config/sdfapi.ini` 这一份模板。DLL 会优先读取应用工作目录中的 `sdfapi.ini`，也会检查其 `config/sdfapi.ini`；复制动作由使用方部署时完成，不在 SDK ZIP 内放置第二份配置。

## MSVC 使用

```bat
cl /nologo /W4 /utf-8 /Iinclude your_program.c ^
  /link /LIBPATH:lib sdfapi_x64.lib /OUT:your_program.exe
```

把 `bin\sdfapi_x64.dll` 放到程序旁，并按上一节准备 `sdfapi.ini`。MinGW 使用 `lib/sdfapi_x64.dll.a`；不使用的导入库可以不复制到最终应用目录。

## 已实现能力

- 设备、会话、设备信息和随机数；
- 标准 SM3/SHA-256、SDFX 扩展 SHA-1/224/384/512 分段摘要及 SM2 ZA 消息预处理；
- SM4 ECB/CBC/CFB/OFB/CTR/XTS、GCM/CCM、CBC-MAC 与 HMAC-SM3；
- 单包/流式对称、认证、MAC/HMAC 和外部密钥扩展；
- SM2 ECC 密钥协商和附录 C IKE/IPSEC/SSL 接口；
- SM2 外部运算、内部签名、内部公钥和 IPK/EPK/ISK；
- RSA 1024–2048 位密钥生成、内外部公私钥运算和 IPK/EPK/ISK；
- 对称包装密钥（标准接口名称保留 KEK）；
- 用户文件接口。

私钥访问控制码允许长度为 0。服务端对持久化 SM2/RSA 非对称密钥和 SM4 对称密钥记录及其索引统一执行 HMAC-SM3 完整性校验。当前仅 SM9 声明返回 `SDR_NOTSUPPORT`。

SDK 算法标识遵循 GM/T 0006-2023。SM2 签名、密钥交换、加密分别使用
`0x00020200`、`0x00020400`、`0x00020800`，SM4-XTS 使用 `0x01000400`。
SHA-1/224/384/512 是 `SDFX_*` 教学扩展，使用标准预留的自定义杂凑标识范围；
旧 `SGD_SHA*` 拼写仅作为源码兼容别名。

## 发布验证

在仓库根目录执行：

```powershell
.\scripts\build_windows_sdk.ps1
.\scripts\package_windows_sdk.ps1 -Version 1.1.4 -Force
```

检查脚本会核对 `sdf.h` 声明的全部 `SDF_*` 导出，并确认 DLL 不依赖 `libwinpthread-1.dll`。打包脚本只按白名单复制上述最小文件，生成 `release/sdfapi-windows-x64-版本.zip` 和新的 `SHA256SUMS`。

## 安全提示

- TCP 18081 当前没有内置 TLS 或双向认证，只应连接可信网络中的服务器；
- 不要把私钥口令写入源码、配置文件、镜像或命令历史；
- 客户端句柄是服务端不透明对象，不能跨会话或进程复用；
- SDK 用于开发和联调，不代表硬件密码机认证。

## 许可证

CryptoKit SoftHSM 原创代码与修改采用 GNU AGPL v3.0 only（`AGPL-3.0-only`），对应源码位于 <https://github.com/sawanolin/cryptokit-soft-hsm>。重新分发 SDK 时必须同时保留 `licenses/` 目录；SDFX、openHiTLS 等上游材料仍适用其原许可证。
