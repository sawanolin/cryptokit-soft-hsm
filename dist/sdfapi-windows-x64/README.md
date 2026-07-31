# CryptoKit SoftHSM Windows x64 SDF SDK

该 SDK 通过 TCP `服务器IP:18081` 调用 Docker 中的 `sdfxd`。客户端 DLL 不链接 openHiTLS，随机数和密码运算都在 Linux 服务端执行。

## 包内容

```text
bin/sdfapi_x64.dll              SDF 客户端 DLL
bin/libwinpthread-1.dll         MinGW 运行依赖
lib/sdfapi_x64.lib              MSVC x64 COFF 导入库
lib/sdfapi_x64.dll.a            MinGW x64 导入库
include/sdf.h                   GM/T 0018 风格公开头文件
config/sdfapi.ini               TCP 客户端配置模板
examples/                       C 示例
verify_exports.ps1              DLL 导出检查
SHA256SUMS                      包内文件校验和
licenses/                       许可证与第三方声明
```

## 配置

将 `config/sdfapi.ini` 复制到应用当前工作目录，命名为 `sdfapi.ini`：

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

DLL 会优先读取当前目录的 `sdfapi.ini`，也会检查 `config/sdfapi.ini`。应用发布时应把配置、`sdfapi_x64.dll` 和 `libwinpthread-1.dll` 放在可找到的位置。

## MSVC 使用

在 “x64 Native Tools Command Prompt for Visual Studio” 中：

```bat
cl /nologo /W4 /utf-8 /Iinclude examples\basic_test.c ^
  /link /LIBPATH:lib sdfapi_x64.lib /OUT:bin\basic_test.exe
```

也可以运行 `build_examples.bat` 重建全部示例。包内已附带 MinGW x64 构建的示例，包括基础连接、随机数、SM2/SM3/SM4、文件和 2048 位 RSA 外部私钥/公钥回环。

## 已实现能力

- 设备、会话、设备信息和随机数；
- SM3 分段摘要；
- SM4 ECB/CBC/CFB/OFB/CTR 与 CBC-MAC；
- SM2 外部运算、内部签名、内部公钥和 IPK/EPK/ISK；
- RSA 1024–2048 位密钥生成、内外部公私钥运算和 IPK/EPK/ISK；
- 对称包装密钥（标准接口名称保留 KEK）；
- 用户文件接口。

私钥访问控制码允许长度为 0。空口令密钥不要求调用 `SDF_GetPrivateKeyAccessRight`，但服务端私钥仍为加密保存。设置了口令的内部密钥必须先取得会话级访问权。签名与加密密钥索引可以不同，应以 Web 安全管理员配置的实际索引为准。服务端对持久化 SM2/RSA 非对称密钥和 SM4 对称密钥记录及其索引统一执行 HMAC-SM3 完整性校验，受损记录不会用于密码运算。

未实现的公开声明明确返回 `SDR_NOTSUPPORT`，不会伪造成功。

## 验证

```powershell
.\verify_exports.ps1
Get-FileHash -Algorithm SHA256 .\bin\sdfapi_x64.dll
```

`verify_exports.ps1` 使用 `dumpbin` 或 `objdump` 检查 `sdf.h` 声明的全部 94 个 `SDF_*` 导出。`SHA256SUMS` 覆盖除自身外的包内文件。

仓库级回归还包括 `tests/test1.c` 的空口令 SM2 封装回环和 `tests/rsa_e2e.c` 的 RSA 内外部运算、IPK/ISK 会话密钥回环；运行前必须在隔离设备卷中由安全管理员创建测试索引。

## 安全提示

- TCP 18081 当前没有内置 TLS 或双向认证，只应连接可信网络中的服务器；
- 不要把私钥口令写入源码、配置文件、镜像或命令历史；
- 客户端句柄是服务端不透明对象，不能跨会话或进程复用；
- SDK 用于开发和联调，不代表硬件密码机认证。

## 许可证

CryptoKit SoftHSM 原创代码与修改采用 GNU AGPL v3.0 only（`AGPL-3.0-only`），对应源码位于 <https://github.com/sawanolin/cryptokit-soft-hsm>。SDK 包内 `licenses/` 目录包含完整 AGPL 正文以及 SDFX、openHiTLS 原许可证和归属声明。重新分发 DLL、导入库、头文件或示例时必须同时保留该目录；上游材料仍适用其原许可证。
