# CryptoKit SoftHSM

[![License](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)
[![GM/T 0018](https://img.shields.io/badge/API-GM%2FT%200018--2023-0b7285.svg)](api-matrix.md)
[![Docker](https://img.shields.io/badge/Docker-linux%2Famd64-2496ed.svg?logo=docker&logoColor=white)](DOCKERHUB_README.md)
[![Windows SDK](https://img.shields.io/badge/SDK-Windows%20x64-0078d4.svg?logo=windows)](dist/sdfapi-windows-x64/README.md)

CryptoKit SoftHSM 是一套基于 SDFX 和 openHiTLS 的 GM/T 0018-2023
SDF 接口兼容软件密码设备模拟器。项目提供 Linux Docker 服务端、内置
Web 管理端，以及通过 TCP 调用服务端的 Windows x64 SDF C SDK。

> 本项目用于学习、开发、教学、接口联调和密码应用测试，不是经过商用
> 密码检测认证的硬件服务器密码机，不应直接用于生产密钥托管或合规场景。
> 演示地址 WEB：http://47.99.222.28:18080 TCP：47.99.222.28:18081
> 超级管理员：superadmin 系统管理员：sysadmin 安全管理员 secadmin 审计管理员 audadmin
> 口令均为：Aa12345678

## 主要能力

- 标准 `SDF_*` 设备、会话和设备信息接口；
- openHiTLS 随机数与 SM3 分段摘要；
- SM2 外部密钥生成、加解密、签名和验签；
- 持久化的 SM2/RSA 内部签名密钥、加密密钥及会话级私钥使用权限；
- SM2/RSA 和对称密钥（SDF KEK）会话密钥封装、导入与销毁；
- SM4 ECB、CBC、CFB、OFB、CTR 和 CBC-MAC；
- SDF 用户文件创建、偏移读写与删除；
- Web 四角色权限管理、设备信息、SM2/RSA/对称密钥生命周期、会话管理和审计；
- Web 随机数、SM3、SM4、SM2、RSA 在线密码自检；
- 经过格式校验的备份、恢复、上传、下载和完全重置；
- Windows x64 `sdfapi_x64.dll`、COFF 导入库、头文件和 C 示例。

未实现的接口不会伪造成功，而是明确返回 `SDR_NOTSUPPORT`。完整状态见
[GM/T 0018-2023 API 实现矩阵](api-matrix.md)。

## 架构

```text
Windows C/C++ 应用
        │  SDF_* API
        ▼
sdfapi_x64.dll
        │  TCP 18081
        ▼
┌───────────────────────────────────────────────┐
│ Docker: CryptoKit SoftHSM                     │
│                                               │
│  sdfxd ── openHiTLS                           │
│    │                                          │
│    ├── SDF TCP 服务 :18081                    │
│    └── 带随机令牌鉴权的私有 Web 管理命令        │
│                                               │
│  Web 管理服务 :18080                           │
│                                               │
│  持久化卷 /var/lib/sdfx                        │
└───────────────────────────────────────────────┘
```

项目不提供独立 Unix 管理接口。Web 后端复用 18081 服务发送私有管理命令，
并使用容器启动时生成、仅保存在 `/run/sdfx/admin.token` 的随机令牌鉴权。

## 快速开始

### 使用 Docker Hub 镜像

正式镜像发布在 `sawanolin/cryptokit-soft-hsm`：

```bash
docker pull sawanolin/cryptokit-soft-hsm:1.0.0

docker run -d `
  --name cryptokit-soft-hsm `
  -p 0.0.0.0:18081:18081 `
  -p 0.0.0.0:18080:18080 `
  -v cryptokit-sdfx-data:/var/lib/sdfx `
  --restart unless-stopped `
  --security-opt no-new-privileges:true `
  sawanolin/cryptokit-soft-hsm:1.0.0
```

访问 `http://服务器IP:18080`，然后完成首次初始化。

### 从源码构建

```bash
git clone https://github.com/sawanolin/cryptokit-soft-hsm.git
cd cryptokit-soft-hsm
docker compose up -d --build
```

检查状态：

```bash
docker compose ps
docker compose logs --tail 100
```

停止服务但保留设备数据：

```bash
docker compose down
```

删除数据卷会永久清除设备数据，请仅在确认后执行：

```bash
docker compose down -v
```

## 首次初始化

首次打开 Web 管理端只创建超级管理员、设备信息和不可由 Web 修改的设备完整性密钥，
不会自动生成任何业务密钥。随后由超级管理员创建系统、安全、审计管理员，
再由安全管理员生成 SM2/RSA 签名密钥、加密密钥和对称密钥。

项目没有默认管理员密码。管理员密码以 PBKDF2-SHA256 记录保存；内部私钥
使用 SM4-CTR 加密后持久化。私钥访问控制码允许留空：留空时不要求应用调用方
输入口令，私钥仍由设备密钥派生的加密密钥保护。命名数据卷会保留管理员账户、
口令摘要和全部设备状态；要创建全新设备必须使用新的空卷或明确删除旧卷。

## 端口与持久化


| 项目     |          默认值 | 用途                                                 |
| -------- | --------------: | ---------------------------------------------------- |
| SDF TCP  |      `ip:18081` | Linux/Windows SDF SDK 调用                           |
| Web 管理 |      `ip:18080` | 浏览器管理、审计和维护                               |
| 数据目录 | `/var/lib/sdfx` | 设备、密钥、对称密钥、用户文件、Web 状态、审计和备份 |

不要在没有额外保护的情况下把 18081 或 18080 直接暴露到公网。

## Windows x64 SDF SDK

预构建 SDK 位于 `dist/sdfapi-windows-x64`，也建议作为 GitHub Release
资产发布。主要文件：

```text
bin/sdfapi_x64.dll
bin/libwinpthread-1.dll
lib/sdfapi_x64.lib
include/sdf.h
config/sdfapi.ini
examples/
SHA256SUMS
```

使用步骤：

1. 启动 Docker 服务；
2. 将 `config/sdfapi.ini` 复制到应用工作目录；
3. 将 `sdfapi_x64.dll` 和 `libwinpthread-1.dll` 放在程序旁；
4. 包含 `include/sdf.h` 并链接 `lib/sdfapi_x64.lib`；
5. 使用标准 `SDF_OpenDevice`、`SDF_OpenSession` 等函数。

包内 `bin/basic_test.exe` 已完成 Windows 到 Docker 的真实连接测试。
`verify_exports.ps1` 可使用 `dumpbin` 或 `objdump` 检查公开导出函数。

## 已实现接口概览


| 分类         | 已实现                                               |
| ------------ | ---------------------------------------------------- |
| 设备与会话   | Open/Close Device、Open/Close Session、GetDeviceInfo |
| 随机数       | GenerateRandom                                       |
| SM3          | HashInit、HashUpdate、HashFinal                      |
| SM2 外部运算 | 密钥生成、加解密、签名、验签                         |
| RSA 运算     | 1024–2048 位密钥生成、内外部公私钥运算、IPK/EPK/ISK |
| 内部密钥     | SM2/RSA 公钥导出、权限获取/释放和内部密码运算        |
| 会话密钥     | SM2/RSA IPK/EPK/ISK、对称密钥包装/导入、DestroyKey   |
| SM4          | ECB、CBC、CFB、OFB、CTR、CBC-MAC                     |
| 用户文件     | Create、Read、Write、Delete                          |

目前尚未实现的主要类别包括 ECC 协商、SM4-GCM 认证加密、流式
对称运算、流式 MAC/HMAC、外部密钥扩展以及 SM9/VPN 扩展。详见
[api-matrix.md](api-matrix.md)。

## Web 管理

Web 管理端提供：

- 设备状态、活动会话和累计请求；
- 设备信息修改；
- SM2/RSA 签名与加密密钥生成、启停、删除、公钥导出、口令修改和索引修改；
- 私钥访问控制码可为空；密钥记录与索引一起用 HMAC-SM3 完整性保护，并提供校验按钮；
- 对称密钥生成、启停和删除，不提供密钥明文导出；
- SDF 会话查看和强制终止；
- 随机数、SM3、SM4、SM2、RSA 在线自检；
- 带级别、分类、请求号、来源地址和详情的管理审计，可配置保留期/显示级别并导出 TXT；
- 备份、恢复、上传、下载和完全重置。

权限边界：


| 功能                         | 超级管理员 | 系统管理员 | 安全管理员 | 审计管理员 |
| ---------------------------- | :--------: | :--------: | :--------: | :--------: |
| 系统初始化、管理员管理       |     是     |     否     |     否     |     否     |
| 系统维护、备份恢复、设备配置 | 按矩阵授权 |     是     |     否     |     否     |
| 密码服务、SM2/RSA/对称密钥   |     否     |     否     |     是     |     否     |
| 日志配置、查询和 TXT 导出    |     否     |     否     |     否     |     是     |

当前 Web 页面只显示该角色获授权的模块；服务端 API 同时强制校验角色，不能通过手工请求越权。

详细安全设计和操作说明见 [WEB-MANAGEMENT.md](WEB-MANAGEMENT.md)。

## 备份与恢复

备份由密码服务创建并在恢复前检查 tar 条目类型、路径、校验和和大小。
内部 SM2/RSA 私钥记录在备份中仍保持加密状态，但备份包本身未额外做整包
口令加密。请将下载的 `.sdfxbak` 文件保存在受控或加密存储中。

创建、恢复和完全重置要求没有活动 SDF 会话。完全重置会删除设备信息、
管理员、审计、设备完整性密钥、内部密钥、对称密钥和用户文件，但保留已有备份文件。

## 安全边界

- 业务 TCP 通道当前没有 TLS 或双向认证；
- Web 管理端默认使用 HTTP；
- 应保持端口只绑定本机，或置于受控网络和 HTTPS 反向代理之后；
- 不要在镜像、Compose 文件、源码或 Git 历史中写入管理员口令和令牌；
- 本项目没有商用密码产品认证、FIPS 认证或硬件防拆能力；
- 备份包需要额外的访问控制或存储加密。

如果发现安全问题，请不要公开提交包含密钥、口令、令牌或可利用细节的
Issue；请通过仓库维护者公布的私密安全报告渠道联系。

## 构建与测试

构建正式镜像：

```bash
docker build --pull -t cryptokit-soft-hsm:1.0.0 .
```

运行 Web 端到端测试：

```bash
python tests/rbac_integrity_e2e.py --base-url http://127.0.0.1:28080
# Windows：编译并运行 tests/rsa_e2e.c 和 tests/test1.c
# reset_e2e.py 只能对隔离测试卷运行
```

`reset_e2e.py` 会重置测试设备，只能对隔离测试卷运行。

当前发布门禁包括：

- Linux C SDK CTest：6/6；
- Web 初始化、四角色 RBAC、CSRF、SM2/RSA/对称密钥、改索引、HMAC-SM3 校验和审计；
- 随机数/SM3/SM4/SM2/RSA 自检、备份恢复与完全重置；
- Windows x64 DLL 的 94 个公开 SDF 导出；
- Windows `test1` 的 SM2 封装回环及 RSA 内外部/会话密钥封装真实连接。

## 项目结构

```text
.
├── Dockerfile
├── docker-compose.yml
├── openhitls/                  # openHiTLS 上游源码
├── sdfx/                       # SDF SDK、服务端、协议和测试
├── web/                        # Web 后端和静态前端
├── server/                     # 容器启动、健康检查和进程管理
├── tests/                      # Web/管理端到端测试
├── dist/sdfapi-windows-x64/    # Windows x64 SDK 交付包
├── api-matrix.md
└── WEB-MANAGEMENT.md
```

## 文档

- [GM/T 0018-2023 API 实现矩阵](api-matrix.md)
- [Web 管理端说明](WEB-MANAGEMENT.md)
- [Windows x64 SDK 说明](dist/sdfapi-windows-x64/README.md)
- [Docker Hub 仓库 README](DOCKERHUB_README.md)
- [GitHub 与 Docker Hub 发布指南](PUBLISHING.md)

## 贡献

欢迎提交 Issue 和 Pull Request。代码变更应：

1. 不夸大算法、接口或合规状态；
2. 对新增协议字段进行边界和长度校验；
3. 不让私钥、对称密钥或会话密钥离开服务端；
4. 为新增功能补充对应测试；
5. 保持未实现接口明确返回 `SDR_NOTSUPPORT`；
6. 保留上游项目的版权、许可证和第三方声明。

## 许可证与第三方组件

本项目原创代码和修改以 [GNU Affero General Public License v3.0 only](LICENSE)
（SPDX：`AGPL-3.0-only`）发布，版权人为 `sawanolin and CryptoKit SoftHSM contributors`。通过网络向用户提供修改版服务时，必须依 AGPL 第 13 条向
这些用户显著提供对应源码。Web 管理端侧栏已经提供
[项目源码](https://github.com/sawanolin/cryptokit-soft-hsm)和许可证入口。

SDFX、openHiTLS 原始材料仍保留 Mulan PSL v2 等既有授权和版权声明；顶层
AGPL 不会抹除或替换第三方许可证。分发时必须同时保留：

- [顶层 LICENSE](LICENSE)；
- [NOTICE](NOTICE)；
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)；
- [SDFX 原许可证](sdfx/LICENSE)；
- [openHiTLS 原许可证](openhitls/LICENSE) 和其第三方声明。

Docker 镜像和 Windows SDK 也随附上述授权材料。上游来源、修改范围、
测试密钥说明和待补充的精确提交信息见第三方声明。

## 致谢

- [openHiTLS](https://gitcode.com/openHiTLS/openHiTLS)
- SDFX 原始项目及贡献者
- GM/T 0018-2023 密码设备应用接口规范

=======

# cryptokit-soft-hsm

>>>>>>> b333fba904ad83a8060f9b740b1cf0a6b8b60533
>>>>>>>
>>>>>>
>>>>>
>>>>
>>>
>>
