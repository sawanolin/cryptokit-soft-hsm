# CryptoKit SoftHSM

Docker Hub 短描述（可直接粘贴，少于 100 字符）：

> GM/T 0018-2023 SDF 软件密码设备模拟器，内置 Web 管理与 Windows x64 SDK

CryptoKit SoftHSM 是一套基于 SDFX 和 openHiTLS 的软件密码设备模拟器。
单个镜像同时运行：

- `sdfxd` SDF TCP 服务；
- openHiTLS 密码运算库；
- Web 管理后端和前端；
- supervisord 进程管理与健康检查。

> 用于学习、开发、教学、接口调试和密码应用测试。它不是经过商用密码
> 检测认证的硬件服务器密码机，不应直接用于生产密钥托管或合规场景。

## 快速启动

镜像仓库为 `sawanolin/cryptokit-soft-hsm`：

```bash
docker pull sawanolin/cryptokit-soft-hsm:1.1.4

docker run -d \
  --name cryptokit-soft-hsm \
  -p 0.0.0.0:18081:18081 \
  -p 0.0.0.0:18080:18080 \
  -v cryptokit-sdfx-data:/var/lib/sdfx \
  --restart unless-stopped \
  --security-opt no-new-privileges:true \
  sawanolin/cryptokit-soft-hsm:1.1.4
```

打开：

```text
http://ip:18080
```

首次进入只创建超级管理员、设备信息和设备完整性密钥，不生成业务密钥。超级管理员再创建系统、安全、审计管理员，业务密钥由安全管理员配置。镜像没有默认管理员密码。每个账户首次创建时由 SDF 接口生成一次固定 8 字节随机盐值，修改口令和后续登录均复用该盐值；浏览器提交 `SM3(UTF8(口令) || 盐值)`，服务端只保存盐值和哈希。

## Docker Compose

```yaml
services:
  softhsm:
    image: sawanolin/cryptokit-soft-hsm:1.1.4
    ports:
      - "0.0.0.0:18081:18081"
      - "0.0.0.0:18080:18080"
    volumes:
      - sdfx-data:/var/lib/sdfx
    restart: unless-stopped
    stop_grace_period: 15s
    security_opt:
      - no-new-privileges:true

volumes:
  sdfx-data:
```

启动：

```bash
docker compose up -d
docker compose ps
```

## 标签与平台


| 标签     | 含义                           |
| -------- | ------------------------------ |
| `1.1.4`  | 固定版本，部署时推荐           |
| `latest` | 最新稳定版本，可能随新版本移动 |

当前已经实际构建和验证的平台为：

```text
linux/amd64
```

在发布者明确提供并测试其他架构标签前，不应假定支持 `linux/arm64`。

## 端口和数据卷


| 容器资源        | 用途                                            |
| --------------- | ----------------------------------------------- |
| `18081/tcp`     | SDF SDK TCP 通道                                |
| `18080/tcp`     | Web 管理端                                      |
| `/var/lib/sdfx` | 设备、账号、密钥、对称密钥、用户文件、Web 状态、审计和备份 |

业务 TCP 通道当前没有 TLS 或双向认证，Web 管理端默认也是 HTTP；不要直接暴露到公网。

## 主要功能

- GM/T 0018-2023 风格的设备、会话和设备信息接口；
- openHiTLS 标准 SM3/SHA-256、SDFX 扩展 SHA 摘要及 SM2 消息签名 ZA 预处理；
- SM2/RSA 外部运算和持久化内部签名/加密密钥；
- 会话级私钥访问权限；
- SM2/RSA 和对称密钥（SDF KEK）会话密钥封装；
- SM4 ECB/CBC/CFB/OFB/CTR/XTS、GCM/CCM、CBC-MAC 与 HMAC-SM3；
- 单包和流式对称、MAC/HMAC、可鉴别加解密及外部密钥扩展；
- SM2 ECC 密钥协商；
- 附录 C IKE、IPSEC、SSL 普通和 EPK 包装接口；
- SDF 用户文件；
- Web 四角色权限、设备、SM2/RSA/对称密钥、会话和审计管理；
- Web 支持为管理员绑定 SM2 用户签名证书与 CA 信任锚，通过 Windows UKey Agent 完成一次性挑战响应登录，并可按账户选择“用户名+口令”或“用户名+口令+UKey”；
- Web 服务管理展示地址、端口、启动时间、运行时长和请求数，系统管理员可真正启停或重启容器内 `sdfxd`；
- Web 随机数、SM3、SM4、SM2、RSA 在线自检；
- 审计日志支持时间段、级别、类型、结果、管理员、操作、来源、请求号、路径和关键字组合筛选，可按字段导出 TXT、CSV 或 JSONL；SDF 调用失败记录为 `ERROR / sdf`；
- 备份、恢复、上传、下载和完全重置。

1.1.4 的公开算法标识按 GM/T 0006-2023 对齐：SM2 签名、密钥交换、加密
分别为 `0x00020200`、`0x00020400`、`0x00020800`，SM4-XTS 为
`0x01000400`。SHA-1/224/384/512 教学扩展使用 `SDFX_*` 自定义标识，
不再占用非标准的 `2/3/5/6`。

当前仅 SM9 接口未实现并明确返回 `SDR_NOTSUPPORT`。附录 C VPN 派生尚未
使用 GM/T 0022/0024 权威向量认证，不能据此宣称通过标准检测。

## Web 角色和密钥保护

- 超级管理员：首次初始化与管理员管理；
- 系统管理员：设备、会话、服务进程和备份恢复；启停密码服务不会停止 Web 或删除数据卷；
- 安全管理员：密码自检及 SM2/RSA/对称密钥；
- 审计管理员：日志配置、查询和 TXT 导出。

UKey 登录所需的 Windows 单文件 Agent 不运行在 Linux 容器中，可从登录页或
对应版本的 GitHub Release 下载到登录电脑。Agent 固定监听 `127.0.0.1:18088`，
可加载 32 位或 64 位厂商 SKF DLL。管理页先校验用户名和服务器口令，再打开
Agent 提供的小型本地浏览器窗口输入 PIN。PIN 不进入管理页或 Docker 服务端；
服务端只接收一次性挑战签名和签名证书，并完成证书链、有效期、用途、指纹和
SM2 验签。未检测到 Agent 时，页面会提示启动、重新检测或下载插件。不要把
Agent 改为监听 `0.0.0.0`。

SM2/RSA 签名与加密密钥索引独立，可以在 Web 中修改。私钥访问控制码可以留空；留空表示应用调用时不要求口令，不表示私钥明文保存。所有持久化非对称密钥及 SM4 对称密钥记录连同索引均使用 HMAC-SM3 完整性保护，并提供显式校验；HMAC 密钥来自首次初始化自动生成且不可通过 Web 修改或导出的设备完整性密钥。旧版 16 字节对称密钥文件会在首次读取时自动迁移为受保护记录。

## 健康检查与日志

镜像健康检查验证 Web `/api/health`。该接口同时报告 Supervisor 管理的
`sdfxd` 实际状态；系统管理员主动停止密码服务时，Web 与容器仍保持
`healthy`，页面会明确显示“密码服务已停止”。这使管理员能继续从 Web
重新启动服务：

```bash
docker inspect \
  --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
  cryptokit-soft-hsm

docker logs --tail 100 cryptokit-soft-hsm
```

健康状态应变为：

```text
healthy
```

运行日志包含时间、级别、模块、进程/线程、请求来源、SDF 命令号、会话号、返回码和耗时，不记录密码、密钥或请求载荷。Web 审计可导出 UTF-8 TXT。

## 数据管理

命名卷会保留管理员账号、固定 8 字节盐值和 SM3 哈希。重建容器时重新挂载同一个卷会继续使用上次账号。仅需重新创建 Web 账号时，可备份并删除容器内 `/var/lib/sdfx/web/state.json` 后重启；需要连同全部密码机数据一起创建全新设备时才应改用新的空卷。

停止或更新容器不会删除命名卷：

```bash
docker stop cryptokit-soft-hsm
docker rm cryptokit-soft-hsm
```

重新创建容器并挂载同一个 `cryptokit-sdfx-data` 卷即可恢复设备状态。

删除该卷会永久清除设备数据：

```bash
docker volume rm cryptokit-sdfx-data
```

执行前应先通过 Web 创建并下载备份。备份包会进行路径、条目类型、
校验和和大小检查，但未额外做整包口令加密，应保存在受控或加密存储。

## 更新版本

建议固定版本标签，并在更新前备份：

```bash
docker pull sawanolin/cryptokit-soft-hsm:1.1.4
docker stop cryptokit-soft-hsm
docker rm cryptokit-soft-hsm
```

然后使用相同的端口和数据卷重新执行启动命令。不要把生产部署只绑定到
会移动的 `latest` 标签。

## Windows x64 SDK

Windows 客户端通过 `sdfapi_x64.dll` 调用 18081 TCP 服务。GitHub Release 提供最小化 SDK 包，包含：

- 唯一的运行时 DLL `sdfapi_x64.dll`；
- 分别供 MSVC 和 MinGW 使用的导入库；
- `sdf.h`、`sdf_types.h`、`sdf_err.h` 三个公开头文件；
- 唯一的 `sdfapi.ini` 配置模板；
- SHA-256 校验和及必须保留的许可证文件。

线程运行库已静态链接。测试程序、OBJ、示例源码、构建元数据和重复配置不进入 SDK ZIP。请从对应版本的 GitHub Release 下载：

```text
https://github.com/sawanolin/cryptokit-soft-hsm/releases
```

## 安全说明

- 不要在环境变量、Compose 文件或镜像层中写入管理员口令；
- 管理令牌在每次容器启动时随机生成，不进入镜像或持久卷；
- 对称密钥、内部私钥和会话密钥不通过管理 API 返回明文；
- Web 端应置于 HTTPS 反向代理之后；
- 18081 端口应限制在本机或可信网络；
- 本镜像不具备硬件防拆、认证边界或商用密码产品认证。

## 源码、文档与许可证

源码：

```text
https://github.com/sawanolin/cryptokit-soft-hsm
```

完整 API 实现矩阵、Windows SDK、Web 管理说明、构建方法和第三方声明均
在源码仓库中。CryptoKit SoftHSM 原创代码与修改采用 GNU AGPL v3.0 only
（`AGPL-3.0-only`）。修改镜像并通过网络提供服务时，必须向用户提供对应
源码；Web 侧栏含固定的源码和许可证入口。SDFX/openHiTLS 原始材料继续
适用其 Mulan PSL v2 等既有许可证。源码仓库、Docker 镜像和 Windows SDK
均随附 LICENSE、NOTICE、上游许可证和第三方声明。
