# GitHub 与 Docker Hub 完整发布指南

本指南用于把当前项目发布为：

1. GitHub 源码仓库：`cryptokit-soft-hsm`
2. Docker Hub 镜像仓库：`cryptokit-soft-hsm`

当前发布版本为 `1.1.4`，Git 标签为 `v1.1.4`。开始前统一核对：


| 占位符                    | 替换内容                                       |
| ------------------------- | ---------------------------------------------- |
| `YOUR_GITHUB_USERNAME`    | GitHub 用户名或组织名                          |
| `YOUR_DOCKERHUB_USERNAME` | Docker Hub 用户名或组织命名空间                |
| `YOUR_NAME`               | 可选：用真实版权人替换通用的 contributors 声明 |

## 一、发布前必须处理的事项

### 1. 核对已经准备好的授权文件

项目原创代码和修改采用 GNU AGPL v3.0 only；SDFX、openHiTLS 原始材料继续适用各自既有许可证。仓库提供：

```text
LICENSE
NOTICE
THIRD_PARTY_NOTICES.md
sdfx/LICENSE
openhitls/LICENSE
openhitls/Third_Party_Open_Source_Software_Notice
```

通用版权声明为 `Copyright (c) 2026 CryptoKit SoftHSM contributors`，只适用
于本项目原创文件和修改，不主张上游组件版权。如果你希望登记真实个人或
组织名称，在发布前统一替换 `NOTICE` 和 `THIRD_PARTY_NOTICES.md` 中的
contributors 声明。不要删除上游源文件中的原版权头。

通过网络提供修改版服务时，AGPL 第 13 条要求向用户提供对应源码。分发源码、Docker 镜像或 Windows SDK 时，还必须保留 SDFX/openHiTLS 的许可证、版权和第三方声明；顶层 AGPL 不会替换上游许可证。

许可证是法律文件。本指南不能代替针对代码来源和发布地区的专业法律审查。

### 2. 确认标准材料的再分发权

仓库包含：

```text
GMT 0018-2023 密码设备应用接口规范.json
```

在没有确认该文件的版权和再分发授权前，不要上传到公开仓库。该文件已加入顶层 `.gitignore`。不能确认时保持忽略状态，只保留由你独立编写的接口实现矩阵和说明。

### 3. 保留 openHiTLS 第三方声明

不要删除：

```text
openhitls/LICENSE
openhitls/Third_Party_Open_Source_Software_Notice
openhitls/SECURITY.md
```

如果以后把 openHiTLS 改为 Git submodule，应记录构建验证过的准确提交。

### 4. 区分测试私钥与真实秘密

openHiTLS 上游测试数据包含 PEM 私钥测试夹具。它们不是本项目的生产
密钥，但可能触发扫描提醒。确认这些文件与上游公开源码一致，并在第三方
说明中标注其测试用途。

任何真实管理员口令、Docker Hub PAT、GitHub Token、备份包、运行时
`admin.token`、设备数据卷或你自己生成的私钥都不得进入 Git。

## 二、清理和检查本地目录

在 PowerShell 中进入项目根目录：

```powershell
Set-Location 'D:\dptui\mm (1)\SDF'
```

本仓库已经提供顶层 `.gitignore`。确认以下内容不会被提交：

- `build/` 和所有 CMake/Ninja 中间文件；
- Python 缓存、虚拟环境和测试缓存；
- IDE 用户配置；
- `.env`、令牌、口令文件和本地配置覆盖；
- `.sdfxbak`、运行时数据和 Docker 数据卷导出；
- 临时日志、崩溃转储和覆盖率文件。

检查大文件：

```powershell
Get-ChildItem -File -Recurse |
  Where-Object Length -ge 50MB |
  Select-Object FullName, Length
```

GitHub 对普通 Git 文件超过 50 MiB 会警告，并阻止超过 100 MiB 的文件。
大型二进制交付物应使用 GitHub Release；本项目 Windows SDK 包很小，
仍建议同时作为 Release 资产提供。

检查常见秘密：

```powershell
rg -n -i --hidden `
  --glob '!openhitls/testcode/testdata/**' `
  --glob '!build/**' `
  '(dckr_pat_|github_pat_|ghp_|BEGIN OPENSSH PRIVATE KEY|password\s*[=:]|token\s*[=:])' .
```

如果发现真实秘密，先撤销或轮换，再清理文件和 Git 历史。不要只删除
工作区里的那一行就继续发布。

## 三、发布前重新验证

### 1. 从头重建本地容器

> **容器不是初始化数据边界，数据卷才是。** 删除并重新 `docker run`，如果仍挂载 `cryptokit-sdfx-data:/var/lib/sdfx`，新容器会继续读取旧卷中的管理员账号、密码摘要、设备完整性密钥和业务密钥。这不是镜像把测试口令打包进去。

管理员账户只存放在卷内 `/var/lib/sdfx/web/state.json`。记录中的每个账户仅包含
首次创建时通过 `SDF_GenerateRandom(8)` 生成且以后不再更换的固定盐值和
`SM3(UTF8(口令) || 盐值)` 哈希。仅需重新创建 Web 用户名和口令而保留密码机
密钥时，先备份再删除这个文件即可，无需删除整个卷：

```powershell
docker cp cryptokit-soft-hsm:/var/lib/sdfx/web/state.json .\state.json.backup
docker exec cryptokit-soft-hsm rm -f /var/lib/sdfx/web/state.json
docker restart cryptokit-soft-hsm
```

再次打开 Web 后会进入初始化页。`manager.db`、设备完整性密钥和业务密钥不会因
上述操作被删除。命令中的容器名若已修改，应替换为实际名称。

旧版 PBKDF2 账户摘要不能反推出本版所需的固定盐值 SM3 值，因此本次升级不做
账户口令自动迁移。保留原数据卷升级时，应按上面的方式备份并删除
`/var/lib/sdfx/web/state.json`，再从 Web 初始化页重建管理员；不要删除整个卷。

发布验收建议保留日常卷，并在下文“启动隔离测试容器”步骤中使用明确的新卷 `cryptokit-release-test-data`。开始前只读核对日常资源，不要删除：

```powershell
docker ps -a --filter 'name=^/cryptokit-soft-hsm$'
docker volume inspect cryptokit-sdfx-data
```

如果确实要销毁日常设备重新初始化，应先备份并再次核对卷名，然后显式删除 `cryptokit-sdfx-data`。此操作不可恢复，不能把它混入普通的容器更新流程。
先进入项目根目录并核对 Compose 展开后的配置：

```powershell
cd 'D:\dptui\mm (1)\SDF'
docker compose config
```

停止并删除旧容器和旧网络。这个命令保留命名数据卷，不会删除现有设备、
密钥、用户文件和 Web 状态：

```powershell
docker compose down --remove-orphans
```

如果本次需要模拟一台完全全新的密码机，可以改用下面的命令。它会永久
删除 Compose 数据卷和其中的全部设备数据，只能在确认不需要恢复时执行：

```powershell
docker compose down --volumes --remove-orphans
```

不使用旧构建缓存，从基础镜像开始重新构建：

```powershell
docker build --pull --platform linux/amd64 `
  --no-cache `
  -t cryptokit-soft-hsm:1.1.4 .
```

使用刚构建的镜像强制创建新容器：

```powershell
docker compose up -d --force-recreate --no-build
```

检查容器状态、健康状态和启动日志：

```powershell
docker compose ps
docker compose logs --tail 200

$containerId = docker compose ps -q softhsm
docker inspect `
  --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' `
  $containerId
```

在 Docker 主机上验证端口和 Web 健康接口：

```powershell
Test-NetConnection 127.0.0.1 -Port 18081
Invoke-RestMethod http://127.0.0.1:18080/api/health
```

发布前还应使用系统管理员登录“服务管理”，依次验证“重启服务”“停止服务”
和“启动服务”。停止 `sdfxd` 后 Web 18080 及 `/api/health` 应保持可访问，
健康响应中的 `daemon.running` 为 `false`；再次启动后应恢复为 `true` 且
`daemon.daemon_available` 为 `true`。启停会断开现有 SDF 会话，验证时不要
并行运行 SDK 测试。

再从可信网络中的另一台机器把 `SERVER_IP` 换成 Docker 主机真实 IP，验证
两个对外监听：

```powershell
Test-NetConnection SERVER_IP -Port 18081
Invoke-RestMethod http://SERVER_IP:18080/api/health
```

远程访问失败时，检查主机防火墙是否允许可信来源访问 TCP 18080 和
18081。不要把这两个未启用 TLS 的端口直接开放到公网。

完成 Compose 验证后停止容器但保留数据卷，以释放端口给隔离测试：

```powershell
docker compose down
```

### 2. 启动隔离测试容器

```powershell
docker volume create cryptokit-release-test-data

docker run -d `
  --name cryptokit-release-test `
  -p 127.0.0.1:18081:18081 `
  -p 127.0.0.1:18080:18080 `
  -v cryptokit-release-test-data:/var/lib/sdfx `
  --security-opt no-new-privileges:true `
  cryptokit-soft-hsm:1.1.4
```

等待健康：

```powershell
$deadline = (Get-Date).AddSeconds(60)
do {
  $health = docker inspect `
    --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' `
    cryptokit-release-test
  if ($health -eq 'healthy') { break }
  Start-Sleep -Seconds 2
} while ((Get-Date) -lt $deadline)

if ($health -ne 'healthy') {
  docker logs --tail 200 cryptokit-release-test
  throw "Release container is not healthy."
}
```

### 3. 执行端到端测试

在绑定到 `127.0.0.1:18080` 的全新测试卷上执行综合测试：

```powershell
python tests\rbac_integrity_e2e.py --base-url http://127.0.0.1:18080
```

该测试必须覆盖四角色权限、SM2/RSA 空口令、签名/加密不同索引、改索引、非对称/对称密钥 HMAC-SM3 校验、RSA 自检、对称密钥、备份、审计配置和 TXT 导出。

还应在构建产物中运行 `test_basic`、`test_hash`、`test_sm2` 和
`test_0018_extended`。`test_basic` 会检查 GM/T 0006-2023 算法标识和设备
能力字段；扩展测试覆盖流式 SM4、标准 HMAC-SM3/HMAC-SHA256 向量、
GCM/CCM、XTS 和六个附录 C 接口。ECC 协商及内部密钥测试需要安全管理员
在隔离卷中预置对应内部密钥。

验证 Windows SDK 的导出和运行依赖：

```powershell
& '.\scripts\verify_windows_sdk.ps1'
```

检查脚本需要 Visual Studio 的 `dumpbin` 或 MinGW 的 `objdump`；除核对 `sdf.h` 声明的导出外，还会拒绝仍依赖 `libwinpthread-1.dll` 的 DLL。测试程序从仓库源码临时编译到 `build/release-tests`，不放入 SDK 包。

在“x64 Native Tools Command Prompt for VS”中编译并运行仓库级 Windows
联调程序。前面的综合测试会建立其所需的无口令密钥：SM2 加密索引 7，
RSA 签名索引 8、加密索引 4。

```powershell
New-Item -ItemType Directory -Force build\release-tests | Out-Null

cl /nologo /W4 /utf-8 `
  /I dist\sdfapi-windows-x64\include `
  tests\test1.c `
  /link /LIBPATH:dist\sdfapi-windows-x64\lib sdfapi_x64.lib `
  /OUT:build\release-tests\test1.exe

cl /nologo /W4 /utf-8 `
  /I dist\sdfapi-windows-x64\include `
  tests\rsa_e2e.c `
  /link /LIBPATH:dist\sdfapi-windows-x64\lib sdfapi_x64.lib `
  /OUT:build\release-tests\rsa_e2e.exe

Copy-Item dist\sdfapi-windows-x64\bin\sdfapi_x64.dll build\release-tests
Copy-Item dist\sdfapi-windows-x64\config\sdfapi.ini build\release-tests\sdfapi.ini

$env:SDF_TEST_KEY_INDEX = '7'
Push-Location build\release-tests
try {
  & '.\test1.exe'
  & '.\rsa_e2e.exe'
} finally {
  Pop-Location
}
```

运行前确认 `build\release-tests\sdfapi.ini` 中的服务器地址是实际可达地址；
客户端不能把服务端监听地址 `0.0.0.0` 当作连接目标。

如需额外运行 `reset_e2e.py`，必须把 `--base-url` 指向隔离测试容器并最后执行，因为它会清除测试设备状态。

确认镜像平台：

```powershell
docker image inspect cryptokit-soft-hsm:1.1.4 `
  --format '{{.Os}}/{{.Architecture}}'
```

首发版本应输出：

```text
linux/amd64
```

### 4. 清理隔离测试资源

确认名称无误后：

```powershell
docker rm -f cryptokit-release-test
docker volume rm cryptokit-release-test-data
```

只清理本项目在反复构建中产生的悬空镜像。先显示目标，确认后再逐个删除；
项目通过 OCI title 标签与其他镜像区分：

```powershell
$danglingImageIds = @(
  docker image ls `
    --filter dangling=true `
    --filter 'label=org.opencontainers.image.title=CryptoKit SoftHSM' `
    --quiet
)

if ($danglingImageIds.Count -gt 0) {
  docker image inspect $danglingImageIds `
    --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.title"}}'

  foreach ($imageId in $danglingImageIds) {
    docker image rm $imageId
  }
}
```

不要使用不带过滤条件的 `docker image prune -a`，它可能删除其他项目仍需
复用的镜像和构建缓存。

## 四、初始化 Git 仓库

确认当前目录是项目根目录后：

```powershell
git init -b main
git config user.name 'YOUR_NAME'
git config user.email '你的 GitHub 已验证邮箱或 noreply 邮箱'
```

暂存前先查看将要提交的内容：

```powershell
git status --short
git add .
git status --short
git diff --cached --stat
git diff --cached
```

特别确认以下内容未被暂存：

```text
build/
真实 .env
管理员口令
GitHub/Docker Hub Token
*.sdfxbak
运行时设备数据
```

完成首个提交：

```powershell
git commit -m 'Initial open-source release'
```

## 五、创建 GitHub 仓库并上传

### 方法 A：GitHub CLI

安装并登录 GitHub CLI：

```powershell
gh auth login
```

创建公开仓库、添加 `origin` 并推送：

```powershell
gh repo create YOUR_GITHUB_USERNAME/cryptokit-soft-hsm `
  --public `
  --source . `
  --remote origin `
  --push
```

### 方法 B：GitHub 网页加 Git

1. 在 GitHub 创建 `cryptokit-soft-hsm`；
2. 选择 Public；
3. 不要让 GitHub 自动创建 README、LICENSE 或 `.gitignore`，避免与本地
   首次提交冲突；
4. 复制仓库 HTTPS 或 SSH 地址。

然后执行：

```powershell
git remote add origin `
  https://github.com/YOUR_GITHUB_USERNAME/cryptokit-soft-hsm.git
git remote -v
git push -u origin main
```

推送后在 GitHub 网页检查：

- README 正常渲染；
- `api-matrix.md` 和 `WEB-MANAGEMENT.md` 链接可打开；
- LICENSE 和第三方声明存在；
- 没有 Build、数据卷、备份或秘密；
- 仓库 About 区填写描述、网站和 Topics。

推荐 Topics：

```text
gm-t-0018
sdf
sm2
sm3
sm4
openhitls
soft-hsm
docker
cryptography
windows-sdk
```

## 六、创建 GitHub v1.1.4 Release

### 1. 打包最小化 Windows SDK

从仓库根目录重新构建 Windows SDK，再执行白名单打包。构建脚本使用 MSYS2 UCRT64，关闭 daemon、tests 和 examples，生成主 DLL、MinGW 导入库和 MSVC 可链接的 `.lib`：

```powershell
.\scripts\build_windows_sdk.ps1
.\scripts\package_windows_sdk.ps1 -Version 1.1.4 -Force
```

`build_windows_sdk.ps1` 会验证 94 个公开导出及 DLL 依赖并更新 `dist`；`package_windows_sdk.ps1` 只复制主 DLL、MSVC/MinGW 导入库、3 个公开头文件、1 份配置模板、许可证和 README，并重新生成包内 `SHA256SUMS`。测试 EXE、OBJ、示例源码、CMake/pkg-config 文件、内部头文件以及重复 INI 均不会进入 ZIP。输出为：

```text
release/sdfapi-windows-x64-1.1.4.zip
```

1.1.4 在保留 GM/T 0006-2023 算法标识修正的基础上增加账户级两种登录方式、
本地浏览器 PIN 桥接窗口和登录页 Agent 下载。发布时必须同时重建 Docker 镜像、
Windows SDK 和 UKey Agent，不能把旧版 `sdfapi_x64.dll`、旧 `sdf_types.h` 或
旧 Agent 与新版服务端混用。打包前确认公共头文件中 SM2 签名/协商/加密分别为
`0x00020200/0x00020400/0x00020800`，SM4-XTS 为 `0x01000400`，并确认
`dist` 头文件与 `sdfx/include/sdf_types.h` 的 SHA-256 完全一致。

脚本最后会输出 ZIP 的 SHA-256，把该值记录到 Release Notes。

### 2. 构建单文件 Windows UKey Agent

UKey Agent 是本仓库的一部分，但不进入 Linux Docker 镜像。发布机需安装
Visual Studio 2022“使用 C++ 的桌面开发”，然后从项目根目录执行：

```powershell
.\ukey-agent\build.ps1 -Configuration Release

New-Item -ItemType Directory -Force -Path '.\release' | Out-Null
Copy-Item -LiteralPath '.\ukey-agent\dist\ukey-agent.exe' `
  -Destination '.\release\ukey-agent-windows-x64-1.1.4.exe' -Force
Get-FileHash -Algorithm SHA256 `
  '.\release\ukey-agent-windows-x64-1.1.4.exe'
```

这个单一 EXE 内嵌 x86/x64 helper、浏览器调用脚本、PIN 桥接页和 logo，可调用 32 位或
64 位厂商 SKF DLL。发布前在一台 Windows 测试机上配置厂商 DLL，至少验证：

- 健康检查 `http://127.0.0.1:18088/v1/health`；
- PIN 桥接页 `http://127.0.0.1:18088/bridge/pin`；
- 自动或指定设备、应用和容器；
- 查看并导出签名/加密证书；
- Web 绑定用户证书与 CA 证书；
- 一次完整的 UKey 挑战登录；
- 逐一验证“用户名+口令”“用户名+口令+UKey”两种账户模式，确认组合
  模式不能绕过服务器口令或 UKey 因子；
- `tests/ukey_auth_integration.py` 中证书匹配、摘要一致、证书链验签和 UKey 签名验签均为 `true`。
- `tests/ukey_login_modes_e2e.py` 输出的两个登录模式结果均为 `true`。

验收时从登录页下载 Agent，确认未启动时出现“启动、重新检测或下载”对话框；
启动后确认主页面弹出小型本地 PIN 窗口，完成签名后自动返回管理页。分别使用
HTTP 和 HTTPS 管理入口验证同一流程；不得把 Agent 改为监听 `0.0.0.0`。

真实设备测试脚本只在显式设置 `UKEY_TEST_PIN` 和 `UKEY_CERT_DIR` 时运行。
其中证书目录应包含 `ukey-sign-certificate.cer` 与 `root-ca.cer`。测试结束后
立即从当前 PowerShell 会话删除这两个环境变量；不要把 PIN、厂商 DLL 或证书
的本机绝对路径写进脚本、文档或提交记录。

厂商 SKF DLL 和测试 PIN 不得放入源码、Release 附件、Docker 构建上下文或
日志。Release 只上传 `ukey-agent-windows-x64-1.1.4.exe`，并记录 SHA-256。

### 3. 创建带注释标签

```powershell
git tag -a v1.1.4 -m 'CryptoKit SoftHSM 1.1.4'
git push origin v1.1.4
```

### 4. 创建 Release

使用 GitHub CLI：

```powershell
gh release create v1.1.4 `
  '.\release\sdfapi-windows-x64-1.1.4.zip' `
  '.\release\ukey-agent-windows-x64-1.1.4.exe' `
  --title 'CryptoKit SoftHSM 1.1.4' `
  --generate-notes
```

也可以在 GitHub 的 Releases 页面选择 `v1.1.4`，填写说明并上传 SDK ZIP 和 UKey Agent EXE。
GitHub Release 自动附带该标签对应源码的 ZIP 和 tar.gz。

Release Notes 至少说明：

- 这是首个公开版本；
- 支持并已测试 `linux/amd64`；
- Linux CTest、Web E2E 和 Windows 实连测试结果；
- 除 SM9 外已实现的 GM/T 0018 接口，包括 SM2 ZA 预处理、ECC 协商、流式 SM4/MAC/HMAC、GCM/CCM/XTS、外部密钥扩展和附录 C；
- 四角色 RBAC、空口令、非对称/对称密钥索引完整性保护和 TXT 审计；
- SM9 接口保留导出并返回 `SDR_NOTSUPPORT`；
- TCP/HTTP、备份加密和认证资质边界；
- Windows SDK ZIP 的 SHA-256。
- UKey Agent EXE 的 SHA-256，以及 32/64 位厂商 SKF DLL 兼容和真实 UKey 登录测试结果。

## 七、创建 Docker Hub 仓库

1. 登录 Docker Hub；
2. 进入 **My Hub → Repositories → Create repository**；
3. Namespace 选择你的用户或组织；
4. Repository Name 输入 `cryptokit-soft-hsm`；
5. Visibility 选择 Public；
6. Short description 粘贴 `DOCKERHUB_README.md` 顶部提供的短描述；
7. 创建前再次检查名称。Docker Hub 仓库创建后不能直接重命名。

创建完成后，把 [DOCKERHUB_README.md](DOCKERHUB_README.md) 的主体粘贴到
Repository Overview，并将两个用户名占位符替换为真实值。

## 八、登录、标记并推送 Docker 镜像

### 1. 创建 Docker Hub PAT

在 Docker Hub 的 Account settings → Personal access tokens 创建带
Read/Write 权限、具有合理过期时间的令牌。复制后放入密码管理器，不要
写进脚本、README、命令参数或 Git。

交互式登录：

```powershell
docker login --username YOUR_DOCKERHUB_USERNAME
```

在 Password 提示处粘贴 PAT，不要使用 `--password` 明文参数。

### 2. 从发布提交重新构建

确保当前提交就是 `v1.1.4`：

```powershell
git status --short
git rev-parse HEAD
git rev-list -n 1 v1.1.4
```

后两个提交 ID 应一致。然后构建两个标签：

```powershell
docker build --platform linux/amd64 `
  -t sawanolin/cryptokit-soft-hsm:1.1.4 `
  -t sawanolin/cryptokit-soft-hsm:latest .
```

### 3. 推送固定版本和 latest

```powershell
docker push sawanolin/cryptokit-soft-hsm:1.1.4
docker push sawanolin/cryptokit-soft-hsm:latest
```

只让 `latest` 指向已经通过全部门禁的稳定版本。不要只发布 `latest`。

### 4. 记录仓库摘要

```powershell
docker buildx imagetools inspect `
  sawanolin/cryptokit-soft-hsm:1.1.4
```

把 Docker Hub 返回的 `sha256:` digest 记录到 GitHub Release Notes。
这个仓库摘要不同于本地 Docker image ID，应以推送后的 registry digest
为准。

## 九、从 Docker Hub 做最终验收

使用一个没有本地同名标签的环境最好。至少执行：

```powershell
docker pull YOUR_DOCKERHUB_USERNAME/cryptokit-soft-hsm:1.1.4

docker run -d `
  --name cryptokit-hub-test `
  -p 0.0.0.0:18081:18081 `
  -p 0.0.0.0:18080:18080 `
  -v cryptokit-hub-test-data:/var/lib/sdfx `
  YOUR_DOCKERHUB_USERNAME/cryptokit-soft-hsm:1.1.4
```

检查健康和 Web：

```powershell
docker inspect `
  --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' `
  cryptokit-hub-test

Invoke-RestMethod http://ip:18080/api/health
```

验收完成后清理这两个准确目标：

```powershell
docker rm -f cryptokit-hub-test
docker volume rm cryptokit-hub-test-data
```

## 十、让两个仓库互相链接

GitHub：

- About → Website 填 Docker Hub 仓库地址；
- README 的 Docker Hub 命令改成真实命名空间；
- Release Notes 写入镜像地址和 digest。

Docker Hub：

- Overview 填 GitHub 源码、Release 和 API 矩阵链接；
- Repository information 的 Source repository 指向 GitHub；
- 每个标签说明对应 Git 标签。

建议建立一一对应关系：


| Git          | Docker Hub | GitHub Release            |
| ------------ | ---------- | ------------------------- |
| `v1.1.4`     | `:1.1.4`   | `CryptoKit SoftHSM 1.1.4` |
| 最新稳定标签 | `:latest`  | 最新非预发布 Release      |

## 十一、以后发布新版本

以 `1.1.4` 为例：

1. 更新版本号、`api-matrix.md` 和变更说明；
2. 从干净数据卷完成 Linux、Web 和 Windows 全部测试；
3. 提交并创建 `v1.1.4` 标签；
4. 创建 GitHub Release 和 Windows SDK ZIP；
5. 从同一标签构建 `:1.1.4`；
6. 推送 `:1.1.4`；
7. 最终验收通过后再更新 `:latest`；
8. 在 Release Notes 记录 registry digest；
9. 不覆盖或删除已经发布的固定版本标签。

## 十二、凭据泄漏或错误发布

如果 Token、口令或私钥已经推送：

1. 立即撤销或轮换凭据；
2. 暂停继续发布；
3. 使用 `git-filter-repo` 清理完整历史；
4. 协调所有克隆和分支，防止旧提交重新污染；
5. 必要时联系 GitHub Support 清理缓存引用；
6. 删除受影响镜像标签，重新构建并发布；
7. 发布安全说明，但不要公开仍可利用的秘密。

不要认为删除文件后再提交一次就完成了清理，旧秘密仍存在于 Git 历史。

## 官方参考

- [GitHub：添加本地代码到 GitHub](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github)
- [GitHub：关于大文件](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)
- [GitHub：关于 Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)
- [GitHub：移除敏感数据](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [Docker Hub：创建仓库](https://docs.docker.com/docker-hub/repos/create/)
- [Docker Hub：推送镜像](https://docs.docker.com/docker-hub/repos/manage/hub-images/push/)
- [Docker：Personal access tokens](https://docs.docker.com/security/access-tokens/)
- [Docker：docker login](https://docs.docker.com/reference/cli/docker/login/)
