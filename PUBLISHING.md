# GitHub 与 Docker Hub 完整发布指南

本指南用于发布当前项目：

1. GitHub：<https://github.com/sawanolin/cryptokit-soft-hsm>
2. Docker Hub：<https://hub.docker.com/r/sawanolin/cryptokit-soft-hsm>

示例发布版本为 `1.0.0`，Git 标签为 `v1.0.0`。版权声明使用
`Copyright (C) 2026 sawanolin and CryptoKit SoftHSM contributors.`。

## 一、发布前必须处理的事项

### 1. 核对已经准备好的授权文件

项目原创代码与修改采用 GNU Affero General Public License v3.0 only
（SPDX：`AGPL-3.0-only`），并提供：

```text
LICENSE
NOTICE
THIRD_PARTY_NOTICES.md
sdfx/LICENSE
openhitls/LICENSE
openhitls/Third_Party_Open_Source_Software_Notice
```

顶层 `LICENSE` 是完整且未经修改的 GNU AGPL v3.0 正文。通用版权声明仅
适用于本项目原创文件和修改，不主张 SDFX、openHiTLS 或标准材料的版权。
不得删除上游源文件中的 Mulan PSL v2 版权头，也不得删除上游许可证副本。

AGPL 要求源码和对象代码分发满足相应源码提供条件；修改版本通过网络向
用户提供服务时，还必须依第 13 条显著提供该版本的对应源码。Web 管理端
已经提供以下固定源码入口：

```text
https://github.com/sawanolin/cryptokit-soft-hsm
```

发布镜像时应确保该仓库中存在与镜像标签对应的提交/标签，并把准确标签和
镜像 digest 互相记录。SDFX 和 openHiTLS 原始材料继续适用其 Mulan PSL v2
等既有许可证，Docker 镜像和 Windows SDK 必须同时携带这些上游声明。

许可证是法律文件。本指南不能代替针对代码来源、修改版权归属和发布地区的
专业法律审查。

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
  -t cryptokit-soft-hsm:1.0.0 .
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
  cryptokit-soft-hsm:1.0.0
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

该测试必须覆盖四角色权限、SM2/RSA 空口令、签名/加密不同索引、改索引、HMAC-SM3 校验、RSA 自检、对称密钥、备份、审计配置和 TXT 导出。

验证 Windows SDK：

```powershell
& '.\dist\sdfapi-windows-x64\verify_exports.ps1'
& '.\dist\sdfapi-windows-x64\bin\basic_test.exe'
& '.\dist\sdfapi-windows-x64\bin\rsa_test.exe'
```

`verify_exports.ps1` 需要当前 `PATH` 中存在 Visual Studio 的 `dumpbin` 或
MinGW 的 `objdump`。

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
Copy-Item dist\sdfapi-windows-x64\bin\libwinpthread-1.dll build\release-tests
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
docker image inspect cryptokit-soft-hsm:1.0.0 `
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
git config user.name 'sawanolin'
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
gh repo create sawanolin/cryptokit-soft-hsm `
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
  https://github.com/sawanolin/cryptokit-soft-hsm.git
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

## 六、创建 GitHub v1.0.0 Release

### 1. 打包 Windows SDK

```powershell
New-Item -ItemType Directory -Force -Path release | Out-Null

Compress-Archive `
  -Path '.\dist\sdfapi-windows-x64\*' `
  -DestinationPath '.\release\sdfapi-windows-x64-1.0.0.zip' `
  -Force

Get-FileHash -Algorithm SHA256 `
  '.\release\sdfapi-windows-x64-1.0.0.zip'
```

把输出的 SHA-256 记录到 Release Notes。

### 2. 创建带注释标签

```powershell
git tag -a v1.0.0 -m 'CryptoKit SoftHSM 1.0.0'
git push origin v1.0.0
```

### 3. 创建 Release

使用 GitHub CLI：

```powershell
gh release create v1.0.0 `
  '.\release\sdfapi-windows-x64-1.0.0.zip' `
  --title 'CryptoKit SoftHSM 1.0.0' `
  --generate-notes
```

也可以在 GitHub 的 Releases 页面选择 `v1.0.0`，填写说明并上传 ZIP。
GitHub Release 自动附带该标签对应源码的 ZIP 和 tar.gz。

Release Notes 至少说明：

- 这是首个公开版本；
- 支持并已测试 `linux/amd64`；
- Linux CTest、Web E2E 和 Windows 实连测试结果；
- 实现的 SM2/RSA/SM3/SM4/对称密钥/文件接口；
- 四角色 RBAC、空口令、索引完整性保护和 TXT 审计；
- 未实现接口会返回 `SDR_NOTSUPPORT`；
- TCP/HTTP、备份加密和认证资质边界；
- Windows SDK ZIP 的 SHA-256。

## 七、创建 Docker Hub 仓库

1. 登录 Docker Hub；
2. 进入 **My Hub → Repositories → Create repository**；
3. Namespace 选择你的用户或组织；
4. Repository Name 输入 `cryptokit-soft-hsm`；
5. Visibility 选择 Public；
6. Short description 粘贴 `DOCKERHUB_README.md` 顶部提供的短描述；
7. 创建前再次检查名称。Docker Hub 仓库创建后不能直接重命名。

创建完成后，把 [DOCKERHUB_README.md](DOCKERHUB_README.md) 的主体粘贴到
Repository Overview；其中的仓库地址已经填写为 `sawanolin/cryptokit-soft-hsm`。

## 八、登录、标记并推送 Docker 镜像

### 1. 创建 Docker Hub PAT

在 Docker Hub 的 Account settings → Personal access tokens 创建带
Read/Write 权限、具有合理过期时间的令牌。复制后放入密码管理器，不要
写进脚本、README、命令参数或 Git。

交互式登录：

```powershell
docker login --username sawanolin
```

在 Password 提示处粘贴 PAT，不要使用 `--password` 明文参数。

### 2. 从发布提交重新构建

确保当前提交就是 `v1.0.0`：

```powershell
git status --short
git rev-parse HEAD
git rev-list -n 1 v1.0.0
```

后两个提交 ID 应一致。然后构建两个标签：

```powershell
docker build --pull --platform linux/amd64 `
  -t sawanolin/cryptokit-soft-hsm:1.0.0 `
  -t sawanolin/cryptokit-soft-hsm:latest .
```

### 3. 推送固定版本和 latest

```powershell
docker push sawanolin/cryptokit-soft-hsm:1.0.0
docker push sawanolin/cryptokit-soft-hsm:latest
```

只让 `latest` 指向已经通过全部门禁的稳定版本。不要只发布 `latest`。

### 4. 记录仓库摘要

```powershell
docker buildx imagetools inspect `
  sawanolin/cryptokit-soft-hsm:1.0.0
```

把 Docker Hub 返回的 `sha256:` digest 记录到 GitHub Release Notes。
这个仓库摘要不同于本地 Docker image ID，应以推送后的 registry digest
为准。

## 九、从 Docker Hub 做最终验收

使用一个没有本地同名标签的环境最好。至少执行：

```powershell
docker pull sawanolin/cryptokit-soft-hsm:1.0.0

docker run -d `
  --name cryptokit-hub-test `
  -p 0.0.0.0:18081:18081 `
  -p 0.0.0.0:18080:18080 `
  -v cryptokit-hub-test-data:/var/lib/sdfx `
  sawanolin/cryptokit-soft-hsm:1.0.0
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
| `v1.0.0`     | `:1.0.0`   | `CryptoKit SoftHSM 1.0.0` |
| 最新稳定标签 | `:latest`  | 最新非预发布 Release      |

## 十一、以后发布新版本

以 `1.1.0` 为例：

1. 更新版本号、`api-matrix.md` 和变更说明；
2. 从干净数据卷完成 Linux、Web 和 Windows 全部测试；
3. 提交并创建 `v1.1.0` 标签；
4. 创建 GitHub Release 和 Windows SDK ZIP；
5. 从同一标签构建 `:1.1.0`；
6. 推送 `:1.1.0`；
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

- [GNU：GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0.html)
- [GNU：如何为自己的软件使用 GNU 许可证](https://www.gnu.org/licenses/gpl-howto.html)
- [SPDX：AGPL-3.0-only](https://spdx.org/licenses/AGPL-3.0-only.html)

- [GitHub：添加本地代码到 GitHub](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github)
- [GitHub：关于大文件](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)
- [GitHub：关于 Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)
- [GitHub：移除敏感数据](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [Docker Hub：创建仓库](https://docs.docker.com/docker-hub/repos/create/)
- [Docker Hub：推送镜像](https://docs.docker.com/docker-hub/repos/manage/hub-images/push/)
- [Docker：Personal access tokens](https://docs.docker.com/security/access-tokens/)
- [Docker：docker login](https://docs.docker.com/reference/cli/docker/login/)
