# CryptoKit UKey 插件

本目录是 CryptoKit SoftHSM 仓库的一部分，用于软件服务器密码机 Web 登录挑战响应。发布文件只有一个 `ukey-agent.exe`，不需要 Python、.NET、INI 文件或额外运行库；项目原创代码统一采用仓库根目录的 `AGPL-3.0-only` 许可证。

## 功能

- 64 位无控制台托盘主程序。
- 同时支持 32 位和 64 位厂商 SKF DLL，自动识别 DLL 位数。
- 内嵌 x86/x64 helper，厂商 DLL 崩溃不会带崩托盘主程序。
- 固定监听 `127.0.0.1:18088`，没有服务端地址配置。
- 托盘设置中选择厂商 SKF DLL，并可指定设备名、应用名和容器名。
- 设备名、应用名或容器名留空时自动选择第一个。
- 本地 PIN 桥接窗口把挑战、SM2 用户 ID 和本次输入的 PIN 传给插件完成签名。
- 同时读取签名证书和加密证书，选择后可查看 Windows 证书详情或导出 DER `.cer`。
- 使用内嵌的 `logo.png` 作为窗口和任务栏通知区域图标。
- 浏览器调用脚本由插件自身的 `/ukey-agent.js` 地址提供。

## 运行和设置

双击 `ukey-agent.exe`。程序不会出现命令行窗口，而是在任务栏通知区域显示图标。首次运行自动打开设置窗口；以后双击托盘图标，或右键选择“设置”。

设置项：

1. 点击“导入 DLL...”选择厂商 SKF DLL。
2. 插件自动显示 DLL 为 x86 或 x64。
3. 设备名称、应用名称、容器名称可以留空，也可以精确填写。
4. 插入 UKey 后可点击“检测设备”，自动填入第一个设备、应用和容器。
5. 点击“保存”。设置保存在当前 Windows 用户的注册表：

```text
HKEY_CURRENT_USER\Software\CryptoKit\UKeyAgent
```

端口固定为 `18088`，绑定地址固定为 `127.0.0.1`，不能在插件中指定远程软件服务器地址。
这里的回环地址始终属于打开网页的登录电脑，与软件服务器密码机的 IP 无关。

## 查看和导出证书

在设置窗口点击“查看证书”。插件会分别调用：

```text
SKF_ExportCertificate(hContainer, TRUE,  ...);  // 签名证书
SKF_ExportCertificate(hContainer, FALSE, ...);  // 加密证书
```

读取成功的证书显示在证书列表中。选择证书后可以：

- 查看主题、颁发者、序列号、有效期和 DER 长度；
- 点击“查看详情”打开 Windows 标准证书查看器；
- 点击“导出所选”保存为 `.cer`。

部分 UKey 容器可能只保存一种证书，插件只显示实际读取成功的项目。

## 浏览器接入

管理端支持“用户名+口令”和“用户名+口令+UKey”两种账户级登录方式。
服务器登录口令先由管理页使用账户创建时的固定 8 字节盐值计算
`SM3(UTF8(口令) || 盐值)`，Agent 只处理随后由本地 PIN 窗口提交的 UKey PIN，
不会接收服务器登录口令。
组合方式的服务器登录口令发送给管理端；通过后，主页面打开 Agent 提供的
`http://127.0.0.1:18088/bridge/pin` 小型浏览器窗口。PIN 在该同源窗口中
直接提交给 Agent，不进入管理页面、URL、`postMessage` 或服务端请求。

主页面只通过 `postMessage` 向窗口发送挑战、用户名和 SM2 ID，窗口完成签名后
只返回签名、摘要和证书。此方式不依赖管理主页面直接 `fetch` 回环地址，HTTP
和 HTTPS 管理入口采用相同流程。Agent 只监听回环地址，不应改为 `0.0.0.0`。

`/ukey-agent.js` 和直接 HTTP API 继续作为兼容及教学接口保留；软件服务器密码机
Web 登录默认使用 PIN 桥接页。

签名响应中的 `signature_base64url` 是固定 64 字节的 `r || s`，不是 ASN.1 DER；`certificate_base64` 是本次签名容器中的签名证书，用于服务端和已绑定证书做指纹匹配。签名过程为：

```text
SKF_ExportPublicKey
SKF_DigestInit(SGD_SM3, 签名公钥, SM2用户ID)
SKF_DigestUpdate(挑战原文)
SKF_DigestFinal
SKF_ECCSignData
```

浏览器也可以导出指定证书：

```javascript
const signCertificate = await UKeyAgent.exportCertificate({
  certificateType: 'sign'
});

const encryptCertificate = await UKeyAgent.exportCertificate({
  certificateType: 'encrypt'
});
```

返回字段 `certificate_base64` 是 X.509 DER 证书的标准 Base64 编码。

## HTTP 接口

| 方法 | 地址 | 功能 |
|---|---|---|
| `GET` | `/v1/health` | 插件状态、DLL 是否配置及 DLL 位数 |
| `GET` | `/bridge/pin` | 与管理端风格一致的本地 PIN 桥接窗口 |
| `GET` | `/ukey-agent.js` | 浏览器调用脚本 |
| `POST` | `/v1/sign` | SM2 挑战签名，PIN 在请求体传入 |
| `POST` | `/v1/certificate` | 导出 `sign` 或 `encrypt` 证书 |

证书请求示例：

```json
{
  "request_id": "可选请求编号",
  "certificate_type": "encrypt"
}
```

## 单文件实现方式

最终 EXE 内嵌：

- `ukey-helper-x86.exe`；
- `ukey-helper-x64.exe`；
- `ukey-agent.js`；
- `pin-bridge.html`；
- `logo.png`。

Windows 不能让 64 位进程直接加载 32 位 DLL，也不能直接从内存启动嵌入的 EXE。因此运行时会把两个 helper 静默释放到：

```text
%LOCALAPPDATA%\CryptoKit\UKeyAgent\1.1.4
```

释放的文件带隐藏属性，用户下载、复制和发布时只需要主 EXE。

## 构建

需要 Visual Studio 2022“使用 C++ 的桌面开发”组件：

```powershell
Set-Location .\ukey-agent
.\build.ps1
```

发布结果：

```text
dist\ukey-agent.exe
```

Release 构建使用静态 C/C++ 运行库，最终 EXE 采用 Windows GUI 子系统，不产生命令行窗口。
