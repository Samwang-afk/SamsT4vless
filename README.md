# SamsT4vless

一个用于学习网络代理、异步 I/O 与 Windows TUN 的 Rust 项目。仓库包含自定义加密隧道、SOCKS5/HTTP 代理、Windows 全局 TUN 客户端，以及可嵌入 Mihomo 的桌面界面。

本仓库不提供公共节点、账号或可直接使用的服务器配置。

## 功能

- ChaCha20-Poly1305 AEAD 加密帧
- SOCKS5 与 HTTP CONNECT 代理
- Windows Wintun 全局 IPv4 路由
- VLESS + XHTTP + TLS 客户端配置
- 单文件 Windows GUI 与本小时/本月流量统计
- Linux 服务端 TUN 与 NAT 转发

## 目录

```text
crates/core    加密、帧和地址编解码
crates/client  SOCKS5、HTTP 与 Windows TUN 客户端
crates/server  TCP/TUN 服务端
crates/gui     Windows 单文件桌面客户端
```

## 构建

安装稳定版 Rust 后运行：

```powershell
cargo test --workspace
cargo build --release --workspace
```

桌面客户端在编译时读取以下环境变量，不会从仓库获得真实节点信息：

```text
VLESS_SERVER
VLESS_PORT
VLESS_UUID
VLESS_SNI
VLESS_XHTTP_PATH
```

构建 GUI 还需要官方 Mihomo Windows x64 可执行文件和官方签名的 `wintun.dll`。路径可分别通过 `SS_RS_MIHOMO_PATH` 与 `SS_RS_WINTUN_PATH` 指定，然后运行：

```powershell
.\package-client.ps1
```

## 当前限制

- TUN 服务端首版仅支持一个客户端
- 自定义 SS-RS 隧道基于 TCP，不支持 UDP 传输层
- GUI 发布流程目前仅面向 Windows x64
- 服务端部署、证书、节点凭据和防火墙策略需自行配置

## 安全说明

这是学习项目，不承诺匿名性或对抗主动检测。请勿提交密码、UUID、私钥、真实服务器地址或面板配置；分享编译后的客户端等同于分享其中嵌入的节点凭据。
