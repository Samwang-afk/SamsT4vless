# VLESS REALITY 单文件客户端设计

## 目标

在现有 3x-ui 上新增一个独立的 VLESS 用户和 TCP/REALITY 入站，并生成一个可分享的 Windows x64 单文件客户端。用户双击后通过一个按钮连接或断开全局 TUN，同时显示本机本小时和本月的总流量。

## 服务端

- 协议：VLESS。
- 传输：TCP，`xtls-rprx-vision`。
- 安全：REALITY。
- 监听端口：443。
- REALITY 目标与 SNI：微软旗下 `www.bing.com:443`。当前 Xray 版本对 `microsoft.com` 的 REALITY 握手已实测失败。
- 生成独立 UUID、X25519 密钥和 short ID；不改动现有 8388 服务。
- 通过 3x-ui 官方 API 创建，以便后续在面板管理用户和流量。

## 客户端

- 复用现有极简 GUI 风格，仅提供连接/断开按钮、状态和流量显示。
- 内嵌固定节点配置与 Mihomo Windows x64 核心；首次运行解压核心到当前用户临时目录。
- 点击连接时请求 UAC，启动 Mihomo TUN；关闭或断开时停止子进程，由 Mihomo 恢复路由和 DNS。
- 不嵌入 3x-ui 管理凭据，不访问服务端管理 API。
- 固定一个节点，不提供服务器编辑、订阅、多用户或规则编辑。

## 流量统计

- 从本机 Mihomo 控制接口读取上下行字节计数。
- 将增量累计到 `%LOCALAPPDATA%\SS-RS\traffic.json`。
- 按本地时间维护当前小时和当前自然月两个计数；跨小时或跨月自动归零相应周期。
- 异常退出最多丢失最后一次轮询后的少量统计，不影响代理连接。

## 验收

- 3x-ui 显示新入站和用户，Xray 配置校验通过且 443 正在监听。
- 使用生成的 VLESS 链接可通过 REALITY 连接，出口 IP 为服务器 IP。
- 单个 EXE 在 Windows x64 双击运行，连接按钮可启动全局 TUN，断开后网络恢复。
- UI 的本小时和本月统计随代理流量增加，重启程序后本月统计保留。
- 原 `ss-server`、8388 入站和 Clash Verge 配置保持不变。
