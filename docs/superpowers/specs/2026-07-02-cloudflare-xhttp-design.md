# Cloudflare XHTTP 入站设计

## 目标

为 `cdn.samstoolbox.asia` 新增独立的 VLESS + XHTTP + TLS 入站，通过 Cloudflare CDN 连接 VPS。保留现有 443 VLESS REALITY 入站，不清除旧服务。完成后将 Windows 单文件客户端切换到新入站。

## 前置条件

- `cdn.samstoolbox.asia` 的 DNS 已全球解析并启用 Cloudflare 代理（橙云）。
- Cloudflare SSL/TLS 模式为 Full (strict)。
- 域名使用固定的 VPS 源站 `23.27.52.126`。
- 若公开 CA 的 HTTP-01 签发失败，不降低 TLS 校验；届时改用 Cloudflare Origin Certificate 或 DNS-01。

## 服务端

- 在 3x-ui 新增入站，不直接修改数据库。
- 协议为 VLESS，传输为 XHTTP，TLS 终止在源站，监听 Cloudflare 支持的 HTTPS 端口 `8443`。
- SNI、证书域名和 XHTTP Host 均为 `cdn.samstoolbox.asia`。
- 使用随机、不可猜测的 XHTTP Path；模式为 `auto`，仅启用基础 padding，不依赖自定义请求头。
- 创建一个独立 UUID 用户，不复用现有 REALITY 用户。
- 证书和私钥仅保存在服务端，私钥权限限制为 root 可读。
- 保持现有 443 REALITY、8388 ss-server、3x-ui 和防火墙规则不变；仅开放并验证 8443 所需路径。

## 客户端

- Windows 客户端连接 `cdn.samstoolbox.asia:8443`，使用新 UUID、XHTTP Path、TLS SNI。
- Mihomo 节点使用 `network: xhttp`、`tls: true` 和与服务端一致的 XHTTP 参数。
- 继续复用现有单 EXE 的启动、Wintun 和界面逻辑；不增加协议选择页或额外配置系统。
- 新客户端验证成功前保留当前可执行文件，构建产物采用新文件名，避免覆盖可回退版本。

## 数据流

`Windows 客户端 -> Cloudflare:8443 -> VPS:8443 / XHTTP Path -> Xray 出站 -> 目标网站`

Cloudflare 负责边缘 TLS 接入并以 Full (strict) 校验源站证书。源站只接受有效 VLESS/XHTTP 会话；未知路径或无效身份不进入代理链路。

## 失败处理

- DNS 尚未传播或未经过 Cloudflare：停止部署，不修改现有入站。
- 证书签发或严格校验失败：保留旧服务并报告具体阻塞，不临时关闭证书校验。
- 8443 入站启动失败：删除本次新增入站，现有 443 保持可用。
- 客户端端到端验证失败：不替换现有发布版 EXE。

## 验收

1. 公共 DNS 返回 Cloudflare 地址，访问响应显示经过 Cloudflare。
2. 3x-ui/Xray 配置校验通过，服务端监听 8443，重启后仍存在。
3. 使用新节点完成实际代理请求，出口 IP 为 VPS 公网 IP。
4. 清空其他代理变量后，Windows 单文件客户端可连接并访问网站。
5. 现有 443 REALITY 和 8388 服务仍正常运行。

## 不包含

- 不迁移或删除现有 443 入站。
- 不配置多域名、负载均衡、自动协议回退或自定义 HTTP 头伪装。
- 不把 `microsoft.com` 用作证书或 SNI；CDN 模式必须使用自有域名。
