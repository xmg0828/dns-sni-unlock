# Security Policy

## Supported versions

| Version | Security updates |
| --- | --- |
| 3.x | Yes |
| 2.x and earlier | No |

v2 及更早版本可能清空全局 iptables 规则并生成开放的 SNI 兜底路由，请升级到 v3。

## Reporting a vulnerability

请通过 GitHub 的 **Private vulnerability reporting** 功能提交安全问题：

1. 打开仓库的 **Security** 页面。
2. 选择 **Report a vulnerability**。
3. 提供影响版本、复现条件、风险和建议修复。

请勿在公开 Issue 中披露可利用细节或真实服务器凭据。维护者应在 7 天内确认报告，并在确认影响后协调修复和披露时间。

## Security boundaries

本项目：

- 不终止或解密 TLS；SNIProxy 依据 HTTP Host 进行 HTTP listener 路由，并依据 TLS ClientHello SNI 路由 TLS 流量。
- 不提供身份系统；访问控制依赖 IPv4/CIDR 防火墙白名单。
- 不防御已进入白名单的恶意客户端。
- 不验证目标第三方服务是否允许代理访问。
- 不保证 dnsmasq/SNIProxy/iptables 自身不存在漏洞。

## Deployment requirements

- 只允许可信客户端或可信网段访问 53/80/443。
- 不要将 `0.0.0.0/0` 加入白名单。
- 定期安装操作系统安全更新。
- 使用云防火墙作为第二层访问控制。
- 不要在 Issue、日志或配置示例中提交真实公网白名单和基础设施凭据。
- 修改规则后运行 `dns-sni-unlock doctor` 并从授权及未授权来源分别测试。

## Out of scope

以下内容不属于漏洞：

- 第三方服务更改地域策略、域名或风控规则。
- 因错误白名单、云防火墙或上游 DNS 配置造成的不可用。
- 在不受支持系统上的兼容性问题（欢迎作为普通 Issue 报告）。
