# DNS SNI Unlock

[![CI](https://github.com/xmg0828/dns-sni-unlock/actions/workflows/ci.yml/badge.svg)](https://github.com/xmg0828/dns-sni-unlock/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-clean-brightgreen.svg)](https://www.shellcheck.net/)

一个面向 **Debian / Ubuntu** 的、默认安全的 DNS + SNIProxy 网关管理脚本。它用 dnsmasq 将你明确配置的域名解析到代理服务器，再由 SNIProxy 在不解密 TLS 的情况下根据 SNI/HTTP Host 转发流量。

> **项目定位：** 管理你自己有权使用的网络中的 DNS/SNI 路由。项目不保证任何第三方平台的地域可用性，也不应被用于绕过法律、服务条款或访问控制。

> [!WARNING]
> **上游 SNIProxy 项目已标记为弃用（deprecated）。** It has HTTP/2 routing, HTTP/3/QUIC, security, and maintenance limitations；部署或继续使用前，请先阅读上游状态说明：<https://github.com/dlundquist/sniproxy#status-deprecated>，并评估这一依赖是否仍符合你的安全与维护要求。

## 为什么重写

早期版本是一个交互式单文件脚本，会覆盖全局 dnsmasq/SNIProxy 配置，并通过清空 iptables 规则来限制访问。v3.0.0 改为可审计、可测试、可回滚的命令行工具：

- **不清空系统防火墙**，不修改 INPUT/FORWARD/OUTPUT 默认策略
- 只管理独立的 `DNS_SNI_UNLOCK_IN` 链
- 安装时强制要求客户端 IPv4/CIDR 白名单
- 不再提供匹配任意域名的 SNI 开放代理
- 只写 `/etc/dnsmasq.d/90-dns-sni-unlock.conf`
- 接管已有 `/etc/sniproxy.conf` 前自动保存原始副本
- 所有配置先校验，再生成并原子替换
- 提供非交互 CLI、诊断命令、卸载和隔离测试模式

从 v2 升级前请阅读 [`docs/MIGRATION-v2-to-v3.md`](docs/MIGRATION-v2-to-v3.md)。

## 工作原理

```text
授权客户端
    │
    ├─ DNS :53 ──> dnsmasq ──> 指定域名返回代理 IPv4
    │                         其他域名转发至上游 DNS
    │
    └─ HTTP :80 / TLS :443 ──> SNIProxy ──> 目标站点

iptables INPUT
    └─ DNS_SNI_UNLOCK_IN（只保护 53/80/443）
       ├─ 白名单来源：允许
       └─ 其他来源：丢弃
```

SNIProxy 在 HTTP 监听器上按 HTTP Host 路由，在 TLS 监听器上读取 TLS ClientHello 中的服务器名称；它不持有目标网站证书，也不解密 TLS 内容。

## 支持范围

- Debian 11/12/13
- Ubuntu 20.04/22.04/24.04
- IPv4 网关和 IPv4/CIDR 白名单
- systemd
- `iptables`（独立链）
- dnsmasq + Debian/Ubuntu 仓库提供的 SNIProxy

目前不支持：IPv6 白名单、firewalld/nftables 原生规则、非 systemd 系统、容器内一键安装。

## 安装

### 1. 克隆并审查

```bash
git clone https://github.com/xmg0828/dns-sni-unlock.git
cd dns-sni-unlock
less dns-sni-unlock.sh
```

不要直接执行未经审查的 `curl | bash`。

### 2. 安装

通过 SSH 执行时，脚本会自动把当前 SSH 客户端 IPv4 加入白名单；仍建议显式传入你的管理网络：

```bash
sudo ./dns-sni-unlock.sh install \
  --allow 203.0.113.10 \
  --proxy-ip 198.51.100.20
```

参数说明：

- `--allow`：允许访问 DNS/HTTP/HTTPS 网关的客户端 IPv4 或 CIDR，可重复
- `--proxy-ip`：dnsmasq 返回给客户端的代理服务器公网 IPv4；省略时自动探测

本地控制台安装且无法检测 SSH 来源时，必须提供至少一个 `--allow`。

### 3. 验证

```bash
sudo ./dns-sni-unlock.sh status
sudo ./dns-sni-unlock.sh doctor
```

然后在白名单客户端上测试：

```bash
dig @198.51.100.20 openai.com A
curl --connect-to openai.com:443:198.51.100.20:443 https://openai.com/
```

请把示例 IP 替换为你自己的地址。

## 配置

### 服务路由

配置文件：`/etc/dns-sni-unlock/services.conf`

格式：

```text
名称|代理IPv4|以空格分隔的域名
```

示例：

```text
Example|198.51.100.20|example.com media.example.com
```

域名只接受普通规范域名，不接受 `*`、URL、端口、Shell 字符或正则表达式。子域名规则由生成器安全地产生。同一父域名及其子域名如果指向同一个代理 IPv4，可以同时保留；如果指向不同 IPv4，校验会拒绝这种 ancestor/descendant overlap。

### 客户端白名单

配置文件：`/etc/dns-sni-unlock/whitelist.conf`

```text
127.0.0.1
203.0.113.10
203.0.113.0/24
```

每行只能写一个 IPv4 或 CIDR。

SNIProxy 上游 CLI 没有 Debian/Ubuntu 版本都可靠提供的独立配置语法检查或 dry-run 选项（支持的参数只有 `-c`、`-f`、`-n` 和 `-V`）。因此项目不伪造 `sniproxy -t` 之类的检查：安装和 `apply` 会通过 systemd 重启 SNIProxy 验证配置，失败时按事务流程回滚。

配置修改后执行：

```bash
sudo dns-sni-unlock apply
```

## 常用命令

```bash
# 状态与诊断
sudo dns-sni-unlock status
sudo dns-sni-unlock doctor

# 路由管理
sudo dns-sni-unlock service list
sudo dns-sni-unlock service add Example 198.51.100.20 example.com media.example.com
sudo dns-sni-unlock service set-ip Example 198.51.100.21
sudo dns-sni-unlock service remove Example

# 白名单管理
sudo dns-sni-unlock firewall list
sudo dns-sni-unlock firewall add 203.0.113.10
sudo dns-sni-unlock firewall remove 203.0.113.10
sudo dns-sni-unlock firewall plan

# 重新生成并应用配置
sudo dns-sni-unlock apply

# 卸载项目配置（保留 apt 安装的软件包）
sudo dns-sni-unlock uninstall --yes
```

不带参数运行会打开包含状态、诊断、路由/白名单查看和应用操作的简易菜单。

## 安全设计

- 默认拒绝非白名单来源访问 53/80/443
- 防火墙只使用项目专属链，可独立添加和移除
- 不执行 `iptables -F`、`iptables -X` 或 `iptables -P` 的全局操作
- 不生成 SNI 通配兜底规则
- 输入经过 IPv4/CIDR、域名和服务名验证
- SNIProxy 原配置仅备份一次，卸载时恢复
- 卸载不会删除 dnsmasq、SNIProxy 或其他程序的软件包

更多说明见 [`SECURITY.md`](SECURITY.md) 和 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 测试

测试不会修改宿主机 `/etc` 或防火墙；它通过临时根目录验证真实脚本行为：

```bash
./tests/test.sh
```

静态检查：

```bash
shellcheck -x dns-sni-unlock.sh tests/test.sh
```

CI 的 Push 检查只触发于 `main`；Pull Request 和手动 `workflow_dispatch` 也会运行这两项检查。

## 贡献

欢迎 Bug 报告、兼容性修复和安全改进。请先阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md)。安全问题请不要公开提交 Issue，报告方式见 [`SECURITY.md`](SECURITY.md)。

## 版本

当前版本：**3.0.0**。变更记录见 [`CHANGELOG.md`](CHANGELOG.md)。

## 许可证

[MIT](LICENSE) © xmg0828 contributors
