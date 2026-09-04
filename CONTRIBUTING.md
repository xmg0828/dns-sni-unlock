# Contributing

感谢你帮助改进 DNS SNI Unlock。

## 开始之前

- 对安全问题，请按 [`SECURITY.md`](SECURITY.md) 私下报告。
- 功能请求请描述实际使用场景，不要只提交模糊的“支持更多平台”。
- 项目只接受用于授权网络管理的功能，不接受绕过访问控制、隐藏滥用来源或构建开放代理的改动。

## 本地开发

依赖：

- Bash 3.2+
- Python 3（仅用于严格校验 IPv4/CIDR）
- ShellCheck 0.9+

运行检查：

```bash
shellcheck -x dns-sni-unlock.sh tests/test.sh
./tests/test.sh
```

测试使用 `DSU_ROOT` 和 `DSU_TEST_MODE=1` 写入临时目录，不要求 root，也不会修改真实防火墙。

## 提交 Pull Request

1. 从 `main` 创建主题分支。
2. 为行为变化先增加失败测试。
3. 实现最小修复并运行完整测试。
4. 更新 README 或 CHANGELOG（如行为对用户可见）。
5. 提交清晰的 PR 描述，包括风险和回滚方式。

提交信息建议采用 Conventional Commits：

```text
fix: preserve unrelated firewall rules
feat: add CIDR allowlist validation
docs: document v2 migration
```

## 代码约定

- 使用 `set -Eeuo pipefail`。
- 所有变量引用都加双引号。
- 不允许清空全局防火墙链或修改默认策略。
- 不允许 `curl | bash` 安装方式。
- 所有配置写入必须原子化。
- 输入必须在进入文件名、命令或配置模板前校验。
- 新增函数和命令必须有自动化测试。

## 兼容性报告

请包含：

- 发行版及版本
- Bash、dnsmasq、SNIProxy、iptables 版本
- `dns-sni-unlock doctor` 输出
- 已脱敏的 `services.conf` 与 `whitelist.conf`
- 复现步骤和预期行为
