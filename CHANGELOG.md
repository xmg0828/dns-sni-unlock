# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [3.0.0] - 2026-09-03

### Added

- Non-interactive command interface for install, apply, status, diagnostics, route management, firewall management, and uninstall.
- Strict validation for service names, IPv4 addresses, CIDRs, and domains.
- Dedicated `DNS_SNI_UNLOCK_IN` firewall chain and systemd persistence unit.
- Mandatory client allowlist during installation.
- Atomic configuration generation and isolated-root test mode.
- Automated behavior tests and ShellCheck CI.
- Architecture, migration, contribution, and security documentation.

### Changed

- Limited support to Debian and Ubuntu so installation behavior is predictable and testable.
- Moved project configuration to `/etc/dns-sni-unlock/`.
- Stopped replacing `/etc/dnsmasq.conf`; v3 writes a dedicated snippet instead.
- SNI routes now match only configured domains and their subdomains.
- Uninstall restores a pre-existing SNIProxy configuration when available and preserves system packages.

### Removed

- Global `iptables -F`, `iptables -X`, and default-policy changes.
- Open catch-all SNI route.
- Automatic trust based on external IP lookup.
- Unverified CentOS/RHEL installation path.
- Destructive interactive firewall reset operations.

### Security

- Prevented arbitrary domain/config injection through strict parsing.
- Prevented accidental destruction of unrelated firewall rules.
- Prevented the default deployment from becoming a public DNS/SNI gateway.

## [2.4] - 2025-05-26

Legacy interactive installer. This release line is unsupported; see the v3 migration guide.

[Unreleased]: https://github.com/xmg0828/dns-sni-unlock/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/xmg0828/dns-sni-unlock/releases/tag/v3.0.0
[2.4]: https://github.com/xmg0828/dns-sni-unlock/commits/main
