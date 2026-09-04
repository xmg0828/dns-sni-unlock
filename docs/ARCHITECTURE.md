# Architecture

## Components

DNS SNI Unlock coordinates existing Linux components rather than implementing a proxy itself:

1. **dnsmasq** answers configured domains with a selected proxy IPv4 and forwards other DNS queries upstream.
2. **SNIProxy** listens on TCP 80/443, reads HTTP Host or TLS SNI, and connects to the corresponding origin.
3. **iptables** limits UDP/TCP 53 and TCP 80/443 to explicitly allowed IPv4 addresses or CIDRs.
4. **systemd** starts services and reapplies the isolated firewall chain after reboot.

## Managed files

| Path | Purpose |
| --- | --- |
| `/etc/dns-sni-unlock/services.conf` | Route source of truth |
| `/etc/dns-sni-unlock/whitelist.conf` | Authorized client IPv4/CIDR list |
| `/etc/dnsmasq.d/90-dns-sni-unlock.conf` | Generated dnsmasq rules |
| `/etc/sniproxy.conf` | Generated SNIProxy configuration |
| `/etc/systemd/system/dns-sni-unlock-firewall.service` | Firewall persistence |
| `/usr/local/sbin/dns-sni-unlock` | Installed CLI |
| `/var/lib/dns-sni-unlock/backups/` | Original unmanaged files taken over by the project |

`services.conf` and `whitelist.conf` are user-owned inputs. Generated files must not be edited directly.

## Configuration flow

```text
services.conf ─┐
               ├─ validate ─> normalized route set ─┬─> dnsmasq snippet
whitelist.conf ┘                                    ├─> SNIProxy table
                                                    └─> isolated iptables chain
```

Rendering is deterministic and atomic. Invalid input stops the operation before a managed file is replaced.

## Firewall invariants

The project owns one chain: `DNS_SNI_UNLOCK_IN`.

- A single jump is inserted at the beginning of `INPUT`.
- Authorized sources may reach UDP 53 and TCP 53/80/443.
- Other sources are dropped only for those four protocol/port combinations.
- All other traffic returns to the host's existing INPUT policy.
- Removing the project deletes only its jump and dedicated chain.

The script never changes global chain policies and never flushes or deletes global chains.

## Threat model

The primary risks are accidental open-resolver/open-proxy deployment, command/config injection, and damage to an existing host firewall. v3 mitigates these through mandatory allowlisting, constrained parsers, no catch-all SNI route, and project-scoped firewall changes.

The design does not protect against a malicious authorized client, a compromised root account, vulnerabilities in dependencies, or policy enforcement by third-party services.

## Testability

`DSU_ROOT` redirects every managed absolute path beneath a temporary directory. `DSU_TEST_MODE=1` suppresses package, systemd, and firewall side effects while retaining real parsing, rendering, route management, installation, and uninstallation behavior. This supports unprivileged CI without mocking core logic.
