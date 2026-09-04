# Migrating from v2 to v3

v3 is a security-focused rewrite. Do not upgrade blindly on a remote production server.

## Important behavior changes

- CentOS/RHEL installation is no longer claimed or automated.
- Configuration moved from `/root/*.conf` to `/etc/dns-sni-unlock/`.
- v3 no longer overwrites `/etc/dnsmasq.conf`.
- v3 no longer clears global iptables rules or changes default policies.
- v3 requires a client allowlist and does not generate a catch-all SNI route.
- Service configuration uses `name|IPv4|domains` instead of colon-separated fields.

## Before migration

From a console or a second SSH session:

```bash
sudo cp -a /etc/dnsmasq.conf /root/dnsmasq.conf.pre-dsu-v3
sudo cp -a /etc/sniproxy.conf /root/sniproxy.conf.pre-dsu-v3
sudo iptables-save | sudo tee /root/iptables.pre-dsu-v3.rules >/dev/null
sudo cp -a /root/dns_unlock_services.conf /root/dns_unlock_services.conf.pre-dsu-v3 2>/dev/null || true
sudo cp -a /root/firewall_whitelist_ips.txt /root/firewall_whitelist_ips.txt.pre-dsu-v3 2>/dev/null || true
```

Ensure your current management IPv4 or CIDR is known. The project firewall does not affect SSH, but a correct allowlist is required to use DNS and proxy ports.

## Recommended migration

1. Stop the v2-managed services during a maintenance window.
2. Restore the host firewall from your known-good ruleset, removing rules created by v2.
3. Clone and inspect the v3 source.
4. Install with an explicit proxy IP and allowlist.
5. Recreate only the domain routes you actually need.
6. Test from an authorized and unauthorized network.

Example:

```bash
sudo systemctl stop dnsmasq sniproxy
sudo ./dns-sni-unlock.sh install \
  --proxy-ip 198.51.100.20 \
  --allow 203.0.113.10
```

Then edit `/etc/dns-sni-unlock/services.conf` and run:

```bash
sudo dns-sni-unlock apply
sudo dns-sni-unlock doctor
```

## Converting a service line

v2:

```text
Example:198.51.100.20:example.com media.example.com
```

v3:

```text
Example|198.51.100.20|example.com media.example.com
```

Do not mechanically convert untrusted content. v3 validates each field and rejects wildcards, URLs, shell characters, malformed IPs, and malformed domains.

## Rollback

If v3 validation or startup fails:

```bash
sudo dns-sni-unlock uninstall --yes
sudo cp -a /root/dnsmasq.conf.pre-dsu-v3 /etc/dnsmasq.conf
sudo cp -a /root/sniproxy.conf.pre-dsu-v3 /etc/sniproxy.conf
sudo iptables-restore < /root/iptables.pre-dsu-v3.rules
sudo systemctl restart dnsmasq sniproxy
```

Keep the console open until DNS and proxy connectivity have been verified.
