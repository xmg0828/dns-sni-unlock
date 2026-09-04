#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$ROOT_DIR/dns-sni-unlock.sh"
PASS=0

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { PASS=$((PASS + 1)); printf 'ok %d - %s\n' "$PASS" "$1"; }
assert_contains() { grep -Fq -- "$2" "$1" || fail "$1 does not contain: $2"; }
assert_not_contains() { ! grep -Fq -- "$2" "$1" 2>/dev/null || fail "$1 unexpectedly contains: $2"; }

workflow="$ROOT_DIR/.github/workflows/ci.yml"
while read -r action_ref _; do
    case "$action_ref" in
        ./*|docker://*) continue ;;
    esac
    [[ "$action_ref" =~ ^[^@[:space:]]+@[0-9a-f]{40}$ ]] || fail "CI action is not pinned to an immutable SHA: $action_ref"
done < <(sed -n 's/^[[:space:]]*uses:[[:space:]]*//p' "$workflow")
pass "pins every external GitHub Action to an immutable commit SHA"

for linux_image in \
    'debian:11-slim' 'debian:12-slim' 'debian:13-slim' \
    'ubuntu:20.04' 'ubuntu:22.04' 'ubuntu:24.04'; do
    assert_contains "$workflow" "image: $linux_image"
done
assert_contains "$workflow" 'runs-on: macos-latest'
assert_contains "$workflow" '/bin/bash ./tests/test.sh'
assert_contains "$workflow" 'brew install python'
assert_contains "$workflow" "\$(brew --prefix python)/bin"
assert_contains "$workflow" 'python3 -c '\''import ipaddress'\'''
assert_contains "$workflow" 'apt-get install -y --no-install-recommends bash ca-certificates coreutils diffutils gawk git grep sed python3'
assert_contains "$workflow" "python3 -c 'import ipaddress'"
pass "CI exercises every documented Debian and Ubuntu release plus macOS Bash 3.2"

version=$($SCRIPT --version)
[[ "$version" == "dns-sni-unlock 3.0.0" ]] || fail "unexpected version: $version"
pass "reports a semantic version"

$SCRIPT validate-ip 203.0.113.7 >/dev/null
if $SCRIPT validate-ip 999.1.2.3 >/dev/null 2>&1; then fail "accepted invalid IPv4"; fi
if $SCRIPT validate-ip '1.2.3.4;touch /tmp/pwned' >/dev/null 2>&1; then fail "accepted injected IPv4"; fi
pass "validates IPv4 addresses without command injection"

$SCRIPT validate-cidr 203.0.113.0/24 >/dev/null
$SCRIPT validate-cidr 203.0.113.7 >/dev/null
if $SCRIPT validate-cidr 203.0.113.0/99 >/dev/null 2>&1; then fail "accepted invalid CIDR"; fi
pass "validates IPv4 hosts and CIDRs"

open_root=$(mktemp -d)
if DSU_ROOT="$open_root" DSU_TEST_MODE=1 "$SCRIPT" install --proxy-ip 198.51.100.20 --allow 0.0.0.0/0 >/dev/null 2>&1; then fail "accepted an open gateway allowlist"; fi
rm -rf "$open_root"
pass "refuses an internet-wide allowlist"

covered_root=$(mktemp -d)
if DSU_ROOT="$covered_root" DSU_TEST_MODE=1 "$SCRIPT" install --proxy-ip 198.51.100.20 \
  --allow 0.0.0.0/1 --allow 128.0.0.0/1 >/dev/null 2>&1; then
  fail "accepted an allowlist whose two /1 entries cover all IPv4 addresses"
fi
rm -rf "$covered_root"
pass "rejects allowlist combinations that cover the entire IPv4 space"

effective_coverage_root=$(mktemp -d)
DSU_ROOT="$effective_coverage_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
python3 - "$effective_coverage_root/etc/dns-sni-unlock/whitelist.conf" <<'PY'
import ipaddress
import sys
with open(sys.argv[1], "w", encoding="utf-8") as output:
    for network in ipaddress.IPv4Network("0.0.0.0/0").address_exclude(
        ipaddress.IPv4Network("127.0.0.1/32")
    ):
        output.write(f"{network}\n")
PY
if DSU_ROOT="$effective_coverage_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null 2>&1; then
  fail "accepted an allowlist that becomes internet-wide after loopback insertion"
fi
rm -rf "$effective_coverage_root"
pass "rejects internet-wide effective allowlists after loopback insertion"

normal_cidr_root=$(mktemp -d)
DSU_ROOT="$normal_cidr_root" DSU_TEST_MODE=1 "$SCRIPT" install --proxy-ip 198.51.100.20 \
  --allow 10.0.0.0/8 --allow 203.0.113.0/24 >/dev/null
rm -rf "$normal_cidr_root"
pass "accepts normal private and public CIDRs"

$SCRIPT validate-domain example.com >/dev/null
$SCRIPT validate-domain media.example.co.uk >/dev/null
if $SCRIPT validate-domain '*.example.com' >/dev/null 2>&1; then fail "accepted wildcard domain"; fi
if $SCRIPT validate-domain 'example.com;id' >/dev/null 2>&1; then fail "accepted injected domain"; fi
if $SCRIPT validate-domain '-example.com' >/dev/null 2>&1; then fail "accepted invalid label"; fi
pass "validates normalized domain names"

sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT
DSU_ROOT="$sandbox" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
services="$sandbox/etc/dns-sni-unlock/services.conf"
whitelist="$sandbox/etc/dns-sni-unlock/whitelist.conf"
[[ -s "$services" && -s "$whitelist" ]] || fail "default configuration was not created"
assert_contains "$services" 'OpenAI|127.0.0.1|openai.com chatgpt.com'
assert_contains "$whitelist" '127.0.0.1'
pass "initializes deterministic configuration"

init_symlink_root=$(mktemp -d)
mkdir -p "$init_symlink_root/etc/dns-sni-unlock"
ln -s missing-services-target "$init_symlink_root/etc/dns-sni-unlock/services.conf"
ln -s missing-whitelist-target "$init_symlink_root/etc/dns-sni-unlock/whitelist.conf"
init_symlink_output="$init_symlink_root/output"
if DSU_ROOT="$init_symlink_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >"$init_symlink_output" 2>&1; then
  :
else
  fail "init-config rejected existing unmanaged symlink inputs"
fi
[[ -L "$init_symlink_root/etc/dns-sni-unlock/services.conf" ]] || fail "init-config replaced dangling services symlink"
[[ "$(readlink "$init_symlink_root/etc/dns-sni-unlock/services.conf")" == missing-services-target ]] || fail "init-config changed dangling services symlink target"
[[ -L "$init_symlink_root/etc/dns-sni-unlock/whitelist.conf" ]] || fail "init-config replaced dangling whitelist symlink"
[[ "$(readlink "$init_symlink_root/etc/dns-sni-unlock/whitelist.conf")" == missing-whitelist-target ]] || fail "init-config changed dangling whitelist symlink target"
if DSU_ROOT="$init_symlink_root" DSU_TEST_MODE=1 "$SCRIPT" render >"$init_symlink_output" 2>&1; then
  fail "render accepted dangling input symlinks"
fi
assert_contains "$init_symlink_output" 'services file is missing or unreadable'
[[ -L "$init_symlink_root/etc/dns-sni-unlock/services.conf" ]] || fail "render replaced dangling services symlink"
[[ -L "$init_symlink_root/etc/dns-sni-unlock/whitelist.conf" ]] || fail "render replaced dangling whitelist symlink"
rm -rf "$init_symlink_root"
pass "preserves dangling input symlinks and rejects them clearly"

DSU_ROOT="$sandbox" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
dnsmasq="$sandbox/etc/dnsmasq.d/90-dns-sni-unlock.conf"
sniproxy="$sandbox/etc/sniproxy.conf"
assert_contains "$dnsmasq" 'address=/openai.com/127.0.0.1'
assert_contains "$dnsmasq" 'address=/chatgpt.com/127.0.0.1'
assert_contains "$sniproxy" '^openai\.com$ *'
assert_contains "$sniproxy" '.*\.openai\.com$ *'
assert_not_contains "$sniproxy" '    .* *'
pass "renders allowlisted DNS and SNI rules without an open catch-all proxy"

cp "$dnsmasq" "$sandbox/dnsmasq.first"
cp "$sniproxy" "$sandbox/sniproxy.first"
DSU_ROOT="$sandbox" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
cmp -s "$dnsmasq" "$sandbox/dnsmasq.first" || fail "dnsmasq render is not idempotent"
cmp -s "$sniproxy" "$sandbox/sniproxy.first" || fail "sniproxy render is not idempotent"
pass "renders configuration idempotently"

render_tx_root=$(mktemp -d)
DSU_ROOT="$render_tx_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
DSU_ROOT="$render_tx_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
render_tx_services="$render_tx_root/etc/dns-sni-unlock/services.conf"
render_tx_dnsmasq="$render_tx_root/etc/dnsmasq.d/90-dns-sni-unlock.conf"
render_tx_sniproxy="$render_tx_root/etc/sniproxy.conf"
cp "$render_tx_dnsmasq" "$render_tx_root/dnsmasq.before"
cp "$render_tx_sniproxy" "$render_tx_root/sniproxy.before"
printf 'RenderTx|198.51.100.30|render-tx.example\n' >> "$render_tx_services"
mkdir -p "$render_tx_root/mock-bin"
cat > "$render_tx_root/mock-bin/mv" <<'EOF'
#!/bin/sh
last=''
for argument do last=$argument; done
if [ "$last" = "$DSU_FAIL_TARGET" ] && [ ! -e "$DSU_FAIL_ONCE" ]; then
  : > "$DSU_FAIL_ONCE"
  exit 73
fi
exec "$DSU_REAL_MV" "$@"
EOF
chmod +x "$render_tx_root/mock-bin/mv"
real_mv=$(command -v mv)
if PATH="$render_tx_root/mock-bin:$PATH" \
  DSU_REAL_MV="$real_mv" \
  DSU_FAIL_TARGET="$render_tx_sniproxy" \
  DSU_FAIL_ONCE="$render_tx_root/mv.failed" \
  DSU_ROOT="$render_tx_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null 2>&1; then
  fail "render succeeded after an injected second-file replacement failure"
fi
cmp -s "$render_tx_dnsmasq" "$render_tx_root/dnsmasq.before" || fail "failed render left dnsmasq partially updated"
cmp -s "$render_tx_sniproxy" "$render_tx_root/sniproxy.before" || fail "failed render changed SNIProxy configuration"
rm -rf "$render_tx_root"
pass "rolls back both generated files when render replacement fails"

for failure_phase in validate firewall restart; do
  apply_tx_root=$(mktemp -d)
  DSU_ROOT="$apply_tx_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
  DSU_ROOT="$apply_tx_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
  apply_tx_services="$apply_tx_root/etc/dns-sni-unlock/services.conf"
  apply_tx_dnsmasq="$apply_tx_root/etc/dnsmasq.d/90-dns-sni-unlock.conf"
  apply_tx_sniproxy="$apply_tx_root/etc/sniproxy.conf"
  cp "$apply_tx_dnsmasq" "$apply_tx_root/dnsmasq.before"
  cp "$apply_tx_sniproxy" "$apply_tx_root/sniproxy.before"
  printf 'ApplyTx|198.51.100.31|apply-tx.example\n' >> "$apply_tx_services"
  if DSU_ROOT="$apply_tx_root" DSU_TEST_MODE=1 bash -c '
    source "$1"
    failure_phase=$2
    validate_runtime_configs() { [[ "$failure_phase" != validate ]]; }
    firewall_apply() { [[ "$failure_phase" != firewall ]]; }
    restart_services() { [[ "$failure_phase" != restart ]]; }
    apply_all
  ' bash "$SCRIPT" "$failure_phase" >/dev/null 2>&1; then
    fail "apply succeeded after injected $failure_phase failure"
  fi
  cmp -s "$apply_tx_dnsmasq" "$apply_tx_root/dnsmasq.before" || fail "$failure_phase failure left dnsmasq partially applied"
  cmp -s "$apply_tx_sniproxy" "$apply_tx_root/sniproxy.before" || fail "$failure_phase failure left SNIProxy partially applied"
  rm -rf "$apply_tx_root"
done
pass "rolls back generated configuration after apply-stage failures"

cp "$services" "$sandbox/services.good"
printf 'Bad|127.0.0.1|example.com;id\n' >> "$services"
if DSU_ROOT="$sandbox" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null 2>&1; then fail "render accepted unsafe config"; fi
mv "$sandbox/services.good" "$services"
pass "rejects unsafe service configuration"

service_name_root=$(mktemp -d)
if ! bash -c '
  source "$1"
  for unsafe_service_name in $'"'"'Bad\tName'"'"' $'"'"'Bad\nName'"'"' $'"'"'Bad\rName'"'"' $'"'"'Bad\vName'"'"' $'"'"'Bad\fName'"'"'; do
    validate_service_name "$unsafe_service_name" || continue
    exit 1
  done
  validate_service_name "Good Name"
' bash "$SCRIPT"; then
  fail "service-name validation did not preserve its explicit safe-character contract"
fi
rm -rf "$service_name_root"
pass "service names allow explicit safe ASCII characters but no controls"

cp "$services" "$sandbox/services.good"
printf 'ConflictA|198.51.100.1|duplicate.example\nConflictB|198.51.100.2|duplicate.example\n' >> "$services"
if DSU_ROOT="$sandbox" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null 2>&1; then fail "render accepted conflicting domain routes"; fi
mv "$sandbox/services.good" "$services"
pass "rejects conflicting routes for the same domain"

! grep -Eq 'iptables[[:space:]]+-P[[:space:]]+(INPUT|FORWARD|OUTPUT)' "$SCRIPT" || fail "script changes global firewall policy"
! grep -Eq 'iptables[[:space:]]+-F([[:space:]]*$|[[:space:]]*;)' "$SCRIPT" || fail "script flushes the global firewall"
! grep -Eq 'iptables[[:space:]]+-X([[:space:]]*$|[[:space:]]*;)' "$SCRIPT" || fail "script deletes global firewall chains"
pass "never resets global firewall policy or global chains"

DSU_ROOT="$sandbox" DSU_TEST_MODE=1 "$SCRIPT" firewall-plan > "$sandbox/firewall.plan"
assert_contains "$sandbox/firewall.plan" 'DNS_SNI_UNLOCK_IN'
assert_contains "$sandbox/firewall.plan" '-p udp --dport 53'
assert_contains "$sandbox/firewall.plan" '-p tcp -m multiport --dports 53,80,443'
assert_not_contains "$sandbox/firewall.plan" 'iptables -F INPUT'
pass "uses an isolated firewall chain"

firewall_tx_root=$(mktemp -d)
DSU_ROOT="$firewall_tx_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$firewall_tx_root/mock-bin"
cat > "$firewall_tx_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
printf 'iptables %s\\n' "$*" >> "$DSU_FW_LOG"
if [ "$1" = "-A" ]; then exit 73; fi
exit 0
EOF
chmod +x "$firewall_tx_root/mock-bin/iptables"
cat > "$firewall_tx_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
printf '*filter\\n:INPUT ACCEPT [0:0]\\nCOMMIT\\n'
EOF
cat > "$firewall_tx_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
printf 'iptables-restore\\n' >> "$DSU_FW_LOG"
cat >/dev/null
EOF
chmod +x "$firewall_tx_root/mock-bin/iptables-save" "$firewall_tx_root/mock-bin/iptables-restore"
if PATH="$firewall_tx_root/mock-bin:$PATH" DSU_FW_LOG="$firewall_tx_root/firewall.log" \
  DSU_ROOT="$firewall_tx_root" DSU_TEST_MODE=0 bash -c '
    source "$1"
    require_root() { :; }
    firewall_apply
  ' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall apply succeeded after replacement rule failure"
fi
assert_contains "$firewall_tx_root/firewall.log" 'iptables-restore'
assert_not_contains "$firewall_tx_root/firewall.log" 'iptables -F DNS_SNI_UNLOCK_IN'
assert_contains "$firewall_tx_root/firewall.log" 'iptables -N DNS_SNI_UNLOCK_IN_NEW_'
rm -rf "$firewall_tx_root"
pass "firewall replacement is fail-closed and rollback-safe"

remove_ref_root=$(mktemp -d)
DSU_ROOT="$remove_ref_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$remove_ref_root/mock-bin"
cat > "$remove_ref_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:UNMANAGED ACCEPT [0:0]
:DNS_SNI_UNLOCK_IN - [0:0]
-A UNMANAGED -j DNS_SNI_UNLOCK_IN
-A INPUT -j DNS_SNI_UNLOCK_IN
COMMIT
RULES
EOF
cat > "$remove_ref_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_FW_LOG"
case "$1:$2:$3:$4" in
  -C:INPUT:-j:DNS_SNI_UNLOCK_IN) exit 1 ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$remove_ref_root/mock-bin/iptables" "$remove_ref_root/mock-bin/iptables-save"
if PATH="$remove_ref_root/mock-bin:$PATH" DSU_FW_LOG="$remove_ref_root/firewall.log" \
  DSU_ROOT="$remove_ref_root" DSU_TEST_MODE=0 bash -c '
    source "$1"
    require_root() { :; }
    firewall_remove
  ' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall clear ignored an unmanaged chain reference"
fi
assert_not_contains "$remove_ref_root/firewall.log" '-F DNS_SNI_UNLOCK_IN'
assert_not_contains "$remove_ref_root/firewall.log" '-X DNS_SNI_UNLOCK_IN'
rm -rf "$remove_ref_root"
pass "refuses to retire a dedicated chain referenced by an unmanaged chain"

clear_tx_root=$(mktemp -d)
DSU_ROOT="$clear_tx_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$clear_tx_root/var/lib/dns-sni-unlock"
printf 'Managed by dns-sni-unlock firewall chain DNS_SNI_UNLOCK_IN\n' > "$clear_tx_root/var/lib/dns-sni-unlock/firewall.ownership"
mkdir -p "$clear_tx_root/mock-bin"
cat > "$clear_tx_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:DNS_SNI_UNLOCK_IN - [0:0]
-A INPUT -j DNS_SNI_UNLOCK_IN
COMMIT
RULES
EOF
cat > "$clear_tx_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
printf 'iptables %s\n' "$*" >> "$DSU_FW_LOG"
if [ "$1" = "-S" ] && [ "$2" = "INPUT" ]; then
  printf '%s\n' '-A INPUT -j DNS_SNI_UNLOCK_IN'
  exit 0
fi
if [ "$1" = "-F" ]; then exit 73; fi
exit 0
EOF
cat > "$clear_tx_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
if [ "${DSU_RESTORE_FAIL:-0}" = 1 ]; then cat >/dev/null; exit 74; fi
cat > "$DSU_RESTORED"
EOF
chmod +x "$clear_tx_root/mock-bin/iptables" "$clear_tx_root/mock-bin/iptables-save" "$clear_tx_root/mock-bin/iptables-restore"
if PATH="$clear_tx_root/mock-bin:$PATH" DSU_FW_LOG="$clear_tx_root/firewall.log" \
  DSU_RESTORED="$clear_tx_root/restored.rules" DSU_ROOT="$clear_tx_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; require_root() { :; }; firewall_remove' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall clear succeeded after a destructive command failed"
fi
printf '*filter\n:INPUT ACCEPT [0:0]\n:DNS_SNI_UNLOCK_IN - [0:0]\n-A INPUT -j DNS_SNI_UNLOCK_IN\nCOMMIT\n' > "$clear_tx_root/expected.rules"
cmp -s "$clear_tx_root/restored.rules" "$clear_tx_root/expected.rules" || fail "firewall clear did not restore the exact snapshot"
if PATH="$clear_tx_root/mock-bin:$PATH" DSU_FW_LOG="$clear_tx_root/firewall.log" \
  DSU_RESTORED="$clear_tx_root/restored.rules" DSU_RESTORE_FAIL=1 DSU_ROOT="$clear_tx_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; require_root() { :; }; firewall_remove' bash "$SCRIPT" >"$clear_tx_root/restore-failure.out" 2>&1; then
  fail "firewall clear succeeded when rollback restore failed"
fi
assert_contains "$clear_tx_root/restore-failure.out" 'UNSAFE STATE'
assert_contains "$clear_tx_root/restore-failure.out" 'firewall transaction directory:'
clear_fail_txdir=$(sed $'s/\033\[[0-9;]*m//g' "$clear_tx_root/restore-failure.out" | sed -n 's/.*firewall transaction directory: \([^ ]*\).*/\1/p')
[[ -d "$clear_fail_txdir" ]] || fail "firewall remove deleted evidence after rollback failure"
[[ -f "$clear_fail_txdir/firewall.before" ]] || fail "firewall remove did not retain the exact snapshot"
rm -rf "$clear_tx_root"
pass "firewall clear restores its exact snapshot and retains evidence when rollback fails"

doctor_root=$(mktemp -d)
DSU_ROOT="$doctor_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
DSU_ROOT="$doctor_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
mkdir -p "$doctor_root/mock-bin"
cat > "$doctor_root/mock-bin/systemctl" <<'EOF'
#!/bin/sh
case "$1" in
  is-active) printf '%s\n' active ;;
  *) exit 0 ;;
esac
EOF
cat > "$doctor_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$doctor_root/mock-bin/systemctl" "$doctor_root/mock-bin/iptables"
if PATH="$doctor_root/mock-bin:$PATH" DSU_ROOT="$doctor_root" DSU_TEST_MODE=0 \
  bash -c '
    source "$1"
    require_root() { :; }
    doctor
  ' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "doctor accepted a missing live firewall chain"
fi
rm -rf "$doctor_root"
pass "doctor verifies live firewall state instead of trusting service state"

exact_doctor_root=$(mktemp -d)
DSU_ROOT="$exact_doctor_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
DSU_ROOT="$exact_doctor_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
mkdir -p "$exact_doctor_root/mock-bin"
cat > "$exact_doctor_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
case "$1:$2" in
  -L:DNS_SNI_UNLOCK_IN) exit 0 ;;
  -C:*) exit 0 ;;
  -S:DNS_SNI_UNLOCK_IN)
    printf '%s\n' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p udp --dport 53 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p tcp -m multiport --dports 53,80,443 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -p udp --dport 53 -j DROP' '-A DNS_SNI_UNLOCK_IN -p tcp -m multiport --dports 53,80,443 -j DROP' '-A DNS_SNI_UNLOCK_IN -j RETURN' ;;
  -S:INPUT)
    printf '%s\n' '-A INPUT -j ACCEPT' '-A INPUT -j DNS_SNI_UNLOCK_IN' ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$exact_doctor_root/mock-bin/iptables"
if PATH="$exact_doctor_root/mock-bin:$PATH" DSU_ROOT="$exact_doctor_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; require_root() { :; }; doctor_firewall' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "doctor accepted an INPUT jump that was not first"
fi
rm -rf "$exact_doctor_root"
pass "doctor verifies dedicated-chain exactness and INPUT jump ordering"

real_iptables_root=$(mktemp -d)
DSU_ROOT="$real_iptables_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
DSU_ROOT="$real_iptables_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
mkdir -p "$real_iptables_root/var/lib/dns-sni-unlock" "$real_iptables_root/mock-bin"
printf '%s\n' 'Managed by dns-sni-unlock firewall chain DNS_SNI_UNLOCK_IN' > "$real_iptables_root/var/lib/dns-sni-unlock/firewall.ownership"
cat > "$real_iptables_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
case "$1:$2" in
  -L:DNS_SNI_UNLOCK_IN) exit 0 ;;
  -S:DNS_SNI_UNLOCK_IN)
    printf '%s\n' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p udp -m udp --dport 53 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p tcp -m multiport --dports 53,80,443 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -p udp -m udp --dport 53 -j DROP' '-A DNS_SNI_UNLOCK_IN -p tcp -m multiport --dports 53,80,443 -j DROP' '-A DNS_SNI_UNLOCK_IN -j RETURN' ;;
  -S:INPUT) printf '%s\n' '-A INPUT -j DNS_SNI_UNLOCK_IN' ;;
  *) exit 0 ;;
esac
EOF
cat > "$real_iptables_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' ':DNS_SNI_UNLOCK_IN - [0:0]' '-A INPUT -j DNS_SNI_UNLOCK_IN' 'COMMIT'
EOF
chmod +x "$real_iptables_root/mock-bin/iptables" "$real_iptables_root/mock-bin/iptables-save"
if ! PATH="$real_iptables_root/mock-bin:$PATH" DSU_ROOT="$real_iptables_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; require_root() { :; }; doctor_firewall' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "doctor rejected real iptables -S implicit UDP match serialization"
fi
rm -rf "$real_iptables_root"
pass "accepts real iptables UDP serialization with implicit -m udp"

doctor_ref_root=$(mktemp -d)
DSU_ROOT="$doctor_ref_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
DSU_ROOT="$doctor_ref_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
mkdir -p "$doctor_ref_root/mock-bin"
cat > "$doctor_ref_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:UNMANAGED ACCEPT [0:0]
:DNS_SNI_UNLOCK_IN - [0:0]
-A UNMANAGED -j DNS_SNI_UNLOCK_IN
-A INPUT -j DNS_SNI_UNLOCK_IN
COMMIT
RULES
EOF
cat > "$doctor_ref_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
case "$1:$2" in
  -L:DNS_SNI_UNLOCK_IN) exit 0 ;;
  -S:DNS_SNI_UNLOCK_IN)
    printf '%s\n' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p udp --dport 53 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p tcp -m multiport --dports 53,80,443 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -p udp --dport 53 -j DROP' '-A DNS_SNI_UNLOCK_IN -p tcp -m multiport --dports 53,80,443 -j DROP' '-A DNS_SNI_UNLOCK_IN -j RETURN' ;;
  -S:INPUT) printf '%s\n' '-A INPUT -j DNS_SNI_UNLOCK_IN' ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$doctor_ref_root/mock-bin/iptables" "$doctor_ref_root/mock-bin/iptables-save"
if PATH="$doctor_ref_root/mock-bin:$PATH" DSU_ROOT="$doctor_ref_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; require_root() { :; }; doctor_firewall' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "doctor accepted an unmanaged dedicated-chain reference"
fi
rm -rf "$doctor_ref_root"
pass "doctor rejects unmanaged references to the dedicated firewall chain"

config_doctor_root=$(mktemp -d)
DSU_ROOT="$config_doctor_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
DSU_ROOT="$config_doctor_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
printf 'Changed|198.51.100.70|changed.example\n' >> "$config_doctor_root/etc/dns-sni-unlock/services.conf"
if DSU_ROOT="$config_doctor_root" DSU_TEST_MODE=1 "$SCRIPT" doctor >/dev/null 2>&1; then
  fail "doctor accepted generated configuration that did not match sources"
fi
rm -rf "$config_doctor_root"
pass "doctor verifies generated configuration against source files"

apply_ref_root=$(mktemp -d)
DSU_ROOT="$apply_ref_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$apply_ref_root/mock-bin"
cat > "$apply_ref_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:UNMANAGED ACCEPT [0:0]
:DNS_SNI_UNLOCK_IN - [0:0]
-A UNMANAGED -j DNS_SNI_UNLOCK_IN
COMMIT
RULES
EOF
cat > "$apply_ref_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_FW_LOG"
case "$1" in
  -L) exit 0 ;;
  -A) exit 0 ;;
  -C) exit 1 ;;
  *) exit 0 ;;
esac
EOF
cat > "$apply_ref_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
cat >/dev/null
exit 0
EOF
chmod +x "$apply_ref_root/mock-bin/iptables" "$apply_ref_root/mock-bin/iptables-save" "$apply_ref_root/mock-bin/iptables-restore"
if PATH="$apply_ref_root/mock-bin:$PATH" DSU_FW_LOG="$apply_ref_root/firewall.log" \
  DSU_ROOT="$apply_ref_root" DSU_TEST_MODE=0 bash -c '
    source "$1"
    require_root() { :; }
    firewall_apply
  ' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall apply retired a chain referenced by an unmanaged chain"
fi
assert_not_contains "$apply_ref_root/firewall.log" '-E DNS_SNI_UNLOCK_IN'
rm -rf "$apply_ref_root"
pass "firewall apply refuses to retire a referenced old chain"

restore_fail_root=$(mktemp -d)
DSU_ROOT="$restore_fail_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$restore_fail_root/mock-bin"
cat > "$restore_fail_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
printf 'iptables %s\n' "$*" >> "$DSU_FW_LOG"
[ "$1" = "-A" ] && exit 73
exit 0
EOF
cat > "$restore_fail_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
printf '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n'
EOF
cat > "$restore_fail_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
cat >/dev/null
printf 'restore-failed\n' >> "$DSU_FW_LOG"
exit 74
EOF
chmod +x "$restore_fail_root/mock-bin/iptables" "$restore_fail_root/mock-bin/iptables-save" "$restore_fail_root/mock-bin/iptables-restore"
if PATH="$restore_fail_root/mock-bin:$PATH" DSU_FW_LOG="$restore_fail_root/firewall.log" \
  DSU_ROOT="$restore_fail_root" DSU_TEST_MODE=0 bash -c '
    source "$1"
    require_root() { :; }
    firewall_apply
  ' bash "$SCRIPT" >"$restore_fail_root/output" 2>&1; then
  fail "firewall apply succeeded when rollback restore failed"
fi
assert_contains "$restore_fail_root/output" 'UNSAFE STATE'
assert_contains "$restore_fail_root/output" 'firewall transaction directory:'
restore_fail_txdir=$(sed $'s/\033\[[0-9;]*m//g' "$restore_fail_root/output" | sed -n 's/.*firewall transaction directory: \([^ ]*\).*/\1/p')
[[ -d "$restore_fail_txdir" ]] || fail "firewall apply deleted evidence after rollback failure"
[[ -f "$restore_fail_txdir/firewall.before" ]] || fail "firewall apply did not retain the exact snapshot"
rm -rf "$restore_fail_root"
pass "reports an unsafe state when firewall rollback cannot restore the snapshot and retains evidence"

state_root=$(mktemp -d)
mkdir -p "$state_root/etc/dnsmasq.d" "$state_root/usr/local/sbin" "$state_root/mock-bin"
printf 'unmanaged installed binary\n' > "$state_root/usr/local/sbin/dns-sni-unlock"
cp "$state_root/usr/local/sbin/dns-sni-unlock" "$state_root/installed.expected"
cat > "$state_root/mock-bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_STATE_LOG"
case "$1:$2" in
  is-enabled:dnsmasq) printf '%s\n' disabled; exit 1 ;;
  is-active:dnsmasq) printf '%s\n' inactive; exit 1 ;;
  is-enabled:sniproxy) printf '%s\n' enabled ;;
  is-active:sniproxy) printf '%s\n' active ;;
  is-enabled:*) printf '%s\n' disabled; exit 1 ;;
  is-active:*) printf '%s\n' inactive; exit 1 ;;
esac
exit 0
EOF
chmod +x "$state_root/mock-bin/systemctl"
cat > "$state_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
printf '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n'
EOF
chmod +x "$state_root/mock-bin/iptables-save"
cat > "$state_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$state_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
cat >/dev/null
exit 0
EOF
chmod +x "$state_root/mock-bin/iptables" "$state_root/mock-bin/iptables-restore"
if ! PATH="$state_root/mock-bin:$PATH" DSU_STATE_LOG="$state_root/systemctl.log" \
  DSU_ROOT="$state_root" DSU_TEST_MODE=0 bash -c '
    source "$1"
    require_root() { :; }
    install_packages() { :; }
    validate_runtime_configs() { :; }
    doctor() { :; }
    install_gateway --proxy-ip 198.51.100.20 --allow 203.0.113.10
    [[ -s "$STATE_DIR/service-state" ]]
    grep -Fxq "dnsmasq|disabled|inactive" "$STATE_DIR/service-state"
    grep -Fxq "sniproxy|enabled|active" "$STATE_DIR/service-state"
    grep -Fq "$MANAGED_MARKER" "$INSTALLED_BIN"
    uninstall_gateway --yes
    [[ -f "$INSTALLED_BIN" ]]
    cmp -s "$INSTALLED_BIN" "$ROOT_PREFIX/installed.expected"
  ' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "service state or installed binary ownership was not preserved on uninstall"
fi
rm -rf "$state_root"
pass "persists service states and removes only the managed installed binary"

uninstall_success_state_root=$(mktemp -d)
DSU_ROOT="$uninstall_success_state_root" DSU_TEST_MODE=1 "$SCRIPT" install --proxy-ip 198.51.100.21 --allow 203.0.113.21 >/dev/null
mkdir -p "$uninstall_success_state_root/mock-bin"
cat > "$uninstall_success_state_root/mock-bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_STATE_LOG"
case "$1:$2" in
  is-enabled:dnsmasq|is-enabled:sniproxy) printf '%s\n' disabled; exit 1 ;;
  is-active:dnsmasq|is-active:sniproxy) printf '%s\n' inactive; exit 1 ;;
  is-enabled:dns-sni-unlock-firewall.service) printf '%s\n' enabled; exit 0 ;;
  is-active:dns-sni-unlock-firewall.service) printf '%s\n' active; exit 0 ;;
  *) exit 0 ;;
esac
EOF
cat > "$uninstall_success_state_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$uninstall_success_state_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' 'COMMIT'
EOF
cat > "$uninstall_success_state_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
cat >/dev/null
EOF
chmod +x "$uninstall_success_state_root/mock-bin/systemctl" \
  "$uninstall_success_state_root/mock-bin/iptables" \
  "$uninstall_success_state_root/mock-bin/iptables-save" \
  "$uninstall_success_state_root/mock-bin/iptables-restore"
if ! PATH="$uninstall_success_state_root/mock-bin:$PATH" \
  DSU_STATE_LOG="$uninstall_success_state_root/systemctl.log" \
  DSU_ROOT="$uninstall_success_state_root" DSU_TEST_MODE=0 bash -c '
    source "$1"
    require_root() { :; }
    firewall_remove() { :; }
    uninstall_gateway --yes
  ' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "successful non-test uninstall failed while removing its unit"
fi
assert_not_contains "$uninstall_success_state_root/systemctl.log" 'enable dns-sni-unlock-firewall.service'
assert_not_contains "$uninstall_success_state_root/systemctl.log" 'restart dns-sni-unlock-firewall.service'
assert_not_contains "$uninstall_success_state_root/systemctl.log" 'start dns-sni-unlock-firewall.service'
rm -rf "$uninstall_success_state_root"
pass "does not restore or restart the removed project firewall unit after successful uninstall"

source_tx_root=$(mktemp -d)
DSU_ROOT="$source_tx_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
cp "$source_tx_root/etc/dns-sni-unlock/services.conf" "$source_tx_root/services.before"
cp "$source_tx_root/etc/dns-sni-unlock/whitelist.conf" "$source_tx_root/whitelist.before"
if DSU_ROOT="$source_tx_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  require_root() { :; }
  apply_all() { return 71; }
  service_add NewRoute 198.51.100.40 new-route.example
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "service add succeeded after apply failure"
fi
cmp -s "$source_tx_root/etc/dns-sni-unlock/services.conf" "$source_tx_root/services.before" || fail "failed service add changed services.conf"
if DSU_ROOT="$source_tx_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  require_root() { :; }
  apply_all() { return 72; }
  firewall_add 203.0.113.40
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall add succeeded after apply failure"
fi
cmp -s "$source_tx_root/etc/dns-sni-unlock/whitelist.conf" "$source_tx_root/whitelist.before" || fail "failed firewall add changed whitelist.conf"
rm -rf "$source_tx_root"
pass "rolls back source configuration when service or firewall apply fails"

source_write_root=$(mktemp -d)
DSU_ROOT="$source_write_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$source_write_root/mock-bin"
cat > "$source_write_root/mock-bin/mv" <<'EOF'
#!/bin/sh
last=''
for argument do last=$argument; done
if [ "$last" = "$DSU_FAIL_TARGET" ]; then exit 73; fi
exec "$DSU_REAL_MV" "$@"
EOF
chmod +x "$source_write_root/mock-bin/mv"
source_write_services="$source_write_root/etc/dns-sni-unlock/services.conf"
source_write_whitelist="$source_write_root/etc/dns-sni-unlock/whitelist.conf"
cp "$source_write_services" "$source_write_root/services.before"
cp "$source_write_whitelist" "$source_write_root/whitelist.before"
source_write_mv=$(command -v mv)
if PATH="$source_write_root/mock-bin:$PATH" DSU_REAL_MV="$source_write_mv" DSU_FAIL_TARGET="$source_write_services" \
  DSU_ROOT="$source_write_root" DSU_TEST_MODE=1 "$SCRIPT" service add Atomic 198.51.100.41 atomic.example >/dev/null 2>&1; then
  fail "service add succeeded after an atomic source replacement failure"
fi
cmp -s "$source_write_services" "$source_write_root/services.before" || fail "failed service source replacement changed services.conf"
if PATH="$source_write_root/mock-bin:$PATH" DSU_REAL_MV="$source_write_mv" DSU_FAIL_TARGET="$source_write_whitelist" \
  DSU_ROOT="$source_write_root" DSU_TEST_MODE=1 "$SCRIPT" firewall add 203.0.113.41 >/dev/null 2>&1; then
  fail "firewall add succeeded after an atomic source replacement failure"
fi
cmp -s "$source_write_whitelist" "$source_write_root/whitelist.before" || fail "failed firewall source replacement changed whitelist.conf"
rm -rf "$source_write_root"
pass "atomically replaces source files and preserves them on write failure"

install_fw_root=$(mktemp -d)
mkdir -p "$install_fw_root/mock-bin"
cat > "$install_fw_root/mock-bin/systemctl" <<'EOF'
#!/bin/sh
case "$1:$2" in
  is-enabled:*) printf disabled; exit 1 ;;
  is-active:*) printf inactive; exit 1 ;;
esac
exit 0
EOF
cat > "$install_fw_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
printf '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n'
EOF
cat > "$install_fw_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
cat >/dev/null
printf 'restored\n' >> "$DSU_FW_LOG"
EOF
chmod +x "$install_fw_root/mock-bin/systemctl" "$install_fw_root/mock-bin/iptables-save" "$install_fw_root/mock-bin/iptables-restore"
if PATH="$install_fw_root/mock-bin:$PATH" DSU_FW_LOG="$install_fw_root/firewall.log" \
  DSU_ROOT="$install_fw_root" DSU_TEST_MODE=0 bash -c '
    source "$1"
    require_root() { :; }
    install_packages() { :; }
    validate_runtime_configs() { :; }
    restart_services() { return 74; }
    doctor() { :; }
    install_gateway --proxy-ip 198.51.100.51 --allow 203.0.113.51
  ' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "install succeeded after restart failure"
fi
assert_contains "$install_fw_root/firewall.log" 'restored'
rm -rf "$install_fw_root"
pass "install rollback restores the exact pre-install firewall snapshot"

install_service_rollback_root=$(mktemp -d)
mkdir -p "$install_service_rollback_root/mock-bin" "$install_service_rollback_root/unit-state" \
  "$install_service_rollback_root/etc/systemd/system"
: > "$install_service_rollback_root/unit-state/dns-sni-unlock-firewall.service.enabled"
: > "$install_service_rollback_root/unit-state/dns-sni-unlock-firewall.service.active"
printf 'pre-existing project firewall unit\n' > "$install_service_rollback_root/etc/systemd/system/dns-sni-unlock-firewall.service"
cat > "$install_service_rollback_root/mock-bin/systemctl" <<'EOF'
#!/bin/sh
unit_state_dir=$DSU_UNIT_STATE_DIR
printf '%s\n' "$*" >> "$DSU_STATE_LOG"
state_file() { printf '%s/%s.%s' "$unit_state_dir" "$2" "$1"; }
case "$1:$2" in
  is-enabled:*) printf 'enabled\n' ;;
  is-active:*) printf 'active\n' ;;
  enable:*)
    shift
    for unit do : > "$(state_file enabled "$unit")"; done
    ;;
  restart:*)
    shift
    for unit do : > "$(state_file active "$unit")"; done
    [ "${1:-}" = dnsmasq ] && [ ! -e "$DSU_RESTART_FAILED" ] && { : > "$DSU_RESTART_FAILED"; exit 74; }
    :
    ;;
  stop:*)
    shift
    for unit do rm -f "$(state_file active "$unit")"; done
    ;;
  disable:*)
    shift
    [ "${1:-}" = --now ] && shift
    for unit do rm -f "$(state_file enabled "$unit")" "$(state_file active "$unit")"; done
    ;;
  *) : ;;
esac
EOF
cat > "$install_service_rollback_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' 'COMMIT'
EOF
cat > "$install_service_rollback_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
cat >/dev/null
printf 'restored\n' >> "$DSU_FW_LOG"
EOF
chmod +x "$install_service_rollback_root/mock-bin/systemctl" \
  "$install_service_rollback_root/mock-bin/iptables-save" \
  "$install_service_rollback_root/mock-bin/iptables-restore"
if PATH="$install_service_rollback_root/mock-bin:$PATH" \
  DSU_UNIT_STATE_DIR="$install_service_rollback_root/unit-state" \
  DSU_STATE_LOG="$install_service_rollback_root/systemctl.log" \
  DSU_RESTART_FAILED="$install_service_rollback_root/restart.failed" \
  DSU_FW_LOG="$install_service_rollback_root/firewall.log" \
  DSU_ROOT="$install_service_rollback_root" DSU_TEST_MODE=0 bash -c '
    source "$1"
    require_root() { :; }
    install_packages() { :; }
    validate_runtime_configs() { :; }
    install_gateway --proxy-ip 198.51.100.52 --allow 203.0.113.52
  ' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "install succeeded after a late service restart failure"
fi
assert_contains "$install_service_rollback_root/systemctl.log" 'enable dnsmasq sniproxy dns-sni-unlock-firewall.service'
[[ -f "$install_service_rollback_root/etc/systemd/system/dns-sni-unlock-firewall.service" ]] || fail "late install rollback lost the project firewall unit"
assert_contains "$install_service_rollback_root/systemctl.log" 'unmask dns-sni-unlock-firewall.service'
assert_contains "$install_service_rollback_root/systemctl.log" 'enable dns-sni-unlock-firewall.service'
assert_contains "$install_service_rollback_root/systemctl.log" 'restart dns-sni-unlock-firewall.service'
assert_contains "$install_service_rollback_root/firewall.log" 'restored'
rm -rf "$install_service_rollback_root"
pass "late install rollback restores project firewall unit enablement and activity"

runtime_tx_root=$(mktemp -d)
DSU_ROOT="$runtime_tx_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
if DSU_ROOT="$runtime_tx_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  require_root() { :; }
  save_service_state() { printf "before\n" > "$1"; }
  restore_service_state() { printf "restored\n" > "$ROOT_PREFIX/runtime.restored"; }
  render_configs() { :; }
  validate_runtime_configs() { :; }
  firewall_apply() { :; }
  restart_services() { return 73; }
  apply_all
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "apply succeeded after a service restart failure"
fi
assert_contains "$runtime_tx_root/runtime.restored" 'restored'
rm -rf "$runtime_tx_root"
pass "restores runtime service state after an apply failure"

apply_firewall_rollback_root=$(mktemp -d)
DSU_ROOT="$apply_firewall_rollback_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
if DSU_ROOT="$apply_firewall_rollback_root" bash -c '
  source "$1"
  require_root() { :; }
  render_configs() { :; }
  validate_runtime_configs() { :; }
  firewall_apply() { :; }
  save_service_state() { :; }
  save_firewall_snapshot() { printf "firewall snapshot\n" > "$1"; }
  restore_firewall_snapshot() { return 74; }
  restart_services() { return 73; }
  apply_all
' bash "$SCRIPT" >"$apply_firewall_rollback_root/output" 2>&1; then
  fail "apply_all succeeded after firewall rollback failure"
fi
assert_contains "$apply_firewall_rollback_root/output" 'UNSAFE STATE: could not restore prior firewall state'
assert_contains "$apply_firewall_rollback_root/output" 'apply transaction directory:'
apply_firewall_txdir=$(sed $'s/\033\[[0-9;]*m//g' "$apply_firewall_rollback_root/output" | sed -n 's/.*apply transaction directory: \([^ ]*\).*/\1/p')
[[ -d "$apply_firewall_txdir" ]] || fail "apply_all deleted evidence after firewall rollback failure"
[[ -f "$apply_firewall_txdir/firewall.before" ]] || fail "apply_all did not retain its exact firewall snapshot"
rm -rf "$apply_firewall_rollback_root"
pass "apply_all retains its transaction and exact snapshot after firewall rollback failure"

install_tx_root=$(mktemp -d)
if DSU_ROOT="$install_tx_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  require_root() { :; }
  install_packages() { :; }
  validate_runtime_configs() { :; }
  restart_services() { return 74; }
  doctor() { :; }
  install_gateway --proxy-ip 198.51.100.50 --allow 203.0.113.50
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "install succeeded after a systemd failure"
fi
[[ ! -e "$install_tx_root/etc/dns-sni-unlock" ]] || fail "failed install left source configuration"
[[ ! -e "$install_tx_root/etc/dnsmasq.d/90-dns-sni-unlock.conf" ]] || fail "failed install left dnsmasq configuration"
[[ ! -e "$install_tx_root/etc/sniproxy.conf" ]] || fail "failed install left SNIProxy configuration"
[[ ! -e "$install_tx_root/usr/local/sbin/dns-sni-unlock" ]] || fail "failed install left installed binary"
[[ ! -e "$install_tx_root/var/lib/dns-sni-unlock" ]] || fail "failed install left state directory"
rm -rf "$install_tx_root"
pass "rolls back persistent files after install service failure"

delete_root=$(mktemp -d)
DSU_ROOT="$delete_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
delete_whitelist="$delete_root/etc/dns-sni-unlock/whitelist.conf"
printf '203.0.113.10 # office\n' >> "$delete_whitelist"
DSU_ROOT="$delete_root" DSU_TEST_MODE=1 "$SCRIPT" firewall remove 203.0.113.10 >/dev/null
assert_not_contains "$delete_whitelist" '203.0.113.10'
cp "$delete_whitelist" "$delete_root/after-first-remove"
if DSU_ROOT="$delete_root" DSU_TEST_MODE=1 "$SCRIPT" firewall remove 203.0.113.10 >/dev/null 2>&1; then
  fail "removing a missing allowlist entry succeeded"
fi
cmp -s "$delete_whitelist" "$delete_root/after-first-remove" || fail "missing-entry removal changed the allowlist"
rm -rf "$delete_root"
pass "removes canonical inline-comment allowlist entries and rejects missing ones"

DSU_ROOT="$sandbox" DSU_TEST_MODE=1 "$SCRIPT" service add Custom 198.51.100.10 example.org media.example.org >/dev/null
assert_contains "$services" 'Custom|198.51.100.10|example.org media.example.org'
assert_contains "$dnsmasq" 'address=/example.org/198.51.100.10'
DSU_ROOT="$sandbox" DSU_TEST_MODE=1 "$SCRIPT" service set-ip Custom 198.51.100.11 >/dev/null
assert_contains "$services" 'Custom|198.51.100.11|example.org media.example.org'
DSU_ROOT="$sandbox" DSU_TEST_MODE=1 "$SCRIPT" service remove Custom >/dev/null
assert_not_contains "$services" 'Custom|'
pass "manages services end to end in an isolated root"

DSU_ROOT="$sandbox" DSU_TEST_MODE=1 "$SCRIPT" service add AI 198.51.100.12 ai-route.example >/dev/null
assert_contains "$services" 'AI|198.51.100.12|ai-route.example'
DSU_ROOT="$sandbox" DSU_TEST_MODE=1 "$SCRIPT" service remove AI >/dev/null
pass "compares service names exactly when detecting duplicates"

dependency_root=$(mktemp -d)
if ! DSU_ROOT="$dependency_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  order_file=$2
  install_packages() { printf "packages-ready\n" > "$order_file"; }
  detect_proxy_ip() {
    [[ -s "$order_file" ]] || return 79
    printf "198.51.100.20"
  }
  install_self() { :; }
  render_configs() { :; }
  write_firewall_unit() { :; }
  validate_runtime_configs() { :; }
  restart_services() { :; }
  doctor() { :; }
  install_gateway --allow 203.0.113.10
' bash "$SCRIPT" "$dependency_root/order" >/dev/null 2>&1; then
  fail "automatic proxy detection ran before dependency installation"
fi
rm -rf "$dependency_root"
pass "installs dependencies before automatic proxy IPv4 detection"

install_root=$(mktemp -d)
DSU_ROOT="$install_root" DSU_TEST_MODE=1 "$SCRIPT" install --proxy-ip 198.51.100.20 --allow 203.0.113.0/24 --allow 198.51.100.7 >/dev/null
assert_contains "$install_root/etc/dns-sni-unlock/services.conf" 'OpenAI|198.51.100.20|'
assert_contains "$install_root/etc/dns-sni-unlock/whitelist.conf" '203.0.113.0/24'
assert_contains "$install_root/etc/dns-sni-unlock/whitelist.conf" '198.51.100.7'
assert_contains "$install_root/etc/systemd/system/dns-sni-unlock-firewall.service" 'DNS SNI Unlock isolated firewall chain'
DSU_ROOT="$install_root" DSU_TEST_MODE=1 "$SCRIPT" uninstall --yes >/dev/null
[[ ! -e "$install_root/etc/dns-sni-unlock" ]] || fail "uninstall left configuration behind"
rm -rf "$install_root"
pass "installs and uninstalls safely in an isolated root"

restore_root=$(mktemp -d)
mkdir -p "$restore_root/etc/dnsmasq.d"
printf 'unmanaged dnsmasq bytes\n' > "$restore_root/etc/dnsmasq.d/90-dns-sni-unlock.conf"
printf 'unmanaged sniproxy bytes\n' > "$restore_root/etc/sniproxy.conf"
cp "$restore_root/etc/dnsmasq.d/90-dns-sni-unlock.conf" "$restore_root/dnsmasq.expected"
cp "$restore_root/etc/sniproxy.conf" "$restore_root/sniproxy.expected"
DSU_ROOT="$restore_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
DSU_ROOT="$restore_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
DSU_ROOT="$restore_root" DSU_TEST_MODE=1 "$SCRIPT" uninstall --yes >/dev/null
cmp -s "$restore_root/etc/dnsmasq.d/90-dns-sni-unlock.conf" "$restore_root/dnsmasq.expected" || fail "uninstall did not restore the unmanaged dnsmasq snippet"
cmp -s "$restore_root/etc/sniproxy.conf" "$restore_root/sniproxy.expected" || fail "uninstall did not restore the unmanaged SNIProxy config"
rm -rf "$restore_root"
pass "backs up and restores unmanaged dnsmasq and SNIProxy configuration"

ownership_root=$(mktemp -d)
DSU_ROOT="$ownership_root" DSU_TEST_MODE=1 "$SCRIPT" install --proxy-ip 198.51.100.60 --allow 203.0.113.60 >/dev/null
ownership_dnsmasq="$ownership_root/etc/dnsmasq.d/90-dns-sni-unlock.conf"
ownership_sniproxy="$ownership_root/etc/sniproxy.conf"
ownership_bin="$ownership_root/usr/local/sbin/dns-sni-unlock"
ownership_unit="$ownership_root/etc/systemd/system/dns-sni-unlock-firewall.service"
printf '\nadmin dnsmasq change\n' >> "$ownership_dnsmasq"
printf '\nadmin sniproxy change\n' >> "$ownership_sniproxy"
printf '\nadmin binary change\n' >> "$ownership_bin"
printf '\nadmin unit change\n' >> "$ownership_unit"
if DSU_ROOT="$ownership_root" DSU_TEST_MODE=1 "$SCRIPT" uninstall --yes >/dev/null 2>&1; then
  fail "uninstall claimed success after preserving administrator-modified files"
fi
for ownership_file in "$ownership_dnsmasq" "$ownership_sniproxy" "$ownership_bin" "$ownership_unit"; do
  [[ -f "$ownership_file" ]] || fail "uninstall deleted an administrator-modified file: $ownership_file"
done
[[ -d "$ownership_root/etc/dns-sni-unlock" ]] || fail "uninstall deleted configuration after preserving modifications"
[[ -d "$ownership_root/var/lib/dns-sni-unlock" ]] || fail "uninstall deleted ownership state after preserving modifications"
[[ -f "$ownership_root/var/lib/dns-sni-unlock/ownership.manifest" ]] || fail "uninstall deleted ownership manifest after preserving modifications"
rm -rf "$ownership_root"
pass "explicit ownership state preserves administrator-modified managed files and reports incomplete uninstall"

missing_current_root=$(mktemp -d)
missing_current_target="$missing_current_root/etc/managed.conf"
mkdir -p "$missing_current_root/etc" "$missing_current_root/var/lib/dns-sni-unlock/backups"
printf 'current target\n' > "$missing_current_target"
printf 'pre-existing backup\n' > "$missing_current_root/var/lib/dns-sni-unlock/backups/managed.original"
printf 'managed.conf|%s\n' "$missing_current_target" > "$missing_current_root/var/lib/dns-sni-unlock/ownership.manifest"
if DSU_ROOT="$missing_current_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  restore_original_or_remove_managed "$2" managed.conf
' bash "$SCRIPT" "$missing_current_target" >/dev/null 2>&1; then
  fail "restoration succeeded without a managed-current snapshot"
fi
assert_contains "$missing_current_target" 'current target'
rm -rf "$missing_current_root"
pass "fails closed when managed-current ownership proof is missing"

missing_manifest_root=$(mktemp -d)
DSU_ROOT="$missing_manifest_root" DSU_TEST_MODE=1 "$SCRIPT" install --proxy-ip 198.51.100.61 --allow 203.0.113.61 >/dev/null
rm -f \
  "$missing_manifest_root/etc/systemd/system/dns-sni-unlock-firewall.service" \
  "$missing_manifest_root/etc/dnsmasq.d/90-dns-sni-unlock.conf" \
  "$missing_manifest_root/etc/sniproxy.conf" \
  "$missing_manifest_root/usr/local/sbin/dns-sni-unlock" \
  "$missing_manifest_root/var/lib/dns-sni-unlock/ownership.manifest"
if DSU_ROOT="$missing_manifest_root" DSU_TEST_MODE=1 "$SCRIPT" uninstall --yes >/dev/null 2>&1; then
  fail "uninstall claimed success without an ownership manifest"
fi
[[ -d "$missing_manifest_root/etc/dns-sni-unlock" ]] || fail "uninstall deleted configuration without an ownership manifest"
[[ -d "$missing_manifest_root/var/lib/dns-sni-unlock" ]] || fail "uninstall deleted state without an ownership manifest"
rm -rf "$missing_manifest_root"
pass "rejects uninstall with a missing ownership manifest even when targets are absent"

incomplete_manifest_root=$(mktemp -d)
DSU_ROOT="$incomplete_manifest_root" DSU_TEST_MODE=1 "$SCRIPT" install --proxy-ip 198.51.100.62 --allow 203.0.113.62 >/dev/null
incomplete_manifest="$incomplete_manifest_root/var/lib/dns-sni-unlock/ownership.manifest"
incomplete_firewall_unit="$incomplete_manifest_root/etc/systemd/system/dns-sni-unlock-firewall.service"
rm -f "$incomplete_firewall_unit"
printf 'dnsmasq-snippet.conf|%s\nsniproxy.conf|%s\ninstalled-bin|%s\n' \
  "$incomplete_manifest_root/etc/dnsmasq.d/90-dns-sni-unlock.conf" \
  "$incomplete_manifest_root/etc/sniproxy.conf" \
  "$incomplete_manifest_root/usr/local/sbin/dns-sni-unlock" > "$incomplete_manifest"
if DSU_ROOT="$incomplete_manifest_root" DSU_TEST_MODE=1 "$SCRIPT" uninstall --yes >/dev/null 2>&1; then
  fail "uninstall claimed success with an incomplete ownership manifest"
fi
[[ -d "$incomplete_manifest_root/etc/dns-sni-unlock" ]] || fail "uninstall deleted configuration with an incomplete ownership manifest"
[[ -d "$incomplete_manifest_root/var/lib/dns-sni-unlock" ]] || fail "uninstall deleted state with an incomplete ownership manifest"
rm -rf "$incomplete_manifest_root"
pass "rejects uninstall with an incomplete manifest even when its missing target is absent"

atomic_root=$(mktemp -d)
mkdir -p "$atomic_root/mock-bin"
cat > "$atomic_root/mock-bin/chmod" <<'EOF'
#!/bin/sh
exit 72
EOF
chmod +x "$atomic_root/mock-bin/chmod"
if PATH="$atomic_root/mock-bin:$PATH" bash -c '
  source "$1"
  printf data | atomic_replace "$2"
' bash "$SCRIPT" "$atomic_root/result" >/dev/null 2>&1; then
  fail "atomic_replace ignored chmod failure"
fi
[[ ! -e "$atomic_root/result" ]] || fail "atomic_replace left a target after chmod failure"
rm -rf "$atomic_root"
pass "atomic replacement propagates chmod failures"

install_self_root=$(mktemp -d)
mkdir -p "$install_self_root/usr/local/sbin" "$install_self_root/mock-bin"
printf 'existing managed target\n' > "$install_self_root/usr/local/sbin/dns-sni-unlock"
cat > "$install_self_root/mock-bin/install" <<'EOF'
#!/bin/sh
exit 73
EOF
chmod +x "$install_self_root/mock-bin/install"
if PATH="$install_self_root/mock-bin:$PATH" DSU_ROOT="$install_self_root" DSU_TEST_MODE=1 \
  bash -c 'source "$1"; require_root() { :; }; if install_self; then exit 0; else exit 1; fi' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "install_self ignored a failed install command"
fi
rm -rf "$install_self_root"
pass "install_self propagates install failures"

unit_write_root=$(mktemp -d)
mkdir -p "$unit_write_root/etc/systemd/system" "$unit_write_root/mock-bin"
printf 'existing firewall unit\n' > "$unit_write_root/etc/systemd/system/dns-sni-unlock-firewall.service"
cat > "$unit_write_root/mock-bin/mv" <<'EOF'
#!/bin/sh
last=''
for argument do last=$argument; done
if [ "$last" = "$DSU_FAIL_TARGET" ]; then exit 73; fi
exec "$DSU_REAL_MV" "$@"
EOF
chmod +x "$unit_write_root/mock-bin/mv"
if PATH="$unit_write_root/mock-bin:$PATH" DSU_REAL_MV="$(command -v mv)" \
  DSU_FAIL_TARGET="$unit_write_root/etc/systemd/system/dns-sni-unlock-firewall.service" \
  DSU_ROOT="$unit_write_root" DSU_TEST_MODE=1 bash -c 'source "$1"; require_root() { :; }; if write_firewall_unit; then exit 0; else exit 1; fi' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "write_firewall_unit ignored an atomic replacement failure"
fi
rm -rf "$unit_write_root"
pass "write_firewall_unit propagates atomic replacement failures"

runtime_validate_root=$(mktemp -d)
mkdir -p "$runtime_validate_root/mock-bin" "$runtime_validate_root/etc"
printf '%s\n' 'Managed by dns-sni-unlock' > "$runtime_validate_root/etc/sniproxy.conf"
cat > "$runtime_validate_root/mock-bin/dnsmasq" <<'EOF'
#!/bin/sh
exit 73
EOF
chmod +x "$runtime_validate_root/mock-bin/dnsmasq"
if PATH="$runtime_validate_root/mock-bin:$PATH" DSU_ROOT="$runtime_validate_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; if validate_runtime_configs; then exit 0; else exit 1; fi' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "validate_runtime_configs ignored dnsmasq validation failure"
fi
rm -rf "$runtime_validate_root"
pass "validate_runtime_configs propagates configuration test failures"

restart_root=$(mktemp -d)
mkdir -p "$restart_root/mock-bin"
cat > "$restart_root/mock-bin/systemctl" <<'EOF'
#!/bin/sh
[ "$1" = daemon-reload ] && exit 73
exit 0
EOF
chmod +x "$restart_root/mock-bin/systemctl"
if PATH="$restart_root/mock-bin:$PATH" DSU_ROOT="$restart_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; if restart_services; then exit 0; else exit 1; fi' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "restart_services ignored daemon-reload failure"
fi
rm -rf "$restart_root"
pass "restart_services propagates systemctl failures"

apply_snapshot_root=$(mktemp -d)
DSU_ROOT="$apply_snapshot_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
if DSU_ROOT="$apply_snapshot_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  render_configs() { :; }
  validate_runtime_configs() { :; }
  firewall_apply() { :; }
  restart_services() { :; }
  save_service_state() { :; }
  save_firewall_snapshot() { return 73; }
  if apply_all; then exit 0; else exit 1; fi
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "apply_all ignored a firewall snapshot failure"
fi
rm -rf "$apply_snapshot_root"
pass "apply_all propagates firewall snapshot failures"

install_snapshot_root=$(mktemp -d)
printf '%s' "$install_snapshot_root/snapshot.path" > "$install_snapshot_root/capture"
if DSU_ROOT="$install_snapshot_root" DSU_TEST_MODE=1 INSTALL_CAPTURE="$install_snapshot_root/capture" bash -c '
  source "$1"
  snapshot_file() { printf "%s" "$2" > "$INSTALL_CAPTURE"; return 73; }
  save_service_state() { :; }
  save_firewall_snapshot() { :; }
  install_packages() { :; }
  init_config() { :; }
  canonicalize_whitelist_file() { printf "127.0.0.1\\n" > "$2"; }
  install_self() { :; }
  render_configs() { :; }
  write_firewall_unit() { :; }
  validate_runtime_configs() { :; }
  restart_services() { :; }
  doctor() { :; }
  if install_gateway --proxy-ip 198.51.100.80 --allow 203.0.113.80; then exit 0; else exit 1; fi
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "install_gateway ignored an early persistent snapshot failure"
fi
install_snapshot_path=$(cat "$install_snapshot_root/capture")
[[ ! -e "$(dirname "$install_snapshot_path")" ]] || fail "early install snapshot failure left its transaction directory"
rm -rf "$install_snapshot_root"
pass "install cleans up its transaction after an early snapshot failure"

service_state_root=$(mktemp -d)
printf 'dnsmasq|masked|inactive\nsniproxy|enabled-runtime|active\nstatic-unit|static|inactive\n' > "$service_state_root/state"
mkdir -p "$service_state_root/mock-bin"
cat > "$service_state_root/mock-bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_STATE_LOG"
exit 0
EOF
chmod +x "$service_state_root/mock-bin/systemctl"
if PATH="$service_state_root/mock-bin:$PATH" DSU_STATE_LOG="$service_state_root/systemctl.log" \
  bash -c 'source "$1"; if restore_service_state "$2"; then exit 0; else exit 1; fi' bash "$SCRIPT" "$service_state_root/state" >/dev/null 2>&1; then
  fail "restore_service_state claimed exact restoration of an unsupported state"
fi
assert_contains "$service_state_root/systemctl.log" 'mask dnsmasq'
assert_contains "$service_state_root/systemctl.log" 'enable --runtime sniproxy'
rm -rf "$service_state_root"
pass "restore_service_state handles masked/runtime states and rejects unsupported states"

install_rollback_root=$(mktemp -d)
if DSU_ROOT="$install_rollback_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  restore_file_snapshot() { return 75; }
  restore_firewall_snapshot() { return 76; }
  save_firewall_snapshot() { printf snapshot > "$1"; }
  install_packages() { :; }
  validate_runtime_configs() { :; }
  restart_services() { return 74; }
  doctor() { :; }
  if install_gateway --proxy-ip 198.51.100.81 --allow 203.0.113.81; then exit 0; else exit 1; fi
' bash "$SCRIPT" >"$install_rollback_root/output" 2>&1; then
  fail "install succeeded after restart failure"
fi
assert_contains "$install_rollback_root/output" 'UNSAFE STATE'
assert_contains "$install_rollback_root/output" 'install transaction directory:'
install_rollback_txdir=$(sed $'s/\033\[[0-9;]*m//g' "$install_rollback_root/output" | sed -n 's/.*install transaction directory: \([^ ]*\).*/\1/p')
[[ -d "$install_rollback_txdir" ]] || fail "install deleted evidence after firewall rollback failure"
[[ -f "$install_rollback_txdir/firewall.before" ]] || fail "install did not retain the exact firewall snapshot"
rm -rf "$install_rollback_root"
pass "install reports file rollback failures loudly and retains firewall evidence"

service_state_validation_root=$(mktemp -d)
mkdir -p "$service_state_validation_root/mock-bin"
cat > "$service_state_validation_root/mock-bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$DSU_BAD_STATE"
exit 1
EOF
chmod +x "$service_state_validation_root/mock-bin/systemctl"
for bad_service_state in not-found mystery-state; do
  if PATH="$service_state_validation_root/mock-bin:$PATH" \
    DSU_BAD_STATE="$bad_service_state" DSU_TEST_SYSTEMCTL=1 DSU_TEST_MODE=1 \
    bash -c 'source "$1"; save_service_state "$2"' bash "$SCRIPT" "$service_state_validation_root/$bad_service_state" >/dev/null 2>&1; then
    fail "save_service_state accepted unsupported state: $bad_service_state"
  fi
done
rm -rf "$service_state_validation_root"
pass "rejects not-found and unknown systemd states before installation"

render_helper_root=$(mktemp -d)
DSU_ROOT="$render_helper_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
if DSU_ROOT="$render_helper_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  generate_config_files() { :; }
  backup_unmanaged_file() { return 73; }
  snapshot_file() { :; }
  atomic_replace() { :; }
  record_managed_file() { :; }
  if render_configs; then exit 0; else exit 1; fi
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "render_configs ignored backup_unmanaged_file failure"
fi
rm -rf "$render_helper_root"
pass "render_configs propagates backup and snapshot failures"

for tx_command in \
  'service_add NewRoute 198.51.100.82 new-route.example' \
  'service_remove OpenAI' \
  'service_set_ip OpenAI 198.51.100.82' \
  'firewall_add 203.0.113.82' \
  'firewall_delete 203.0.113.82'; do
  tx_helper_root=$(mktemp -d)
  DSU_ROOT="$tx_helper_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
  if DSU_ROOT="$tx_helper_root" TX_COMMAND="$tx_command" bash -c '
    source "$1"
    printf "203.0.113.82\\n" >> "$WHITELIST_FILE"
    snapshot_file() { return 73; }
    apply_all() { :; }
    if eval "$TX_COMMAND"; then exit 0; else exit 1; fi
  ' bash "$SCRIPT" >/dev/null 2>&1; then
    fail "$tx_command ignored snapshot_file failure"
  fi
  rm -rf "$tx_helper_root"
done
pass "service and firewall mutations propagate source snapshot failures"

uninstall_helper_root=$(mktemp -d)
DSU_ROOT="$uninstall_helper_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
if DSU_ROOT="$uninstall_helper_root" bash -c '
  source "$1"
  restore_original_or_remove_managed() { return 73; }
  if uninstall_gateway --yes; then exit 0; else exit 1; fi
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "uninstall ignored restore_original_or_remove_managed failure"
fi
rm -rf "$uninstall_helper_root"
pass "uninstall propagates managed-file restore failures"


duplicate_root=$(mktemp -d)
DSU_ROOT="$duplicate_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
duplicate_services="$duplicate_root/etc/dns-sni-unlock/services.conf"
printf 'Duplicate|198.51.100.61|duplicate-a.example\nDuplicate|198.51.100.62|duplicate-b.example\n' >> "$duplicate_services"
if DSU_ROOT="$duplicate_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null 2>&1; then
  fail "parse_services accepted duplicate service names"
fi
rm -rf "$duplicate_root"
pass "rejects duplicate service names already present in services.conf"

duplicate_domain_root=$(mktemp -d)
DSU_ROOT="$duplicate_domain_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
duplicate_domain_services="$duplicate_domain_root/etc/dns-sni-unlock/services.conf"
printf 'DuplicateDomain|198.51.100.61|Example.com example.com.\n' >> "$duplicate_domain_services"
if DSU_ROOT="$duplicate_domain_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null 2>&1; then
  fail "parse_services accepted duplicate normalized domains with the same IP"
fi
rm -rf "$duplicate_domain_root"
pass "rejects duplicate normalized domains even when the proxy IP matches"

overlap_root=$(mktemp -d)
DSU_ROOT="$overlap_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
overlap_services="$overlap_root/etc/dns-sni-unlock/services.conf"
printf 'Ancestor|198.51.100.63|example.net\nDescendant|198.51.100.64|foo.example.net\n' >> "$overlap_services"
if DSU_ROOT="$overlap_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null 2>&1; then
  fail "render accepted overlapping routes with different proxy IPs"
fi
printf 'SameA|198.51.100.65|same.example.net\nSameB|198.51.100.65|foo.same.example.net\n' > "$overlap_services"
DSU_ROOT="$overlap_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
rm -rf "$overlap_root"
pass "rejects conflicting ancestor routes and accepts same-IP overlap"

canonical_root=$(mktemp -d)
DSU_ROOT="$canonical_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
canonical_whitelist="$canonical_root/etc/dns-sni-unlock/whitelist.conf"
printf '203.0.113.7/24 # old spelling\n203.0.113.0/24 # duplicate\n' > "$canonical_whitelist"
DSU_ROOT="$canonical_root" DSU_TEST_MODE=1 "$SCRIPT" firewall add 203.0.113.7/24 >/dev/null
[[ "$(grep -Fxc '203.0.113.0/24' "$canonical_whitelist")" == 1 ]] || fail "firewall add did not canonicalize and deduplicate CIDR"
DSU_ROOT="$canonical_root" DSU_TEST_MODE=1 "$SCRIPT" firewall remove 203.0.113.7/24 >/dev/null
assert_not_contains "$canonical_whitelist" '203.0.113.'
rm -rf "$canonical_root"
pass "canonicalizes, deduplicates, and stably removes equivalent CIDR entries"

$SCRIPT --help > "$sandbox/help.txt"
assert_contains "$sandbox/help.txt" 'install --allow <IPv4/CIDR>'
assert_contains "$sandbox/help.txt" 'firewall add <IPv4/CIDR>'
assert_contains "$sandbox/help.txt" 'uninstall'
pass "documents the supported command interface"

assert_contains "$ROOT_DIR/README.md" 'curl --connect-to openai.com:443:198.51.100.20:443 https://openai.com/'
pass "README verifies a domain present in the default SNIProxy table"

assert_contains "$ROOT_DIR/README.md" '> [!WARNING]'
assert_contains "$ROOT_DIR/README.md" 'https://github.com/dlundquist/sniproxy#status-deprecated'
assert_contains "$ROOT_DIR/README.md" 'HTTP/2 routing, HTTP/3/QUIC, security, and maintenance limitations'
pass "README prominently warns that upstream SNIProxy is deprecated"

assert_not_contains "$ROOT_DIR/README.md" 'SNIProxy 只读取 TLS ClientHello 中的服务器名称；'
assert_contains "$ROOT_DIR/README.md" 'HTTP Host'
pass "README accurately describes both HTTP Host and TLS ClientHello routing"

assert_contains "$ROOT_DIR/SECURITY.md" 'HTTP Host'
assert_contains "$ROOT_DIR/SECURITY.md" 'TLS ClientHello SNI'
pass "documents HTTP Host routing as well as TLS SNI routing"

if grep -Eq 'tmp="\$\{target\}\.tmp\.\$\$"|manifest_tmp="\$\{OWNERSHIP_MANIFEST\}\.record\.\$\$"|tmp="\$\{output\}\.tmp\.\$\$"' "$SCRIPT"; then
  fail "predictable $$ temporary filename remains in a transactional helper"
fi
pass "uses securely created temporary files for transactional replacements"

uninstall_preserve_root=$(mktemp -d)
DSU_ROOT="$uninstall_preserve_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$uninstall_preserve_root/var/lib/dns-sni-unlock/backups"
printf 'recovery material\n' > "$uninstall_preserve_root/var/lib/dns-sni-unlock/backups/keep.me"
if DSU_ROOT="$uninstall_preserve_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  restore_original_or_remove_managed() { return 73; }
  uninstall_gateway --yes
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "uninstall succeeded after a managed-file restore failure"
fi
[[ -d "$uninstall_preserve_root/etc/dns-sni-unlock" ]] || fail "uninstall deleted CONFIG_DIR after restore failure"
[[ -d "$uninstall_preserve_root/var/lib/dns-sni-unlock" ]] || fail "uninstall deleted STATE_DIR after restore failure"
[[ -f "$uninstall_preserve_root/var/lib/dns-sni-unlock/backups/keep.me" ]] || fail "uninstall deleted ownership recovery material after restore failure"
rm -rf "$uninstall_preserve_root"
pass "retains configuration, state, and recovery materials after restore failure"

firewall_missing_root=$(mktemp -d)
mkdir -p "$firewall_missing_root/mock-bin"
printf '#!/bin/sh\nexit 0\n' > "$firewall_missing_root/mock-bin/iptables-save"
printf '#!/bin/sh\nexit 0\n' > "$firewall_missing_root/mock-bin/iptables-restore"
chmod +x "$firewall_missing_root/mock-bin/iptables-save" "$firewall_missing_root/mock-bin/iptables-restore"
if PATH="$firewall_missing_root/mock-bin" DSU_ROOT="$firewall_missing_root" DSU_TEST_MODE=0 \
  /bin/bash -c 'source "$1"; require_root() { :; }; firewall_remove' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall_remove succeeded while iptables was unavailable"
fi
rm -rf "$firewall_missing_root"
pass "fails closed when iptables is unavailable"

firewall_idempotent_root=$(mktemp -d)
mkdir -p "$firewall_idempotent_root/mock-bin"
printf '%s\n' '#!/bin/sh' 'printf "*filter\\n:INPUT ACCEPT [0:0]\\nCOMMIT\\n"' > "$firewall_idempotent_root/mock-bin/iptables-save"
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' 'case "$1:$2" in' '  -L:DNS_SNI_UNLOCK_IN) exit 1 ;;' '  -S:INPUT) exit 0 ;;' '  *) exit 1 ;;' 'esac' > "$firewall_idempotent_root/mock-bin/iptables"
printf '%s\n' '#!/bin/sh' 'cat >/dev/null' 'exit 0' > "$firewall_idempotent_root/mock-bin/iptables-restore"
chmod +x "$firewall_idempotent_root/mock-bin/iptables-save" "$firewall_idempotent_root/mock-bin/iptables" "$firewall_idempotent_root/mock-bin/iptables-restore"
if ! PATH="$firewall_idempotent_root/mock-bin:$PATH" DSU_ROOT="$firewall_idempotent_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; require_root() { :; }; firewall_remove; firewall_remove' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall clear was not idempotent after the owned chain was already cleared"
fi
rm -rf "$firewall_idempotent_root"
pass "treats an already-cleared owned firewall chain as a successful idempotent clear"

install_service_state_root=$(mktemp -d)
mkdir -p "$install_service_state_root/var/lib/dns-sni-unlock"
printf 'pre-existing state\n' > "$install_service_state_root/var/lib/dns-sni-unlock/keep.me"
if DSU_ROOT="$install_service_state_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  install_packages() { :; }
  doctor() { return 74; }
  install_gateway --proxy-ip 198.51.100.90 --allow 203.0.113.90
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "install succeeded after a later failure"
fi
[[ ! -e "$install_service_state_root/var/lib/dns-sni-unlock/service-state" ]] || fail "failed install left a newly created service-state file"
assert_contains "$install_service_state_root/var/lib/dns-sni-unlock/keep.me" 'pre-existing state'
rm -rf "$install_service_state_root"
pass "restores the service-state file exactly after install failure"

install_cleanup_root=$(mktemp -d)
mkdir -p "$install_cleanup_root/mock-bin"
cat > "$install_cleanup_root/mock-bin/rm" <<'EOF'
#!/bin/sh
for argument do
  [ "$argument" = "$DSU_FAIL_CONFIG" ] && exit 77
  [ "$argument" = "$DSU_FAIL_STATE" ] && exit 78
done
exec "$DSU_REAL_RM" "$@"
EOF
chmod +x "$install_cleanup_root/mock-bin/rm"
install_cleanup_real_rm=$(command -v rm)
if PATH="$install_cleanup_root/mock-bin:$PATH" \
  DSU_REAL_RM="$install_cleanup_real_rm" \
  DSU_FAIL_CONFIG="$install_cleanup_root/etc/dns-sni-unlock" \
  DSU_FAIL_STATE="$install_cleanup_root/var/lib/dns-sni-unlock" \
  DSU_ROOT="$install_cleanup_root" DSU_TEST_MODE=1 bash -c '
    source "$1"
    install_packages() { :; }
    doctor() { return 74; }
    install_gateway --proxy-ip 198.51.100.92 --allow 203.0.113.92
  ' bash "$SCRIPT" >"$install_cleanup_root/output" 2>&1; then
  fail "install succeeded after rollback directory cleanup failures"
fi
assert_contains "$install_cleanup_root/output" 'CONFIG_DIR'
assert_contains "$install_cleanup_root/output" 'STATE_DIR'
assert_contains "$install_cleanup_root/output" 'install transaction evidence retained at'
install_cleanup_txdir=$(sed $'s/\033\[[0-9;]*m//g' "$install_cleanup_root/output" | sed -n 's/.*install transaction evidence retained at \([^ ]*\).*/\1/p')
[[ -d "$install_cleanup_txdir" ]] || fail "install deleted transaction evidence after directory cleanup failures"
rm -rf "$install_cleanup_root"
pass "classifies CONFIG_DIR and STATE_DIR rollback cleanup failures and retains evidence"

firewall_goto_root=$(mktemp -d)
DSU_ROOT="$firewall_goto_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
DSU_ROOT="$firewall_goto_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
mkdir -p "$firewall_goto_root/mock-bin"
cat > "$firewall_goto_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:UNMANAGED ACCEPT [0:0]
:DNS_SNI_UNLOCK_IN - [0:0]
-A UNMANAGED -g DNS_SNI_UNLOCK_IN
-A INPUT -j DNS_SNI_UNLOCK_IN
COMMIT
RULES
EOF
cat > "$firewall_goto_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
case "$1:$2" in
  -L:DNS_SNI_UNLOCK_IN) exit 0 ;;
  -S:DNS_SNI_UNLOCK_IN)
    printf '%s\n' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p udp --dport 53 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p tcp -m multiport --dports 53,80,443 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -p udp --dport 53 -j DROP' '-A DNS_SNI_UNLOCK_IN -p tcp -m multiport --dports 53,80,443 -j DROP' '-A DNS_SNI_UNLOCK_IN -j RETURN' ;;
  -S:INPUT) printf '%s\n' '-A INPUT -j DNS_SNI_UNLOCK_IN' ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$firewall_goto_root/mock-bin/iptables" "$firewall_goto_root/mock-bin/iptables-save"
if PATH="$firewall_goto_root/mock-bin:$PATH" DSU_ROOT="$firewall_goto_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; require_root() { :; }; doctor_firewall' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "doctor accepted an unmanaged goto reference to the dedicated chain"
fi
rm -rf "$firewall_goto_root"
pass "doctor rejects unmanaged jump and goto references to the dedicated chain"

input_goto_root=$(mktemp -d)
printf '%s\n' '-A INPUT -j ACCEPT' '-A INPUT -g DNS_SNI_UNLOCK_IN' > "$input_goto_root/rules"
if bash -c 'source "$1"; firewall_chain_has_unmanaged_reference "$2"' bash "$SCRIPT" "$input_goto_root/rules"; then
  fail "firewall reference check ignored an unmanaged INPUT goto"
fi
rm -rf "$input_goto_root"
pass "rejects unmanaged INPUT goto references while allowing only the owned jump"

doctor_bypass_root=$(mktemp -d)
DSU_ROOT="$doctor_bypass_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
DSU_ROOT="$doctor_bypass_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
mkdir -p "$doctor_bypass_root/mock-bin"
cat > "$doctor_bypass_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' ':DNS_SNI_UNLOCK_IN - [0:0]' '-A INPUT -j DNS_SNI_UNLOCK_IN' 'COMMIT'
EOF
cat > "$doctor_bypass_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
case "$1:$2" in
  -L:DNS_SNI_UNLOCK_IN) exit 0 ;;
  -S:DNS_SNI_UNLOCK_IN)
    printf '%s\n' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p udp --dport 53 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p tcp -m multiport --dports 53,80,443 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -p tcp --dport 443 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -p udp --dport 53 -j DROP' '-A DNS_SNI_UNLOCK_IN -p tcp -m multiport --dports 53,80,443 -j DROP' '-A DNS_SNI_UNLOCK_IN -j RETURN' ;;
  -S:INPUT) printf '%s\n' '-A INPUT -j DNS_SNI_UNLOCK_IN' ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$doctor_bypass_root/mock-bin/iptables" "$doctor_bypass_root/mock-bin/iptables-save"
if PATH="$doctor_bypass_root/mock-bin:$PATH" DSU_ROOT="$doctor_bypass_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; require_root() { :; }; doctor_firewall' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "doctor accepted an extra dedicated-chain ACCEPT bypass rule"
fi
rm -rf "$doctor_bypass_root"
pass "doctor rejects extra dedicated-chain bypass rules"

uninstall_firewall_root=$(mktemp -d)
DSU_ROOT="$uninstall_firewall_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$uninstall_firewall_root/var/lib/dns-sni-unlock/backups"
printf 'keep for recovery\n' > "$uninstall_firewall_root/var/lib/dns-sni-unlock/backups/firewall-failure"
if DSU_ROOT="$uninstall_firewall_root" DSU_TEST_MODE=0 bash -c '
  source "$1"
  systemctl() { return 0; }
  firewall_remove() { return 73; }
  uninstall_gateway --yes
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "uninstall succeeded after firewall clear failure"
fi
[[ -d "$uninstall_firewall_root/etc/dns-sni-unlock" ]] || fail "uninstall deleted CONFIG_DIR after firewall clear failure"
[[ -d "$uninstall_firewall_root/var/lib/dns-sni-unlock" ]] || fail "uninstall deleted STATE_DIR after firewall clear failure"
[[ -f "$uninstall_firewall_root/var/lib/dns-sni-unlock/backups/firewall-failure" ]] || fail "uninstall deleted recovery material after firewall clear failure"
rm -rf "$uninstall_firewall_root"
pass "retains state when firewall clear fails during uninstall"

firewall_apply_cleanup_root=$(mktemp -d)
DSU_ROOT="$firewall_apply_cleanup_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$firewall_apply_cleanup_root/mock-bin"
cat > "$firewall_apply_cleanup_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
printf '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n'
EOF
cat > "$firewall_apply_cleanup_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_FW_LOG"
case "$1" in
  -L) exit 0 ;;
  -S)
    if [ "$2" = "DNS_SNI_UNLOCK_IN" ]; then
      printf '%s\n' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p udp --dport 53 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p tcp -m multiport --dports 53,80,443 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -p udp --dport 53 -j DROP' '-A DNS_SNI_UNLOCK_IN -p tcp -m multiport --dports 53,80,443 -j DROP' '-A DNS_SNI_UNLOCK_IN -j RETURN'
    else
      printf '%s\n' '-A INPUT -j DNS_SNI_UNLOCK_IN'
    fi
    ;;
  -C) exit 0 ;;
  *) exit 0 ;;
esac
EOF
cat > "$firewall_apply_cleanup_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
cat >/dev/null
exit 0
EOF
cat > "$firewall_apply_cleanup_root/mock-bin/rm" <<'EOF'
#!/bin/sh
exit 73
EOF
chmod +x "$firewall_apply_cleanup_root/mock-bin/iptables-save" \
  "$firewall_apply_cleanup_root/mock-bin/iptables" \
  "$firewall_apply_cleanup_root/mock-bin/iptables-restore" \
  "$firewall_apply_cleanup_root/mock-bin/rm"
if ! PATH="$firewall_apply_cleanup_root/mock-bin:$PATH" \
  DSU_FW_LOG="$firewall_apply_cleanup_root/firewall.log" \
  DSU_ROOT="$firewall_apply_cleanup_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; require_root() { :; }; firewall_apply' bash "$SCRIPT" \
  >"$firewall_apply_cleanup_root/output" 2>&1; then
  fail "firewall apply reported failure after a successful commit and cleanup failure"
fi
assert_contains "$firewall_apply_cleanup_root/output" 'could not clean up temporary file'
assert_contains "$firewall_apply_cleanup_root/firewall.log" '-I INPUT 1 -j DNS_SNI_UNLOCK_IN_NEW_'
rm -rf "$firewall_apply_cleanup_root"
pass "firewall apply succeeds after commit when temporary cleanup fails"

firewall_remove_cleanup_root=$(mktemp -d)
mkdir -p "$firewall_remove_cleanup_root/var/lib/dns-sni-unlock" "$firewall_remove_cleanup_root/mock-bin"
printf 'Managed by dns-sni-unlock firewall chain DNS_SNI_UNLOCK_IN\n' > "$firewall_remove_cleanup_root/var/lib/dns-sni-unlock/firewall.ownership"
cat > "$firewall_remove_cleanup_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
if [ -e "$DSU_CLEARED" ]; then
  printf '*filter\n:INPUT ACCEPT [0:0]\n:DNS_SNI_UNLOCK_IN - [0:0]\nCOMMIT\n'
else
  printf '*filter\n:INPUT ACCEPT [0:0]\n:DNS_SNI_UNLOCK_IN - [0:0]\n-A INPUT -j DNS_SNI_UNLOCK_IN\nCOMMIT\n'
fi
EOF
cat > "$firewall_remove_cleanup_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_FW_LOG"
case "$1:$2" in
  -S:INPUT) printf '%s\n' '-A INPUT -j DNS_SNI_UNLOCK_IN' ;;
  -D:INPUT) : > "$DSU_CLEARED" ;;
  *) exit 0 ;;
esac
EOF
cat > "$firewall_remove_cleanup_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
cat >/dev/null
exit 0
EOF
cat > "$firewall_remove_cleanup_root/mock-bin/rm" <<'EOF'
#!/bin/sh
if [ ! -e "$DSU_RM_MARKER" ]; then
  : > "$DSU_RM_MARKER"
  exit 0
fi
exit 73
EOF
chmod +x "$firewall_remove_cleanup_root/mock-bin/iptables-save" \
  "$firewall_remove_cleanup_root/mock-bin/iptables" \
  "$firewall_remove_cleanup_root/mock-bin/iptables-restore" \
  "$firewall_remove_cleanup_root/mock-bin/rm"
if ! PATH="$firewall_remove_cleanup_root/mock-bin:$PATH" \
  DSU_FW_LOG="$firewall_remove_cleanup_root/firewall.log" \
  DSU_RM_MARKER="$firewall_remove_cleanup_root/rm.marker" \
  DSU_CLEARED="$firewall_remove_cleanup_root/cleared" \
  DSU_ROOT="$firewall_remove_cleanup_root" DSU_TEST_MODE=0 \
  bash -c 'source "$1"; require_root() { :; }; firewall_remove' bash "$SCRIPT" \
  >"$firewall_remove_cleanup_root/output" 2>&1; then
  fail "firewall remove reported failure after a successful commit and cleanup failure"
fi
assert_contains "$firewall_remove_cleanup_root/output" 'could not clean up temporary file'
assert_contains "$firewall_remove_cleanup_root/firewall.log" '-F DNS_SNI_UNLOCK_IN'
assert_contains "$firewall_remove_cleanup_root/firewall.log" '-X DNS_SNI_UNLOCK_IN'
rm -rf "$firewall_remove_cleanup_root"
pass "firewall remove succeeds after commit when temporary cleanup fails"

restore_snapshot_root=$(mktemp -d)
printf 'snapshot bytes\n' > "$restore_snapshot_root/source"
chmod 0600 "$restore_snapshot_root/source"
printf 'target bytes\n' > "$restore_snapshot_root/target"
chmod 0644 "$restore_snapshot_root/target"
DSU_RESTORE_SNAPSHOT="$restore_snapshot_root/snapshot"
DSU_RESTORE_TARGET="$restore_snapshot_root/target"
inode_of() {
  if stat -c '%i' "$1" >/dev/null 2>&1; then
    stat -c '%i' "$1"
  else
    stat -f '%i' "$1"
  fi
}
mode_of() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}
# shellcheck disable=SC1090
source "$SCRIPT"
snapshot_file "$restore_snapshot_root/source" "$DSU_RESTORE_SNAPSHOT"
restore_inode_before=$(inode_of "$DSU_RESTORE_TARGET")
restore_file_snapshot "$DSU_RESTORE_SNAPSHOT" "$DSU_RESTORE_TARGET"
restore_inode_after=$(inode_of "$DSU_RESTORE_TARGET")
[[ "$restore_inode_before" != "$restore_inode_after" ]] || fail "file snapshot restore reused the existing target inode"
assert_contains "$DSU_RESTORE_TARGET" 'snapshot bytes'
restore_mode=$(mode_of "$DSU_RESTORE_TARGET")
[[ "$restore_mode" == 600 ]] || fail "file snapshot restore did not restore the exact mode: $restore_mode"
rm -rf "$restore_snapshot_root"
pass "restores regular file snapshots by exact replacement with mode"

symlink_snapshot_root=$(mktemp -d)
ln -s 'missing-target' "$symlink_snapshot_root/source-link"
printf 'target bytes\n' > "$symlink_snapshot_root/target"
snapshot_file "$symlink_snapshot_root/source-link" "$symlink_snapshot_root/link.snapshot"
restore_file_snapshot "$symlink_snapshot_root/link.snapshot" "$symlink_snapshot_root/target"
[[ -L "$symlink_snapshot_root/target" ]] || fail "symlink snapshot restore changed the target into a regular file"
[[ "$(readlink "$symlink_snapshot_root/target")" == 'missing-target' ]] || fail "symlink snapshot restore changed the link target"
rm -rf "$symlink_snapshot_root"
pass "restores dangling symlink snapshots as symlinks"

allowlist_host_root=$(mktemp -d)
DSU_ROOT="$allowlist_host_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
allowlist_host_file="$allowlist_host_root/etc/dns-sni-unlock/whitelist.conf"
printf '203.0.113.7\n203.0.113.7/32\n' > "$allowlist_host_file"
DSU_ROOT="$allowlist_host_root" DSU_TEST_MODE=1 "$SCRIPT" firewall add 203.0.113.7/32 >/dev/null
[[ "$(grep -Fxc '203.0.113.7' "$allowlist_host_file")" == 1 ]] || fail "allowlist did not retain one canonical host entry"
assert_not_contains "$allowlist_host_file" '203.0.113.7/32'
rm -rf "$allowlist_host_root"
pass "canonicalizes equivalent host and /32 allowlist entries"

whitespace_domain_root=$(mktemp -d)
DSU_ROOT="$whitespace_domain_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
whitespace_domain_services="$whitespace_domain_root/etc/dns-sni-unlock/services.conf"
printf 'ValidRoute|198.51.100.91|valid.example\nWhitespaceRoute|198.51.100.92|   \n' > "$whitespace_domain_services"
if DSU_ROOT="$whitespace_domain_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null 2>&1; then
  fail "parse_services accepted a whitespace-only domain field"
fi
rm -rf "$whitespace_domain_root"
pass "rejects whitespace-only domain fields even when other routes exist"

wildcard_domain_root=$(mktemp -d)
DSU_ROOT="$wildcard_domain_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
printf 'WildcardRoute|198.51.100.93|*.example\n' > "$wildcard_domain_root/etc/dns-sni-unlock/services.conf"
: > "$wildcard_domain_root/matched.example"
if ! (cd "$wildcard_domain_root" && DSU_ROOT="$wildcard_domain_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null 2>&1); then
  :
else
  rm -rf "$wildcard_domain_root"
  fail "parse_services accepted a wildcard after pathname expansion"
fi
rm -rf "$wildcard_domain_root"
pass "keeps wildcard domains literal for validation"

symlink_backup_root=$(mktemp -d)
mkdir -p "$symlink_backup_root/etc/dnsmasq.d"
ln -s 'missing-dnsmasq-target' "$symlink_backup_root/etc/dnsmasq.d/90-dns-sni-unlock.conf"
DSU_ROOT="$symlink_backup_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
DSU_ROOT="$symlink_backup_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
symlink_backup="$symlink_backup_root/var/lib/dns-sni-unlock/backups/dnsmasq-snippet.conf.original"
[[ -L "$symlink_backup" ]] || fail "render did not back up the dangling unmanaged symlink"
DSU_ROOT="$symlink_backup_root" DSU_TEST_MODE=1 "$SCRIPT" uninstall --yes >/dev/null
[[ -L "$symlink_backup_root/etc/dnsmasq.d/90-dns-sni-unlock.conf" ]] || fail "uninstall did not restore the dangling unmanaged symlink"
[[ "$(readlink "$symlink_backup_root/etc/dnsmasq.d/90-dns-sni-unlock.conf")" == 'missing-dnsmasq-target' ]] || fail "uninstall changed the dangling symlink target"
rm -rf "$symlink_backup_root"
pass "backs up and restores dangling unmanaged symlinks through render and uninstall"

backup_rollback_root=$(mktemp -d)
mkdir -p "$backup_rollback_root/etc/dns-sni-unlock" "$backup_rollback_root/etc/dnsmasq.d"
backup_rollback_services="$backup_rollback_root/etc/dns-sni-unlock/services.conf"
backup_rollback_whitelist="$backup_rollback_root/etc/dns-sni-unlock/whitelist.conf"
backup_rollback_dnsmasq="$backup_rollback_root/etc/dnsmasq.d/90-dns-sni-unlock.conf"
backup_rollback_sniproxy="$backup_rollback_root/etc/sniproxy.conf"
printf '# source services\nOpenAI|127.0.0.1|openai.com\n' > "$backup_rollback_services"
printf '# source whitelist\n127.0.0.1\n' > "$backup_rollback_whitelist"
printf 'dnsmasq before failed render\n' > "$backup_rollback_dnsmasq"
printf 'sniproxy before failed render\n' > "$backup_rollback_sniproxy"
mkdir -p "$backup_rollback_root/mock-bin"
cat > "$backup_rollback_root/mock-bin/mv" <<'EOF'
#!/bin/sh
last=''
for argument do last=$argument; done
if [ "$last" = "$DSU_FAIL_TARGET" ] && [ ! -e "$DSU_FAIL_ONCE" ]; then
  : > "$DSU_FAIL_ONCE"
  exit 73
fi
exec "$DSU_REAL_MV" "$@"
EOF
chmod +x "$backup_rollback_root/mock-bin/mv"
backup_rollback_real_mv=$(command -v mv)
if PATH="$backup_rollback_root/mock-bin:$PATH" \
  DSU_REAL_MV="$backup_rollback_real_mv" \
  DSU_FAIL_TARGET="$backup_rollback_sniproxy" \
  DSU_FAIL_ONCE="$backup_rollback_root/mv.failed" \
  DSU_ROOT="$backup_rollback_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null 2>&1; then
  fail "render succeeded after injected failure with unmanaged configurations"
fi
printf 'dnsmasq latest pre-takeover\n' > "$backup_rollback_dnsmasq"
printf 'sniproxy latest pre-takeover\n' > "$backup_rollback_sniproxy"
DSU_ROOT="$backup_rollback_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
DSU_ROOT="$backup_rollback_root" DSU_TEST_MODE=1 "$SCRIPT" uninstall --yes >/dev/null
assert_contains "$backup_rollback_dnsmasq" 'dnsmasq latest pre-takeover'
assert_contains "$backup_rollback_sniproxy" 'sniproxy latest pre-takeover'
rm -rf "$backup_rollback_root"
pass "rolls back failed-render backups before later takeover and uninstall"

candidate_write_root=$(mktemp -d)
DSU_ROOT="$candidate_write_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
if DSU_ROOT="$candidate_write_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  printf() {
    case "$1" in
      "address=/%s/%s\\n") return 73 ;;
      *) builtin printf "$@" ;;
    esac
  }
  generate_config_files "$2/dnsmasq" "$2/sniproxy"
' bash "$SCRIPT" "$candidate_write_root" >/dev/null 2>&1; then
  fail "generate_config_files ignored an intermediate candidate printf failure"
fi
rm -rf "$candidate_write_root"
pass "propagates intermediate candidate printf failures"

admin_jump_root=$(mktemp -d)
DSU_ROOT="$admin_jump_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$admin_jump_root/mock-bin"
cat > "$admin_jump_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:DNS_SNI_UNLOCK_IN - [0:0]
-A INPUT -j DNS_SNI_UNLOCK_IN
COMMIT
RULES
EOF
cat > "$admin_jump_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_FW_LOG"
exit 0
EOF
cat > "$admin_jump_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
cat >/dev/null
exit 0
EOF
chmod +x "$admin_jump_root/mock-bin/iptables-save" "$admin_jump_root/mock-bin/iptables" "$admin_jump_root/mock-bin/iptables-restore"
if PATH="$admin_jump_root/mock-bin:$PATH" DSU_FW_LOG="$admin_jump_root/firewall.log" \
  DSU_ROOT="$admin_jump_root" DSU_TEST_MODE=0 bash -c 'source "$1"; require_root() { :; }; firewall_apply' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall apply treated an administrator exact INPUT jump as tool-owned without proof"
fi
assert_not_contains "$admin_jump_root/firewall.log" '-D INPUT -j DNS_SNI_UNLOCK_IN'
rm -rf "$admin_jump_root"
pass "requires persistent firewall ownership proof before replacing an exact jump"

final_verify_root=$(mktemp -d)
DSU_ROOT="$final_verify_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$final_verify_root/mock-bin"
cat > "$final_verify_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
printf '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n'
EOF
cat > "$final_verify_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_FW_LOG"
case "$1:$2" in
  -L:DNS_SNI_UNLOCK_IN)
    if [ ! -e "$DSU_CHAIN_SEEN" ]; then : > "$DSU_CHAIN_SEEN"; exit 1; fi
    exit 0 ;;
  -S:DNS_SNI_UNLOCK_IN)
    printf '%s\n' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p udp --dport 53 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p tcp -m multiport --dports 53,80,443 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -p tcp --dport 443 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -p udp --dport 53 -j DROP' '-A DNS_SNI_UNLOCK_IN -p tcp -m multiport --dports 53,80,443 -j DROP' '-A DNS_SNI_UNLOCK_IN -j RETURN' ;;
  -S:INPUT) printf '%s\n' '-A INPUT -j DNS_SNI_UNLOCK_IN' ;;
  *) exit 0 ;;
esac
EOF
cat > "$final_verify_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
printf 'restored\n' >> "$DSU_FW_LOG"
cat >/dev/null
EOF
chmod +x "$final_verify_root/mock-bin/iptables-save" "$final_verify_root/mock-bin/iptables" "$final_verify_root/mock-bin/iptables-restore"
if PATH="$final_verify_root/mock-bin:$PATH" DSU_FW_LOG="$final_verify_root/firewall.log" DSU_CHAIN_SEEN="$final_verify_root/chain-seen" \
  DSU_ROOT="$final_verify_root" DSU_TEST_MODE=0 bash -c 'source "$1"; require_root() { :; }; firewall_apply' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall apply succeeded with an extra dedicated-chain rule"
fi
assert_contains "$final_verify_root/firewall.log" 'restored'
rm -rf "$final_verify_root"
pass "rolls back when final firewall chain verification finds an extra rule"

race_root=$(mktemp -d)
DSU_ROOT="$race_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$race_root/var/lib/dns-sni-unlock" "$race_root/mock-bin"
printf 'Managed by dns-sni-unlock firewall chain DNS_SNI_UNLOCK_IN\n' > "$race_root/var/lib/dns-sni-unlock/firewall.ownership"
cat > "$race_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
if [ ! -e "$DSU_RECHECK" ]; then
  : > "$DSU_RECHECK"
  printf '*filter\n:INPUT ACCEPT [0:0]\n:DNS_SNI_UNLOCK_IN - [0:0]\n-A INPUT -j DNS_SNI_UNLOCK_IN\nCOMMIT\n'
else
  printf '*filter\n:INPUT ACCEPT [0:0]\n:ADMIN ACCEPT [0:0]\n:DNS_SNI_UNLOCK_IN - [0:0]\n-A ADMIN -j DNS_SNI_UNLOCK_IN\nCOMMIT\n'
fi
EOF
cat > "$race_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_FW_LOG"
exit 0
EOF
cat > "$race_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
cat >/dev/null
exit 0
EOF
chmod +x "$race_root/mock-bin/iptables-save" "$race_root/mock-bin/iptables" "$race_root/mock-bin/iptables-restore"
if PATH="$race_root/mock-bin:$PATH" DSU_FW_LOG="$race_root/firewall.log" DSU_RECHECK="$race_root/recheck" \
  DSU_ROOT="$race_root" DSU_TEST_MODE=0 bash -c 'source "$1"; require_root() { :; }; firewall_apply' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall apply ignored a concurrent old-chain reference"
fi
assert_not_contains "$race_root/firewall.log" '-E DNS_SNI_UNLOCK_IN DNS_SNI_UNLOCK_IN_OLD_'
rm -rf "$race_root"
pass "rechecks live references before renaming the old dedicated chain"

failed_state_root=$(mktemp -d)
printf 'dnsmasq|disabled|failed\n' > "$failed_state_root/state"
mkdir -p "$failed_state_root/mock-bin"
cat > "$failed_state_root/mock-bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_STATE_LOG"
exit 0
EOF
chmod +x "$failed_state_root/mock-bin/systemctl"
if PATH="$failed_state_root/mock-bin:$PATH" DSU_STATE_LOG="$failed_state_root/systemctl.log" \
  bash -c 'source "$1"; restore_service_state "$2"' bash "$SCRIPT" "$failed_state_root/state" >/dev/null 2>&1; then
  fail "restore_service_state silently converted failed to inactive"
fi
assert_not_contains "$failed_state_root/systemctl.log" 'stop dnsmasq'
rm -rf "$failed_state_root"
pass "fails loudly instead of claiming exact restoration of systemd failed state"

uninstall_late_root=$(mktemp -d)
DSU_ROOT="$uninstall_late_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
if DSU_ROOT="$uninstall_late_root" DSU_TEST_MODE=0 DSU_RESTORE_MARKER="$uninstall_late_root/firewall.restored" bash -c '
  source "$1"
  save_unit_state() { printf "%s\\n" "dnsmasq|disabled|inactive" > "$1"; }
  save_firewall_snapshot() { printf before > "$1"; }
  restore_firewall_snapshot() { printf restored > "$DSU_RESTORE_MARKER"; }
  firewall_remove() { printf restored > "$DSU_RESTORE_MARKER"; :; }
  systemctl() {
    case "$1" in
      is-enabled) printf disabled ;;
      is-active) printf inactive ;;
    esac
    if [ "$1:$2" = "stop:sniproxy" ]; then return 73; fi
    return 0
  }
  uninstall_gateway --yes
' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "uninstall succeeded after a later service-stop failure"
fi
[[ -d "$uninstall_late_root/etc/dns-sni-unlock" ]] || fail "uninstall deleted configuration after a later failure"
rm -rf "$uninstall_late_root"
pass "retains configuration and reports a later uninstall failure"

stale_ownership_root=$(mktemp -d)
mkdir -p "$stale_ownership_root/var/lib/dns-sni-unlock" "$stale_ownership_root/mock-bin"
printf '%s\n' 'Managed by dns-sni-unlock firewall chain DNS_SNI_UNLOCK_IN' > "$stale_ownership_root/var/lib/dns-sni-unlock/firewall.ownership"
cat > "$stale_ownership_root/mock-bin/iptables-save" <<'EOF'
#!/bin/sh
if [ "${DSU_CHAIN_APPEARED:-0}" = 1 ]; then
  printf '*filter\n:INPUT ACCEPT [0:0]\n:DNS_SNI_UNLOCK_IN - [0:0]\nCOMMIT\n'
else
  printf '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n'
fi
EOF
cat > "$stale_ownership_root/mock-bin/iptables" <<'EOF'
#!/bin/sh
case "$1:$2" in
  -L:DNS_SNI_UNLOCK_IN) exit 0 ;;
  -S:DNS_SNI_UNLOCK_IN)
    printf '%s\n' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p udp --dport 53 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -s 127.0.0.1 -p tcp -m multiport --dports 53,80,443 -j ACCEPT' '-A DNS_SNI_UNLOCK_IN -p udp --dport 53 -j DROP' '-A DNS_SNI_UNLOCK_IN -p tcp -m multiport --dports 53,80,443 -j DROP' '-A DNS_SNI_UNLOCK_IN -j RETURN' ;;
  -S:INPUT) printf '%s\n' '-A INPUT -j DNS_SNI_UNLOCK_IN' ;;
  *) exit 0 ;;
esac
EOF
cat > "$stale_ownership_root/mock-bin/iptables-restore" <<'EOF'
#!/bin/sh
cat >/dev/null
exit 0
EOF
chmod +x "$stale_ownership_root/mock-bin/iptables-save" "$stale_ownership_root/mock-bin/iptables" "$stale_ownership_root/mock-bin/iptables-restore"
if ! PATH="$stale_ownership_root/mock-bin:$PATH" \
  DSU_ROOT="$stale_ownership_root" DSU_TEST_MODE=0 DSU_CHAIN_APPEARED=0 \
  bash -c 'source "$1"; require_root() { :; }; firewall_remove' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall clear failed for an already-absent owned chain"
fi
if [[ ! -e "$stale_ownership_root/var/lib/dns-sni-unlock/firewall.ownership" ]]; then
  :
else
  if grep -Fqx 'Managed by dns-sni-unlock firewall chain DNS_SNI_UNLOCK_IN' \
    "$stale_ownership_root/var/lib/dns-sni-unlock/firewall.ownership"; then
    fail "firewall clear left stale ownership proof after the owned chain was absent"
  fi
fi
if PATH="$stale_ownership_root/mock-bin:$PATH" \
  DSU_ROOT="$stale_ownership_root" DSU_TEST_MODE=0 DSU_CHAIN_APPEARED=1 \
  bash -c 'source "$1"; require_root() { :; }; firewall_apply' bash "$SCRIPT" >/dev/null 2>&1; then
  fail "firewall apply trusted a same-name chain after stale ownership was cleared"
fi
rm -rf "$stale_ownership_root"
pass "invalidates stale firewall ownership when the chain is absent and refuses a later same-name chain"

render_evidence_root=$(mktemp -d)
DSU_ROOT="$render_evidence_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
DSU_ROOT="$render_evidence_root" DSU_TEST_MODE=1 "$SCRIPT" render >/dev/null
mkdir -p "$render_evidence_root/mock-bin"
cat > "$render_evidence_root/mock-bin/mv" <<'EOF'
#!/bin/sh
last=''
for argument do last=$argument; done
if [ "$last" = "$DSU_FAIL_TARGET" ]; then exit 73; fi
exec "$DSU_REAL_MV" "$@"
EOF
chmod +x "$render_evidence_root/mock-bin/mv"
render_evidence_real_mv=$(command -v mv)
render_evidence_dnsmasq="$render_evidence_root/etc/dnsmasq.d/90-dns-sni-unlock.conf"
render_evidence_sniproxy="$render_evidence_root/etc/sniproxy.conf"
cp "$render_evidence_dnsmasq" "$render_evidence_root/dnsmasq.before"
cp "$render_evidence_sniproxy" "$render_evidence_root/sniproxy.before"
printf 'EvidenceRoute|198.51.100.93|evidence.example\n' >> "$render_evidence_root/etc/dns-sni-unlock/services.conf"
if PATH="$render_evidence_root/mock-bin:$PATH" \
  DSU_REAL_MV="$render_evidence_real_mv" \
  DSU_FAIL_TARGET="$render_evidence_sniproxy" \
  DSU_ROOT="$render_evidence_root" DSU_TEST_MODE=1 bash -c '
    source "$1"
    restore_file_snapshot() { return 75; }
    render_configs
  ' bash "$SCRIPT" >"$render_evidence_root/output" 2>&1; then
  fail "render succeeded after its rollback restoration failed"
fi
assert_contains "$render_evidence_root/output" 'UNSAFE STATE'
assert_contains "$render_evidence_root/output" 'render transaction evidence retained at'
render_evidence_txdir=$(sed $'s/\033\[[0-9;]*m//g' "$render_evidence_root/output" | sed -n 's/.*render transaction evidence retained at \([^ ]*\).*/\1/p')
[[ -d "$render_evidence_txdir" ]] || fail "render deleted evidence after rollback restoration failure"
[[ -f "$render_evidence_txdir/dnsmasq.old" ]] || fail "render did not retain the exact dnsmasq snapshot"
cmp -s "$render_evidence_txdir/dnsmasq.old" "$render_evidence_root/dnsmasq.before" || fail "render retained an inexact dnsmasq snapshot"
rm -rf "$render_evidence_root"
pass "retains render transaction evidence and exact snapshots after rollback restoration failure"

install_file_evidence_root=$(mktemp -d)
if DSU_ROOT="$install_file_evidence_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  restore_file_snapshot() { return 75; }
  restore_firewall_snapshot() { :; }
  save_firewall_snapshot() { printf snapshot > "$1"; }
  install_packages() { :; }
  validate_runtime_configs() { :; }
  restart_services() { return 74; }
  doctor() { :; }
  install_gateway --proxy-ip 198.51.100.94 --allow 203.0.113.94
' bash "$SCRIPT" >"$install_file_evidence_root/output" 2>&1; then
  fail "install succeeded after file rollback restoration failures"
fi
assert_contains "$install_file_evidence_root/output" 'UNSAFE STATE'
assert_contains "$install_file_evidence_root/output" 'install transaction evidence retained at'
install_file_evidence_txdir=$(sed $'s/\033\[[0-9;]*m//g' "$install_file_evidence_root/output" | sed -n 's/.*install transaction evidence retained at \([^ ]*\).*/\1/p')
[[ -d "$install_file_evidence_txdir" ]] || fail "install deleted evidence after file rollback restoration failures"
[[ -f "$install_file_evidence_txdir/firewall.before" ]] || fail "install did not retain the exact snapshot after file rollback failure"
rm -rf "$install_file_evidence_root"
pass "retains install transaction evidence after file rollback restoration failure"

apply_file_evidence_root=$(mktemp -d)
DSU_ROOT="$apply_file_evidence_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
if DSU_ROOT="$apply_file_evidence_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  restore_file_snapshot() { return 75; }
  render_configs() { :; }
  validate_runtime_configs() { :; }
  firewall_apply() { :; }
  save_firewall_snapshot() { printf snapshot > "$1"; }
  restore_firewall_snapshot() { :; }
  restart_services() { return 73; }
  apply_all
' bash "$SCRIPT" >"$apply_file_evidence_root/output" 2>&1; then
  fail "apply succeeded after file rollback restoration failures"
fi
assert_contains "$apply_file_evidence_root/output" 'UNSAFE STATE'
assert_contains "$apply_file_evidence_root/output" 'apply transaction evidence retained at'
apply_file_evidence_txdir=$(sed $'s/\033\[[0-9;]*m//g' "$apply_file_evidence_root/output" | sed -n 's/.*apply transaction evidence retained at \([^ ]*\).*/\1/p')
[[ -d "$apply_file_evidence_txdir" ]] || fail "apply deleted evidence after file rollback restoration failures"
[[ -f "$apply_file_evidence_txdir/firewall.before" ]] || fail "apply did not retain the exact snapshot after file rollback failure"
rm -rf "$apply_file_evidence_root"
pass "retains apply transaction evidence after file rollback restoration failure"

fresh_install_root=$(mktemp -d)
mkdir -p "$fresh_install_root/mock-bin"
cat > "$fresh_install_root/mock-bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_SYSTEMCTL_LOG"
if [ ! -e "$DSU_PACKAGES_READY" ]; then
  case "$1" in
    is-enabled|is-active) printf 'not-found\n'; exit 1 ;;
  esac
else
  case "$1" in
    is-enabled) printf 'disabled\n'; exit 1 ;;
    is-active) printf 'inactive\n'; exit 3 ;;
  esac
fi
exit 0
EOF
chmod +x "$fresh_install_root/mock-bin/systemctl"
if PATH="$fresh_install_root/mock-bin:$PATH" \
  DSU_ROOT="$fresh_install_root" DSU_TEST_MODE=0 \
  DSU_SYSTEMCTL_LOG="$fresh_install_root/systemctl.log" \
  DSU_PACKAGES_READY="$fresh_install_root/packages-ready" \
  bash -c '
    source "$1"
    require_root() { :; }
    install_packages() { : > "$DSU_PACKAGES_READY"; }
    save_firewall_snapshot() { :; }
    detect_proxy_ip() { printf "198.51.100.95"; }
    install_self() { :; }
    render_configs() { :; }
    write_firewall_unit() { :; }
    validate_runtime_configs() { :; }
    restart_services() { return 74; }
    doctor() { :; }
    install_gateway --allow 203.0.113.95
  ' bash "$SCRIPT" >"$fresh_install_root/output" 2>&1; then
  fail "fresh install succeeded after injected late failure"
fi
[[ -e "$fresh_install_root/packages-ready" ]] || fail "fresh install did not reach install_packages after not-found unit state"
assert_contains "$fresh_install_root/systemctl.log" 'disable dnsmasq'
assert_contains "$fresh_install_root/systemctl.log" 'stop dnsmasq'
assert_contains "$fresh_install_root/systemctl.log" 'disable sniproxy'
assert_contains "$fresh_install_root/systemctl.log" 'stop sniproxy'
rm -rf "$fresh_install_root"
pass "accepts explicit clean-install not-found unit state and rolls back units introduced by package installation"

uninstall_rollback_root=$(mktemp -d)
DSU_ROOT="$uninstall_rollback_root" DSU_TEST_MODE=1 "$SCRIPT" install --proxy-ip 198.51.100.96 --allow 203.0.113.96 >/dev/null
uninstall_rollback_config_before="$uninstall_rollback_root/config.before"
uninstall_rollback_state_before="$uninstall_rollback_root/state.before"
cp -a "$uninstall_rollback_root/etc/dns-sni-unlock" "$uninstall_rollback_config_before"
cp -a "$uninstall_rollback_root/var/lib/dns-sni-unlock" "$uninstall_rollback_state_before"
mkdir -p "$uninstall_rollback_root/mock-bin"
for uninstall_rollback_command in iptables iptables-save iptables-restore; do
  printf '#!/bin/sh\nexit 0\n' > "$uninstall_rollback_root/mock-bin/$uninstall_rollback_command"
  chmod +x "$uninstall_rollback_root/mock-bin/$uninstall_rollback_command"
done
if PATH="$uninstall_rollback_root/mock-bin:$PATH" \
  DSU_ROOT="$uninstall_rollback_root" DSU_TEST_MODE=0 \
  DSU_UNINSTALL_ROLLBACK_STARTED="$uninstall_rollback_root/rollback.started" \
  bash -c '
    source "$1"
    require_root() { :; }
    firewall_remove() { :; }
    restore_firewall_snapshot() { : > "$DSU_UNINSTALL_ROLLBACK_STARTED"; }
    systemctl() {
      case "${1:-}:${2:-}" in
        is-enabled:*) printf disabled; return 1 ;;
        is-active:*) printf inactive; return 3 ;;
        stop:sniproxy)
          if [ ! -e "$DSU_UNINSTALL_ROLLBACK_STARTED" ]; then return 73; fi
          ;;
      esac
      return 0
    }
    uninstall_gateway --yes
  ' bash "$SCRIPT" >"$uninstall_rollback_root/output" 2>&1; then
  fail "uninstall succeeded after late service failure"
fi
assert_contains "$uninstall_rollback_root/output" 'INCOMPLETE UNINSTALL'
diff -ru "$uninstall_rollback_config_before" "$uninstall_rollback_root/etc/dns-sni-unlock" >/dev/null || fail "uninstall rollback did not restore the exact configuration directory"
diff -ru "$uninstall_rollback_state_before" "$uninstall_rollback_root/var/lib/dns-sni-unlock" >/dev/null || fail "uninstall rollback did not restore the exact ownership state directory"
[[ -f "$uninstall_rollback_root/etc/dnsmasq.d/90-dns-sni-unlock.conf" ]] || fail "uninstall rollback did not restore dnsmasq configuration"
[[ -f "$uninstall_rollback_root/etc/sniproxy.conf" ]] || fail "uninstall rollback did not restore sniproxy configuration"
[[ -f "$uninstall_rollback_root/etc/systemd/system/dns-sni-unlock-firewall.service" ]] || fail "uninstall rollback did not restore firewall unit"
[[ -f "$uninstall_rollback_root/usr/local/sbin/dns-sni-unlock" ]] || fail "uninstall rollback did not restore installed binary"
rm -rf "$uninstall_rollback_root"
pass "rolls back exact uninstall files, ownership evidence, and service failure state"

uninstall_abort_root=$(mktemp -d)
DSU_ROOT="$uninstall_abort_root" DSU_TEST_MODE=1 "$SCRIPT" init-config >/dev/null
mkdir -p "$uninstall_abort_root/var/lib/dns-sni-unlock"
printf 'firewall-unit|%s\ndnsmasq-snippet.conf|%s\nsniproxy.conf|%s\ninstalled-bin|%s\n' \
  "$uninstall_abort_root/etc/systemd/system/dns-sni-unlock-firewall.service" \
  "$uninstall_abort_root/etc/dnsmasq.d/90-dns-sni-unlock.conf" \
  "$uninstall_abort_root/etc/sniproxy.conf" \
  "$uninstall_abort_root/usr/local/sbin/dns-sni-unlock" \
  > "$uninstall_abort_root/var/lib/dns-sni-unlock/ownership.manifest"
if DSU_ROOT="$uninstall_abort_root" DSU_TEST_MODE=1 bash -c '
  source "$1"
  restore_original_or_remove_managed() { return 73; }
  restore_file_snapshot() { return 75; }
  uninstall_gateway --yes
' bash "$SCRIPT" >"$uninstall_abort_root/output" 2>&1; then
  fail "uninstall succeeded after rollback restoration failures"
fi
assert_contains "$uninstall_abort_root/output" 'UNSAFE STATE'
assert_contains "$uninstall_abort_root/output" 'uninstall rollback failed; transaction evidence retained at'
uninstall_abort_txdir=$(sed $'s/\033\[[0-9;]*m//g' "$uninstall_abort_root/output" | sed -n 's/.*transaction evidence retained at \([^ ]*\).*/\1/p')
[[ -d "$uninstall_abort_txdir" ]] || fail "uninstall deleted evidence after rollback failure"
[[ -d "$uninstall_abort_txdir/config.before" ]] || fail "uninstall did not retain the exact configuration snapshot after rollback failure"
[[ -d "$uninstall_abort_txdir/state.before" ]] || fail "uninstall did not retain the exact ownership state snapshot after rollback failure"
rm -rf "$uninstall_abort_root"
pass "uninstall_abort executes rollback, reports UNSAFE state, and retains exact evidence on rollback failure"

uninstall_manifest_root=$(mktemp -d)
DSU_ROOT="$uninstall_manifest_root" DSU_TEST_MODE=1 "$SCRIPT" install --proxy-ip 198.51.100.95 --allow 203.0.113.95 >/dev/null
rm -f "$uninstall_manifest_root/var/lib/dns-sni-unlock/ownership.manifest"
if DSU_ROOT="$uninstall_manifest_root" DSU_TEST_MODE=1 "$SCRIPT" uninstall --yes >"$uninstall_manifest_root/output" 2>&1; then
  fail "uninstall succeeded without an ownership manifest"
fi
assert_contains "$uninstall_manifest_root/output" 'INCOMPLETE UNINSTALL'
[[ -d "$uninstall_manifest_root/etc/dns-sni-unlock" ]] || fail "uninstall deleted configuration without ownership proof"
[[ -d "$uninstall_manifest_root/var/lib/dns-sni-unlock" ]] || fail "uninstall deleted state without ownership proof"
[[ -f "$uninstall_manifest_root/etc/dnsmasq.d/90-dns-sni-unlock.conf" ]] || fail "uninstall deleted generated dnsmasq config without ownership proof"
[[ -f "$uninstall_manifest_root/etc/sniproxy.conf" ]] || fail "uninstall deleted generated SNIProxy config without ownership proof"
[[ -f "$uninstall_manifest_root/etc/systemd/system/dns-sni-unlock-firewall.service" ]] || fail "uninstall deleted firewall unit without ownership proof"
[[ -f "$uninstall_manifest_root/usr/local/sbin/dns-sni-unlock" ]] || fail "uninstall deleted installed binary without ownership proof"
uninstall_manifest_txdir=$(sed $'s/\033\[[0-9;]*m//g' "$uninstall_manifest_root/output" | sed -n 's/.*recovery evidence retained at \([^ ]*\).*/\1/p')
[[ -d "$uninstall_manifest_txdir" ]] || fail "uninstall did not retain recovery evidence without ownership proof"
rm -rf "$uninstall_manifest_root"
pass "fails closed and retains recovery evidence when ownership manifest is missing"

install_reload_root=$(mktemp -d)
mkdir -p "$install_reload_root/mock-bin" "$install_reload_root/etc/systemd/system"
cat > "$install_reload_root/mock-bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DSU_STATE_LOG"
case "$1:$2" in
  is-enabled:*) printf 'enabled\n' ;;
  is-active:*) printf 'active\n' ;;
  daemon-reload:*)
    if grep -Fq 'pre-existing project firewall unit' "$DSU_ROOT/etc/systemd/system/dns-sni-unlock-firewall.service"; then
      : > "$DSU_RELOAD_AFTER_UNIT"
    fi
    exit 73
    ;;
esac
EOF
chmod +x "$install_reload_root/mock-bin/systemctl"
printf 'pre-existing project firewall unit\n' > "$install_reload_root/etc/systemd/system/dns-sni-unlock-firewall.service"
if PATH="$install_reload_root/mock-bin:$PATH" \
  DSU_ROOT="$install_reload_root" DSU_TEST_MODE=1 DSU_TEST_SYSTEMCTL=1 \
  DSU_STATE_LOG="$install_reload_root/systemctl.log" \
  DSU_RELOAD_AFTER_UNIT="$install_reload_root/reload-after-unit" \
  bash -c '
    source "$1"
    require_root() { :; }
    install_packages() { :; }
    validate_runtime_configs() { :; }
    restart_services() { return 74; }
    doctor() { :; }
    install_gateway --proxy-ip 198.51.100.94 --allow 203.0.113.94
  ' bash "$SCRIPT" >"$install_reload_root/output" 2>&1; then
  fail "install succeeded after injected restart failure"
fi
[[ -f "$install_reload_root/reload-after-unit" ]] || fail "install rollback did not daemon-reload after restoring firewall unit"
assert_not_contains "$install_reload_root/systemctl.log" 'unmask dnsmasq'
assert_contains "$install_reload_root/output" 'UNSAFE STATE'
assert_contains "$install_reload_root/output" 'install transaction evidence retained at'
install_reload_txdir=$(sed $'s/\033\[[0-9;]*m//g' "$install_reload_root/output" | sed -n 's/.*install transaction evidence retained at \([^ ]*\).*/\1/p')
[[ -d "$install_reload_txdir" ]] || fail "install deleted evidence after daemon-reload failure"
rm -rf "$install_reload_root"
pass "install rollback reloads the restored firewall unit and fails unsafe on reload error"

printf '1..%d\n' "$PASS"
