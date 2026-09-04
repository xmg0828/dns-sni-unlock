#!/usr/bin/env bash
# dns-sni-unlock — safely manage an allowlisted dnsmasq + SNIProxy gateway.
set -Eeuo pipefail
IFS=$'\n\t'

readonly PROGRAM="dns-sni-unlock"
readonly VERSION="3.0.0"
readonly MANAGED_MARKER="Managed by dns-sni-unlock"
readonly ROOT_PREFIX="${DSU_ROOT:-}"
readonly TEST_MODE="${DSU_TEST_MODE:-0}"
readonly CHAIN="DNS_SNI_UNLOCK_IN"

root_path() { printf '%s%s' "$ROOT_PREFIX" "$1"; }
CONFIG_DIR=$(root_path /etc/dns-sni-unlock)
readonly CONFIG_DIR
readonly SERVICES_FILE="$CONFIG_DIR/services.conf"
readonly WHITELIST_FILE="$CONFIG_DIR/whitelist.conf"
DNSMASQ_SNIPPET=$(root_path /etc/dnsmasq.d/90-dns-sni-unlock.conf)
readonly DNSMASQ_SNIPPET
SNIPROXY_CONFIG=$(root_path /etc/sniproxy.conf)
readonly SNIPROXY_CONFIG
STATE_DIR=$(root_path /var/lib/dns-sni-unlock)
readonly STATE_DIR
INSTALLED_BIN=$(root_path /usr/local/sbin/dns-sni-unlock)
readonly INSTALLED_BIN
FIREWALL_UNIT=$(root_path /etc/systemd/system/dns-sni-unlock-firewall.service)
readonly FIREWALL_UNIT
readonly OWNERSHIP_MANIFEST="$STATE_DIR/ownership.manifest"
readonly FIREWALL_OWNERSHIP="$STATE_DIR/firewall.ownership"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[36m'; RESET='\033[0m'

log() { printf '%b%s%b\n' "$GREEN" "$*" "$RESET"; }
info() { printf '%b%s%b\n' "$BLUE" "$*" "$RESET"; }
warn() { printf '%b%s%b\n' "$YELLOW" "$*" "$RESET" >&2; }
die() { printf '%bError: %s%b\n' "$RED" "$*" "$RESET" >&2; exit 1; }

require_root() {
  if [[ "$TEST_MODE" != "1" && ${EUID:-$(id -u)} -ne 0 ]]; then
    die "this command must run as root"
  fi
}

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

validate_ipv4() {
  local value=${1:-}
  python3 - "$value" <<'PY' >/dev/null 2>&1
import ipaddress, sys
try:
    ipaddress.IPv4Address(sys.argv[1])
except Exception:
    raise SystemExit(1)
PY
}

validate_cidr() {
  local value=${1:-}
  python3 - "$value" <<'PY' >/dev/null 2>&1
import ipaddress, sys
try:
    ipaddress.IPv4Network(sys.argv[1], strict=False)
except Exception:
    raise SystemExit(1)
PY
}

validate_allow_entry() {
  local value=${1:-}
  python3 - "$value" <<'PY' >/dev/null 2>&1
import ipaddress, sys
try:
    network = ipaddress.IPv4Network(sys.argv[1], strict=False)
    address = ipaddress.IPv4Address(sys.argv[1]) if "/" not in sys.argv[1] else None
except Exception:
    raise SystemExit(1)
if network.prefixlen == 0 or network.is_multicast:
    raise SystemExit(1)
if address is not None and address.is_unspecified:
    raise SystemExit(1)
PY
}

validate_allowlist_coverage() {
  local source=$1
  python3 - "$source" <<'PY'
import ipaddress
import sys

try:
    networks = []
    with open(sys.argv[1], encoding="utf-8") as source:
        for raw in source:
            value = raw.strip()
            if value:
                networks.append(ipaddress.IPv4Network(value, strict=False))
    covered = ipaddress.collapse_addresses(networks)
except Exception:
    raise SystemExit(1)

if any(network.prefixlen == 0 for network in covered):
    raise SystemExit(1)
PY
}

validate_effective_allowlist_coverage() {
  local source=$1
  if ! grep -Fxq '127.0.0.1' "$source" && ! printf '127.0.0.1\n' >> "$source"; then
    return 1
  fi
  if ! sort -u "$source" -o "$source"; then
    return 1
  fi
  validate_allowlist_coverage "$source"
}

normalize_domain() {
  local value=${1:-}
  value=${value%.}
  printf '%s' "$value" | tr '[:upper:]' '[:lower:]'
}

validate_route_overlaps() {
  python3 - "$1" <<'PY'
import sys
routes = []
with open(sys.argv[1], encoding="utf-8") as source:
    for raw in source:
        name, ip, domain = raw.rstrip("\n").split("|", 2)
        for old_domain, old_ip in routes:
            overlap = (
                domain == old_domain
                or domain.endswith("." + old_domain)
                or old_domain.endswith("." + domain)
            )
            if overlap and ip != old_ip:
                print(
                    "overlapping domains require the same proxy IPv4: "
                    f"{old_domain} and {domain}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
        routes.append((domain, ip))
PY
}

validate_domain() {
  local value
  value=$(normalize_domain "${1:-}")
  [[ ${#value} -le 253 ]] || return 1
  [[ "$value" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]
}

validate_service_name() {
  local value=${1:-} safe_name_re='^[A-Za-z0-9][A-Za-z0-9_. -]*$'
  [[ -n "$value" && ${#value} -le 64 && "$value" =~ $safe_name_re ]]
}

normalize_whitelist_line() {
  local value=${1:-}
  value=${value%%#*}
  value=$(printf '%s' "$value" | tr -d '[:space:]')
  [[ -n "$value" ]] || { printf '\n'; return 0; }
  python3 - "$value" <<'PY'
import ipaddress, sys
value = sys.argv[1]
network = ipaddress.IPv4Network(value, strict=False)
if network.prefixlen == 32:
    print(network.network_address)
else:
    print(network.with_prefixlen)
PY
}

canonicalize_whitelist_file() {
  local source=$1 output=$2 line normalized lineno=0
  : > "$output" || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    if ! normalized=$(normalize_whitelist_line "$line"); then
      die "unsafe or invalid whitelist entry on line $lineno: $line"
    fi
    [[ -z "$normalized" ]] && continue
    validate_allow_entry "$normalized" || die "unsafe or invalid whitelist entry on line $lineno: $normalized"
    printf '%s\n' "$normalized" >> "$output" || return 1
  done < "$source"
  if ! sort -u "$output" -o "$output"; then
    return 1
  fi
  validate_allowlist_coverage "$output"
}

ensure_parent() {
  if ! mkdir -p "$(dirname "$1")"; then
    return 1
  fi
}

remove_temp_file() {
  local path=$1
  if ! rm -f "$path"; then
    warn "could not clean up temporary file: $path"
    return 1
  fi
}

atomic_replace() {
  local target=$1 tmp
  if ! ensure_parent "$target"; then
    return 1
  fi
  if ! tmp=$(mktemp "${target}.tmp.XXXXXX"); then
    return 1
  fi
  if ! cat > "$tmp"; then
    remove_temp_file "$tmp" || true
    return 1
  fi
  if ! chmod 0644 "$tmp"; then
    remove_temp_file "$tmp" || true
    return 1
  fi
  if [[ -f "$target" ]] && cmp -s "$tmp" "$target"; then
    if ! remove_temp_file "$tmp"; then
      return 1
    fi
  else
    if ! mv -f "$tmp" "$target"; then
      remove_temp_file "$tmp" || true
      return 1
    fi
  fi
}

snapshot_file() {
  local source=$1 snapshot=$2
  if ! ensure_parent "$snapshot"; then
    return 1
  fi
  if [[ -e "$source" || -L "$source" ]]; then
    if ! cp -a "$source" "$snapshot"; then
      return 1
    fi
  elif ! : > "${snapshot}.absent"; then
    return 1
  fi
}

restore_file_snapshot() {
  local snapshot=$1 target=$2 restore_dir staged target_backup=''
  if [[ -e "${snapshot}.absent" ]]; then
    if [[ -e "$target" || -L "$target" ]] && ! rm -rf "$target"; then
      warn "could not remove restored-absent target: $target"
      return 1
    fi
  elif [[ -e "$snapshot" || -L "$snapshot" ]]; then
    if ! ensure_parent "$target"; then
      warn "could not create parent directory for restored snapshot: $target"
      return 1
    fi
    restore_dir=$(mktemp -d "$(dirname "$target")/.${target##*/}.restore.XXXXXX") || {
      warn "could not create secure restore directory beside target: $target"
      return 1
    }
    staged="$restore_dir/entry"
    if ! cp -a "$snapshot" "$staged"; then
      warn "could not stage file snapshot for restore: $snapshot"
      rm -rf "$restore_dir" || true
      return 1
    fi
    if [[ -e "$target" || -L "$target" ]]; then
      target_backup="$restore_dir/target.before"
      if ! mv -f "$target" "$target_backup"; then
        warn "could not stage existing target for snapshot restore: $target"
        rm -rf "$restore_dir" || true
        return 1
      fi
    fi
    if ! mv -f "$staged" "$target"; then
      warn "could not atomically replace target with file snapshot: $target"
      if [[ -n "$target_backup" ]] && ! mv -f "$target_backup" "$target"; then
        warn "UNSAFE STATE: could not restore the original target after snapshot replacement failure: $target"
      fi
      rm -rf "$restore_dir" || true
      return 1
    fi
    if ! rm -rf "$restore_dir"; then
      warn "could not clean up secure restore directory: $restore_dir"
      return 1
    fi
  else
    warn "file snapshot does not exist: $snapshot"
    return 1
  fi
}

ownership_has_entry() {
  local label=$1 target=$2
  [[ -r "$OWNERSHIP_MANIFEST" ]] || return 1
  awk -F '|' -v wanted_label="$label" -v wanted_target="$target" \
    '$1 == wanted_label && $2 == wanted_target { found=1 } END { exit found ? 0 : 1 }' \
    "$OWNERSHIP_MANIFEST"
}

ownership_manifest_proves_managed_files() {
  local managed_item restore_target restore_label restore_current installed_state=0
  [[ -r "$OWNERSHIP_MANIFEST" ]] || return 1
  if [[ -e "$STATE_DIR/service-state" || -L "$STATE_DIR/service-state" ||
        -e "$STATE_DIR/managed/installed-bin.current" || -L "$STATE_DIR/managed/installed-bin.current" ||
        -e "$STATE_DIR/managed/firewall-unit.current" || -L "$STATE_DIR/managed/firewall-unit.current" ]]; then
    installed_state=1
  fi
  for managed_item in \
    "$FIREWALL_UNIT|firewall-unit" \
    "$DNSMASQ_SNIPPET|dnsmasq-snippet.conf" \
    "$SNIPROXY_CONFIG|sniproxy.conf" \
    "$INSTALLED_BIN|installed-bin"; do
    IFS='|' read -r restore_target restore_label <<< "$managed_item"
    restore_current="$STATE_DIR/managed/$restore_label.current"
    if [[ $installed_state -eq 1 ||
          -e "$restore_target" || -L "$restore_target" ||
          -e "$restore_current" || -L "$restore_current" ]]; then
      ownership_has_entry "$restore_label" "$restore_target" || return 1
    fi
  done
}

record_managed_file() {
  local label=$1 target=$2 current manifest_tmp
  [[ -e "$target" || -L "$target" ]] || return 1
  current="$STATE_DIR/managed/$label.current"
  if ! ensure_parent "$current" || ! cp -a "$target" "$current"; then
    return 1
  fi
  if ! ensure_parent "$OWNERSHIP_MANIFEST"; then
    return 1
  fi
  if ! manifest_tmp=$(mktemp "${OWNERSHIP_MANIFEST}.record.XXXXXX"); then
    return 1
  fi
  if [[ -f "$OWNERSHIP_MANIFEST" ]]; then
    if ! awk -F '|' -v wanted_label="$label" '$1 != wanted_label' "$OWNERSHIP_MANIFEST" > "$manifest_tmp"; then
      remove_temp_file "$manifest_tmp" || true
      return 1
    fi
  fi
  if ! printf '%s|%s\n' "$label" "$target" >> "$manifest_tmp"; then
    remove_temp_file "$manifest_tmp" || true
    return 1
  fi
  if ! atomic_replace "$OWNERSHIP_MANIFEST" < "$manifest_tmp"; then
    remove_temp_file "$manifest_tmp" || true
    return 1
  fi
  if ! remove_temp_file "$manifest_tmp"; then
    return 1
  fi
}

backup_unmanaged_file() {
  local source=$1 label=$2 backup
  [[ -e "$source" || -L "$source" ]] || return 0
  ownership_has_entry "$label" "$source" && return 0
  if ! mkdir -p "$STATE_DIR/backups"; then
    return 1
  fi
  backup="$STATE_DIR/backups/$label.original"
  if [[ ! -e "$backup" && ! -L "$backup" ]] && ! cp -a "$source" "$backup"; then
    return 1
  fi
}

restore_original_or_remove_managed() {
  local target=$1 label=$2 backup="$STATE_DIR/backups/$2.original" current="$STATE_DIR/managed/$2.current"
  ownership_has_entry "$label" "$target" || return 0
  [[ -e "$target" || -L "$target" ]] || return 0
  if [[ ! -e "$current" && ! -L "$current" ]]; then
    warn "UNSAFE STATE: managed-current snapshot is missing for $target"
    return 1
  fi
  if ! cmp -s "$target" "$current"; then
    warn "preserving administrator-modified file: $target"
    return 2
  fi
  if [[ -e "$backup" || -L "$backup" ]]; then
    restore_file_snapshot "$backup" "$target"
  else
    if [[ -e "$target" || -L "$target" ]] && ! rm -f "$target"; then
      return 1
    fi
  fi
}

service_enablement_supported() {
  case "$1" in
    enabled|enabled-runtime|disabled|disabled-runtime|masked) return 0 ;;
    *) return 1 ;;
  esac
}

service_activity_supported() {
  case "$1" in
    active|inactive|failed) return 0 ;;
    *) return 1 ;;
  esac
}

save_unit_state() {
  local output=$1 unit enabled active tmp allow_not_found=0
  shift
  if [[ "${1:-}" == '--allow-not-found' ]]; then
    allow_not_found=1
    shift
  fi
  if ! ensure_parent "$output"; then
    return 1
  fi
  if [[ "$TEST_MODE" != "1" || "${DSU_TEST_SYSTEMCTL:-0}" == "1" ]]; then
    need_cmd systemctl
  fi
  if ! tmp=$(mktemp "${output}.tmp.XXXXXX"); then
    return 1
  fi
  if ! chmod 0644 "$tmp"; then
    remove_temp_file "$tmp" || true
    return 1
  fi
  if [[ "$TEST_MODE" == "1" && "${DSU_TEST_SYSTEMCTL:-0}" != "1" ]]; then
    if ! mv -f "$tmp" "$output"; then
      remove_temp_file "$tmp" || true
      return 1
    fi
    return 0
  fi
  for unit in "$@"; do
    if ! enabled=$(systemctl is-enabled "$unit" 2>/dev/null); then
      :
    fi
    if ! service_enablement_supported "$enabled"; then
      if [[ $allow_not_found -ne 1 || "$enabled" != not-found ]]; then
        warn "cannot safely save unsupported systemctl enablement state '$enabled' for $unit"
        remove_temp_file "$tmp" || true
        return 1
      fi
    fi
    if ! active=$(systemctl is-active "$unit" 2>/dev/null); then
      :
    fi
    if [[ $allow_not_found -eq 1 && ("$enabled" == not-found || "$active" == not-found) ]]; then
      if [[ "$enabled" != not-found ]] && ! service_enablement_supported "$enabled"; then
        warn "cannot safely save unsupported systemctl enablement state '$enabled' for $unit"
        remove_temp_file "$tmp" || true
        return 1
      fi
      if [[ "$active" != not-found ]] && ! service_activity_supported "$active"; then
        warn "cannot safely save unsupported systemctl activity state '$active' for $unit"
        remove_temp_file "$tmp" || true
        return 1
      fi
      enabled=not-found
      active=not-found
    else
      if ! service_enablement_supported "$enabled"; then
        warn "cannot safely save unsupported systemctl enablement state '$enabled' for $unit"
        remove_temp_file "$tmp" || true
        return 1
      fi
      if ! service_activity_supported "$active"; then
        warn "cannot safely save unsupported systemctl activity state '$active' for $unit"
        remove_temp_file "$tmp" || true
        return 1
      fi
    fi
    if ! printf '%s|%s|%s\n' "$unit" "$enabled" "$active" >> "$tmp"; then
      remove_temp_file "$tmp" || true
      return 1
    fi
  done
  if ! mv -f "$tmp" "$output"; then
    remove_temp_file "$tmp" || true
    return 1
  fi
}

save_service_state() {
  save_unit_state "$1" dnsmasq sniproxy
}

save_preinstall_service_state() {
  save_unit_state "$1" --allow-not-found dnsmasq sniproxy dns-sni-unlock-firewall.service
}

restore_missing_unit_state() {
  local unit=$1 current_enabled current_active
  if ! current_enabled=$(systemctl is-enabled "$unit" 2>/dev/null); then
    :
  fi
  if ! current_active=$(systemctl is-active "$unit" 2>/dev/null); then
    :
  fi
  if [[ "$current_enabled" == not-found && "$current_active" == not-found ]]; then
    return 0
  fi
  service_enablement_supported "$current_enabled" || {
    warn "cannot safely restore pre-install not-found state for $unit: unsupported enablement '$current_enabled'"
    return 1
  }
  service_activity_supported "$current_active" || {
    warn "cannot safely restore pre-install not-found state for $unit: unsupported activity '$current_active'"
    return 1
  }
  if ! systemctl stop "$unit" >/dev/null 2>&1 ||
     ! systemctl disable "$unit" >/dev/null 2>&1; then
    return 1
  fi
}

restore_service_state() {
  local state_file=$1 unit enabled active
  [[ -r "$state_file" ]] || return 0
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "cannot restore service state: systemctl is unavailable"
    return 1
  fi
  while IFS='|' read -r unit enabled active; do
    [[ -n "${unit:-}" ]] || continue
    if [[ "$enabled" == not-found ]]; then
      [[ "$active" == not-found ]] || {
        warn "cannot safely restore malformed pre-install state for $unit"
        return 1
      }
      if ! restore_missing_unit_state "$unit"; then
        return 1
      fi
      continue
    fi
    [[ "$active" != not-found ]] || {
      warn "cannot safely restore malformed pre-install state for $unit"
      return 1
    }
    case "$enabled" in
      enabled)
        if ! systemctl unmask "$unit" >/dev/null 2>&1 ||
           ! systemctl enable "$unit" >/dev/null 2>&1; then
          return 1
        fi
        ;;
      enabled-runtime)
        if ! systemctl unmask "$unit" >/dev/null 2>&1 ||
           ! systemctl enable --runtime "$unit" >/dev/null 2>&1; then
          return 1
        fi
        ;;
      disabled)
        if ! systemctl unmask "$unit" >/dev/null 2>&1 ||
           ! systemctl disable "$unit" >/dev/null 2>&1; then
          return 1
        fi
        ;;
      disabled-runtime)
        if ! systemctl unmask "$unit" >/dev/null 2>&1 ||
           ! systemctl disable --runtime "$unit" >/dev/null 2>&1; then
          return 1
        fi
        ;;
      masked)
        if ! systemctl mask "$unit" >/dev/null 2>&1; then
          return 1
        fi
        ;;
      static|indirect|generated|transient|linked|linked-runtime)
        warn "cannot exactly restore unsupported systemctl enablement state '$enabled' for $unit"
        return 1
        ;;
      *)
        warn "cannot exactly restore unknown systemctl enablement state '$enabled' for $unit"
        return 1
        ;;
    esac
    case "$active" in
      active)
        if ! systemctl restart "$unit" >/dev/null 2>&1; then
          return 1
        fi
        ;;
      inactive)
        if ! systemctl stop "$unit" >/dev/null 2>&1; then
          return 1
        fi
        ;;
      failed)
        warn "cannot exactly restore systemd failed state for $unit; refusing to convert it to inactive"
        return 1
        ;;
      *)
        warn "cannot exactly restore unknown systemctl activity state '$active' for $unit"
        return 1
        ;;
    esac
  done < "$state_file"
}

default_services() {
  local proxy_ip=$1
  cat <<EOF
# name|redirect IPv4|space-separated domains
OpenAI|$proxy_ip|openai.com chatgpt.com oaistatic.com oaiusercontent.com
Anthropic|$proxy_ip|anthropic.com claude.ai
Gemini|$proxy_ip|gemini.google.com generativelanguage.googleapis.com ai.google.dev
xAI|$proxy_ip|x.ai
Netflix|$proxy_ip|netflix.com netflix.net nflxext.com nflximg.net nflxso.net nflxvideo.net
Disney|$proxy_ip|disneyplus.com disney.com bamgrid.com dssott.com
YouTube|$proxy_ip|youtube.com youtu.be googlevideo.com ytimg.com
TikTok|$proxy_ip|tiktok.com tiktokcdn.com tiktokv.com musical.ly
EOF
}

init_config() {
  require_root
  local proxy_ip=${1:-127.0.0.1}
  validate_ipv4 "$proxy_ip" || die "invalid proxy IPv4 address: $proxy_ip"
  if ! mkdir -p "$CONFIG_DIR"; then return 1; fi
  if [[ ! ( -e "$SERVICES_FILE" || -L "$SERVICES_FILE" ) ]] && ! default_services "$proxy_ip" | atomic_replace "$SERVICES_FILE"; then
    return 1
  fi
  if [[ ! ( -e "$WHITELIST_FILE" || -L "$WHITELIST_FILE" ) ]] && ! printf '# One IPv4 address or CIDR per line\n127.0.0.1\n' | atomic_replace "$WHITELIST_FILE"; then
    return 1
  fi
}

parse_services() {
  local output=$1 line name ip domains extra domain normalized lineno=0
  : > "$output"
  [[ -r "$SERVICES_FILE" ]] || die "services file is missing or unreadable: $SERVICES_FILE"
  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    IFS='|' read -r name ip domains extra <<< "$line"
    [[ -z "${extra:-}" ]] || die "invalid services.conf line $lineno: too many fields"
    validate_service_name "${name:-}" || die "invalid service name on line $lineno"
    if awk -F '|' -v n="$name" '$1 == n { found=1 } END { exit found ? 0 : 1 }' "$output"; then
      die "duplicate service name on line $lineno: $name"
    fi
    validate_ipv4 "${ip:-}" || die "invalid service IPv4 on line $lineno"
    [[ -n "${domains:-}" ]] || die "empty domain list on line $lineno"
    local old_ifs=$IFS
    local -a domain_words
    IFS=' '
    read -r -a domain_words <<< "$domains"
    IFS=$old_ifs
    ((${#domain_words[@]} > 0)) || die "empty domain list on line $lineno"
    for domain in "${domain_words[@]}"; do
      normalized=$(normalize_domain "$domain")
      validate_domain "$normalized" || die "invalid domain on line $lineno: $domain"
      printf '%s|%s|%s\n' "$name" "$ip" "$normalized" >> "$output"
    done
  done < "$SERVICES_FILE"
  [[ -s "$output" ]] || die "services.conf contains no routes"
  awk -F '|' '
    seen[$3] {
      printf "duplicate normalized domain %s\n", $3 > "/dev/stderr"
      exit 1
    }
    { seen[$3] = 1 }
  ' "$output" || die "services.conf contains duplicate normalized domains"
  validate_route_overlaps "$output" || die "services.conf contains overlapping domain routes"
  if ! sort -u -t '|' -k3,3 "$output" -o "$output"; then
    return 1
  fi
}

parse_whitelist() {
  local output=$1
  [[ -r "$WHITELIST_FILE" ]] || die "whitelist file is missing or unreadable: $WHITELIST_FILE"
  canonicalize_whitelist_file "$WHITELIST_FILE" "$output" || return 1
  if ! validate_effective_allowlist_coverage "$output"; then
    return 1
  fi
}

generate_config_files() {
  local dnsmasq_candidate=$1 sniproxy_candidate=$2 tmpdir routes allow name ip domain escaped
  if ! tmpdir=$(mktemp -d); then
    return 1
  fi
  routes="$tmpdir/routes"
  allow="$tmpdir/allow"
  if ! parse_services "$routes" || ! parse_whitelist "$allow"; then
    rm -rf "$tmpdir"
    return 1
  fi
  if ! {
    printf '# %s — generated file; edit %s instead.\n' "$MANAGED_MARKER" "$SERVICES_FILE" || return 1
    printf 'domain-needed\n' || return 1
    printf 'bogus-priv\n' || return 1
    printf 'no-resolv\n' || return 1
    printf 'server=1.1.1.1\nserver=8.8.8.8\n' || return 1
    printf 'cache-size=4096\nlocal-ttl=60\n' || return 1
    printf 'bind-dynamic\nlisten-address=0.0.0.0\n' || return 1
    while IFS='|' read -r name ip domain; do
      printf 'address=/%s/%s\n' "$domain" "$ip" || return 1
    done < "$routes"
  } > "$dnsmasq_candidate"; then
    rm -rf "$tmpdir"
    return 1
  fi
  if ! {
    printf '# %s — generated file; edit %s instead.\n' "$MANAGED_MARKER" "$SERVICES_FILE" || return 1
    if ! cat <<'EOF'
user daemon
pidfile /run/sniproxy.pid
error_log {
    syslog daemon
    priority notice
}
resolver {
    nameserver 1.1.1.1
    nameserver 8.8.8.8
    mode ipv4_only
}
listener 0.0.0.0:80 {
    proto http
}
listener 0.0.0.0:443 {
    proto tls
}
table {
EOF
    then
      return 1
    fi
    while IFS='|' read -r name ip domain; do
      escaped=${domain//./\\.}
      printf '    ^%s$ *\n' "$escaped" || return 1
      printf '    .*\\.%s$ *\n' "$escaped" || return 1
    done < "$routes"
    printf '}\n' || return 1
  } > "$sniproxy_candidate"; then
    rm -rf "$tmpdir"
    return 1
  fi
  if ! rm -rf "$tmpdir"; then
    return 1
  fi
}

render_configs() (
  require_root
  local tmpdir dnsmasq_candidate sniproxy_candidate render_mutation_started=0
  local retain_evidence=0
  if ! tmpdir=$(mktemp -d); then
    return 1
  fi
  dnsmasq_candidate="$tmpdir/dnsmasq.new"
  sniproxy_candidate="$tmpdir/sniproxy.new"
  # shellcheck disable=SC2329 # invoked indirectly by the EXIT trap
  render_rollback() {
    local result=$?
    trap - EXIT
    if [[ $result -ne 0 && $render_mutation_started -eq 1 ]]; then
      if ! restore_file_snapshot "$tmpdir/dnsmasq.old" "$DNSMASQ_SNIPPET"; then
        warn "UNSAFE STATE: could not restore dnsmasq configuration"
        retain_evidence=1
        result=1
      fi
      if ! restore_file_snapshot "$tmpdir/sniproxy.old" "$SNIPROXY_CONFIG"; then
        warn "UNSAFE STATE: could not restore SNIProxy configuration"
        retain_evidence=1
        result=1
      fi
      if ! restore_file_snapshot "$tmpdir/ownership.old" "$OWNERSHIP_MANIFEST"; then
        warn "UNSAFE STATE: could not restore ownership manifest"
        retain_evidence=1
        result=1
      fi
      if ! restore_file_snapshot "$tmpdir/dnsmasq.owned.old" "$STATE_DIR/managed/dnsmasq-snippet.conf.current"; then
        warn "UNSAFE STATE: could not restore dnsmasq ownership state"
        retain_evidence=1
        result=1
      fi
      if ! restore_file_snapshot "$tmpdir/sniproxy.owned.old" "$STATE_DIR/managed/sniproxy.conf.current"; then
        warn "UNSAFE STATE: could not restore SNIProxy ownership state"
        retain_evidence=1
        result=1
      fi
      if ! restore_file_snapshot "$tmpdir/dnsmasq.backup.old" "$STATE_DIR/backups/dnsmasq-snippet.conf.original"; then
        warn "UNSAFE STATE: could not restore dnsmasq backup state"
        retain_evidence=1
        result=1
      fi
      if ! restore_file_snapshot "$tmpdir/sniproxy.backup.old" "$STATE_DIR/backups/sniproxy.conf.original"; then
        warn "UNSAFE STATE: could not restore SNIProxy backup state"
        retain_evidence=1
        result=1
      fi
    fi
    if [[ $retain_evidence -eq 1 ]]; then
      warn "UNSAFE STATE: render transaction evidence retained at $tmpdir"
    elif ! rm -rf "$tmpdir"; then
      warn "UNSAFE STATE: could not clean up render transaction directory; evidence retained at $tmpdir"
      result=1
    fi
    exit "$result"
  }
  trap render_rollback EXIT
  if ! generate_config_files "$dnsmasq_candidate" "$sniproxy_candidate"; then
    return 1
  fi
  if ! snapshot_file "$DNSMASQ_SNIPPET" "$tmpdir/dnsmasq.old" ||
     ! snapshot_file "$SNIPROXY_CONFIG" "$tmpdir/sniproxy.old" ||
     ! snapshot_file "$OWNERSHIP_MANIFEST" "$tmpdir/ownership.old" ||
     ! snapshot_file "$STATE_DIR/managed/dnsmasq-snippet.conf.current" "$tmpdir/dnsmasq.owned.old" ||
     ! snapshot_file "$STATE_DIR/managed/sniproxy.conf.current" "$tmpdir/sniproxy.owned.old" ||
     ! snapshot_file "$STATE_DIR/backups/dnsmasq-snippet.conf.original" "$tmpdir/dnsmasq.backup.old" ||
     ! snapshot_file "$STATE_DIR/backups/sniproxy.conf.original" "$tmpdir/sniproxy.backup.old"; then
    return 1
  fi
  render_mutation_started=1
  if ! backup_unmanaged_file "$DNSMASQ_SNIPPET" dnsmasq-snippet.conf ||
     ! backup_unmanaged_file "$SNIPROXY_CONFIG" sniproxy.conf ||
     ! atomic_replace "$DNSMASQ_SNIPPET" < "$dnsmasq_candidate" ||
     ! atomic_replace "$SNIPROXY_CONFIG" < "$sniproxy_candidate" ||
     ! record_managed_file dnsmasq-snippet.conf "$DNSMASQ_SNIPPET" ||
     ! record_managed_file sniproxy.conf "$SNIPROXY_CONFIG"; then
    return 1
  fi
  trap - EXIT
  if ! rm -rf "$tmpdir"; then
    warn "UNSAFE STATE: could not clean up render transaction directory; evidence retained at $tmpdir"
    return 1
  fi
)

firewall_plan() {
  local allow entry replacement old
  if ! allow=$(mktemp); then
    return 1
  fi
  trap 'remove_temp_file "$allow" || true' RETURN
  if ! parse_whitelist "$allow"; then
    remove_temp_file "$allow" || true
    trap - RETURN
    return 1
  fi
  replacement="${CHAIN}_NEW_$$"
  old="${CHAIN}_OLD_$$"
  printf 'iptables-save > firewall.before\n'
  printf 'iptables -N %s\n' "$replacement"
  while IFS= read -r entry; do
    printf 'iptables -A %s -s %s -p udp --dport 53 -m udp -j ACCEPT\n' "$replacement" "$entry"
    printf 'iptables -A %s -s %s -p tcp -m multiport --dports 53,80,443 -j ACCEPT\n' "$replacement" "$entry"
  done < "$allow"
  printf 'iptables -A %s -p udp --dport 53 -m udp -j DROP\n' "$replacement"
  printf 'iptables -A %s -p tcp -m multiport --dports 53,80,443 -j DROP\n' "$replacement"
  printf 'iptables -A %s -j RETURN\n' "$replacement"
  printf 'iptables -I INPUT 1 -j %s\n' "$replacement"
  printf 'while iptables -C INPUT -j %s; do iptables -D INPUT -j %s; done\n' "$CHAIN" "$CHAIN"
  printf 'iptables -E %s %s\n' "$CHAIN" "$old"
  printf 'iptables -E %s %s\n' "$replacement" "$CHAIN"
  printf 'iptables -F %s && iptables -X %s\n' "$old" "$old"
  trap - RETURN
  remove_temp_file "$allow"
}

firewall_apply() (
  require_root
  if [[ "$TEST_MODE" == "1" ]]; then
    firewall_plan >/dev/null
    return 0
  fi
  need_cmd iptables
  need_cmd iptables-save
  need_cmd iptables-restore
  local entry replacement old chain_exists=0 old_input_jumps=0 firewall_txdir firewall_allow firewall_snapshot firewall_snapshot_saved=0 firewall_ownership_before firewall_ownership_saved=0 retain_evidence=0
  if ! firewall_txdir=$(mktemp -d); then
    return 1
  fi
  firewall_allow="$firewall_txdir/allow"
  firewall_snapshot="$firewall_txdir/firewall.before"
  firewall_ownership_before="$firewall_txdir/ownership.before"
  # shellcheck disable=SC2329 # invoked indirectly by the EXIT trap
  firewall_rollback() {
    local result=$?
    trap - EXIT
    if [[ $result -ne 0 && ${firewall_snapshot_saved:-0} -eq 1 ]]; then
      if ! iptables-restore < "$firewall_snapshot" >/dev/null 2>&1; then
        warn "UNSAFE STATE: could not restore the previous firewall rules; firewall transaction directory: $firewall_txdir (snapshot: $firewall_snapshot)"
        exit 1
      fi
    fi
    if [[ $result -ne 0 && ${firewall_ownership_saved:-0} -eq 1 ]] &&
       ! restore_file_snapshot "$firewall_ownership_before" "$FIREWALL_OWNERSHIP"; then
      warn "UNSAFE STATE: could not restore firewall ownership proof; firewall transaction directory: $firewall_txdir"
      retain_evidence=1
      result=1
    fi
    if ! remove_temp_file "$firewall_allow"; then :; fi
    if ! remove_temp_file "$firewall_snapshot"; then :; fi
    if [[ $retain_evidence -eq 1 ]]; then
      warn "UNSAFE STATE: firewall transaction evidence retained at $firewall_txdir"
    elif ! rm -rf "$firewall_txdir"; then
      warn "could not clean up firewall transaction directory: $firewall_txdir"
    fi
    exit "$result"
  }
  trap firewall_rollback EXIT
  if ! iptables-save > "$firewall_snapshot"; then
    return 1
  fi
  firewall_snapshot_saved=1
  if ! snapshot_file "$FIREWALL_OWNERSHIP" "$firewall_ownership_before"; then
    return 1
  fi
  firewall_ownership_saved=1
  if ! firewall_snapshot_is_safe_for_management "$firewall_snapshot"; then
    warn "refusing to replace $CHAIN: missing ownership proof or unsafe chain reference"
    return 1
  fi
  old_input_jumps=$(awk -v chain="$CHAIN" '$1 == "-A" && $2 == "INPUT" { for (i=3; i<NF; i++) if ($i == "-j" && $(i+1) == chain) n++ } END { print n + 0 }' "$firewall_snapshot")
  if ! parse_whitelist "$firewall_allow"; then return 1; fi
  if iptables -L "$CHAIN" -n >/dev/null 2>&1; then
    chain_exists=1
  fi
  replacement="${CHAIN}_NEW_$$"
  old="${CHAIN}_OLD_$$"
  if ! iptables -N "$replacement"; then return 1; fi
  while IFS= read -r entry; do
    if ! iptables -A "$replacement" -s "$entry" -p udp -m udp --dport 53 -j ACCEPT ||
       ! iptables -A "$replacement" -s "$entry" -p tcp -m multiport --dports 53,80,443 -j ACCEPT; then
      return 1
    fi
  done < "$firewall_allow"
  if ! iptables -A "$replacement" -p udp -m udp --dport 53 -j DROP ||
     ! iptables -A "$replacement" -p tcp -m multiport --dports 53,80,443 -j DROP ||
     ! iptables -A "$replacement" -j RETURN ||
     ! iptables -I INPUT 1 -j "$replacement"; then
    return 1
  fi
  while [[ $old_input_jumps -gt 0 ]]; do
    if ! iptables -D INPUT -j "$CHAIN"; then return 1; fi
    old_input_jumps=$((old_input_jumps - 1))
  done
  if [[ $chain_exists -eq 1 ]]; then
    if ! firewall_recheck_no_live_reference "$CHAIN" "$firewall_txdir/before-rename"; then
      warn "refusing to rename $CHAIN: live reference check failed"
      return 1
    fi
    if ! iptables -E "$CHAIN" "$old"; then return 1; fi
  fi
  if ! iptables -E "$replacement" "$CHAIN"; then return 1; fi
  if [[ $chain_exists -eq 1 ]]; then
    if ! firewall_recheck_no_live_reference "$old" "$firewall_txdir/before-flush"; then
      warn "refusing to flush $old: live reference check failed"
      return 1
    fi
    if ! iptables -F "$old"; then return 1; fi
    if ! firewall_recheck_no_live_reference "$old" "$firewall_txdir/before-delete"; then
      warn "refusing to delete $old: live reference check failed"
      return 1
    fi
    if ! iptables -X "$old"; then return 1; fi
  fi
  if ! write_firewall_ownership; then return 1; fi
  if ! firewall_verify_live_state "$firewall_allow"; then
    warn "firewall final verification failed; rolling back"
    return 1
  fi
  trap - EXIT
  remove_temp_file "$firewall_allow" || true
  remove_temp_file "$firewall_snapshot" || true
  if ! rm -rf "$firewall_txdir"; then
    warn "could not clean up firewall transaction directory: $firewall_txdir"
  fi
)

firewall_rules_reference_named_chain() {
  local rules=$1 chain=$2
  awk -v chain="$chain" '
    $1 == "-A" {
      for (i = 3; i < NF; i++) {
        if (($i == "-j" || $i == "-g") && $(i + 1) == chain) {
          found=1
        }
      }
    }
    END { exit found ? 0 : 1 }
  ' "$rules"
}

firewall_chain_has_unmanaged_reference() {
  if firewall_rules_reference_named_chain "$1" "$CHAIN"; then
    return 1
  fi
  return 0
}

firewall_rules_reference_chain() {
  firewall_rules_reference_named_chain "$1" "$CHAIN"
}

firewall_recheck_no_live_reference() {
  local chain=$1 output=$2
  if ! iptables-save > "$output"; then
    return 1
  fi
  if firewall_rules_reference_named_chain "$output" "$chain"; then
    return 1
  fi
}

firewall_snapshot_has_only_owned_references() {
  local rules=$1
  firewall_ownership_is_valid || return 1
  awk -v chain="$CHAIN" '
    $1 == "-A" {
      for (i = 3; i < NF; i++) {
        if (($i == "-j" || $i == "-g") && $(i + 1) == chain) {
          if (!($2 == "INPUT" && $i == "-j" && i == 3 && NF == 4)) {
            found=1
          } else {
            owned++
          }
        }
      }
    }
    END { exit found || owned > 1 ? 1 : 0 }
  ' "$rules"
}

firewall_snapshot_is_safe_for_management() {
  local rules=$1 has_chain=0
  grep -Eq "^:${CHAIN}[[:space:]]" "$rules" && has_chain=1
  if firewall_ownership_is_valid; then
    firewall_snapshot_has_only_owned_references "$rules" || return 1
  else
    firewall_rules_reference_named_chain "$rules" "$CHAIN" && return 1
    [[ $has_chain -eq 0 ]] || return 1
  fi
}

firewall_ownership_is_valid() {
  [[ -e "$FIREWALL_OWNERSHIP" || -L "$FIREWALL_OWNERSHIP" ]] || return 1
  [[ -f "$FIREWALL_OWNERSHIP" ]] || return 1
  cmp -s <(printf '%s\n' "$MANAGED_MARKER firewall chain $CHAIN") "$FIREWALL_OWNERSHIP"
}

write_firewall_ownership() {
  printf '%s\n' "$MANAGED_MARKER firewall chain $CHAIN" | atomic_replace "$FIREWALL_OWNERSHIP"
}

invalidate_firewall_ownership() {
  [[ -e "$FIREWALL_OWNERSHIP" || -L "$FIREWALL_OWNERSHIP" ]] || return 0
  if ! atomic_replace "$FIREWALL_OWNERSHIP" < /dev/null; then
    warn "UNSAFE STATE: could not atomically invalidate firewall ownership proof"
    return 1
  fi
}

canonicalize_firewall_rules() {
  local source=$1 output=$2
  if ! python3 - "$source" > "$output" <<'PY'
import ipaddress
import re
import sys

source_re = re.compile(r"(^|\s)-s\s+(\S+)")
for raw in open(sys.argv[1], encoding="utf-8"):
    line = raw.rstrip("\n")
    def canonical(match):
        value = match.group(2)
        try:
            network = ipaddress.IPv4Network(value, strict=False)
        except ValueError:
            return match.group(0)
        normalized = str(network.network_address)
        if network.prefixlen != 32:
            normalized += "/" + str(network.prefixlen)
        return match.group(1) + "-s " + normalized
    line = source_re.sub(canonical, line)
    tokens = line.split()
    if any(tokens[index:index + 2] == ["-p", "udp"] for index in range(len(tokens) - 1)):
        normalized_tokens = []
        index = 0
        while index < len(tokens):
            if tokens[index:index + 2] == ["-m", "udp"]:
                index += 2
            else:
                normalized_tokens.append(tokens[index])
                index += 1
        line = " ".join(normalized_tokens)
    print(line)
PY
  then
    return 1
  fi
}

firewall_verify_live_state() {
  local allow=$1 tmpdir rules input_rules expected actual canonical_actual canonical_expected entry
  if ! tmpdir=$(mktemp -d); then
    return 1
  fi
  rules="$tmpdir/rules"
  input_rules="$tmpdir/input-rules"
  expected="$tmpdir/expected"
  actual="$tmpdir/actual"
  canonical_actual="$tmpdir/actual.canonical"
  canonical_expected="$tmpdir/expected.canonical"
  if ! iptables -L "$CHAIN" -n >/dev/null 2>&1 ||
     ! iptables -S "$CHAIN" > "$rules" 2>/dev/null ||
     ! iptables -S INPUT > "$input_rules" 2>/dev/null ||
     ! iptables-save > "$tmpdir/firewall" 2>/dev/null ||
     ! firewall_snapshot_has_only_owned_references "$tmpdir/firewall"; then
    rm -rf "$tmpdir"
    return 1
  fi
  if ! : > "$expected"; then
    rm -rf "$tmpdir"
    return 1
  fi
  while IFS= read -r entry; do
    if ! printf '%s\n' "-A $CHAIN -s $entry -p udp -m udp --dport 53 -j ACCEPT" >> "$expected" ||
       ! printf '%s\n' "-A $CHAIN -s $entry -p tcp -m multiport --dports 53,80,443 -j ACCEPT" >> "$expected"; then
      rm -rf "$tmpdir"
      return 1
    fi
  done < "$allow"
  if ! printf '%s\n' \
    "-A $CHAIN -p udp -m udp --dport 53 -j DROP" \
    "-A $CHAIN -p tcp -m multiport --dports 53,80,443 -j DROP" \
    "-A $CHAIN -j RETURN" >> "$expected" ||
     ! awk -v chain="$CHAIN" '$1 == "-A" && $2 == chain { print }' "$rules" > "$actual" ||
     ! canonicalize_firewall_rules "$actual" "$canonical_actual" ||
     ! canonicalize_firewall_rules "$expected" "$canonical_expected" ||
     ! cmp -s "$canonical_expected" "$canonical_actual"; then
    rm -rf "$tmpdir"
    return 1
  fi
  local input_jump_count first_input
  input_jump_count=$(awk -v chain="$CHAIN" '$1 == "-A" && $2 == "INPUT" { for (i=3; i<NF; i++) if ($i == "-j" && $(i+1) == chain) n++ } END { print n + 0 }' "$input_rules")
  first_input=$(awk '$1 == "-A" && $2 == "INPUT" { print; exit }' "$input_rules")
  if [[ "$input_jump_count" != 1 || "$first_input" != "-A INPUT -j $CHAIN" ]]; then
    rm -rf "$tmpdir"
    return 1
  fi
  if ! rm -rf "$tmpdir"; then
    warn "UNSAFE STATE: could not clean up firewall verification directory"
  fi
}

firewall_clear_abort() {
  local snapshot=$1 txdir=$2 message=$3
  if ! iptables-restore < "$snapshot" >/dev/null 2>&1; then
    warn "UNSAFE STATE: could not restore the pre-clear firewall snapshot; firewall transaction directory: $txdir (snapshot: $snapshot)"
    return 1
  fi
  warn "$message"
  if ! remove_temp_file "$snapshot"; then :; fi
  if ! remove_temp_file "$txdir/input-rules"; then :; fi
  if ! rm -rf "$txdir"; then
    warn "could not clean up firewall transaction directory: $txdir"
  fi
  return 1
}

firewall_cleanup_transaction() {
  local txdir=$1
  if ! remove_temp_file "$txdir/firewall.before"; then :; fi
  if ! remove_temp_file "$txdir/input-rules"; then :; fi
  if ! rm -rf "$txdir"; then
    warn "could not clean up firewall transaction directory: $txdir"
  fi
}

snapshot_source_configs() {
  local txdir=$1
  if ! snapshot_file "$SERVICES_FILE" "$txdir/services" ||
     ! snapshot_file "$WHITELIST_FILE" "$txdir/whitelist"; then
    return 1
  fi
}

restore_source_configs() {
  local txdir=$1 result=0
  if ! restore_file_snapshot "$txdir/services" "$SERVICES_FILE"; then
    warn "UNSAFE STATE: could not restore services configuration"
    result=1
  fi
  if ! restore_file_snapshot "$txdir/whitelist" "$WHITELIST_FILE"; then
    warn "UNSAFE STATE: could not restore whitelist configuration"
    result=1
  fi
  return "$result"
}

firewall_remove() {
  require_root
  [[ "$TEST_MODE" == "1" ]] && return 0
  need_cmd iptables
  need_cmd iptables-save
  need_cmd iptables-restore
  local txdir snapshot input_rules input_jumps
  if ! txdir=$(mktemp -d); then
    die "could not create firewall inspection transaction directory; refusing to remove $CHAIN"
  fi
  snapshot="$txdir/firewall.before"
  input_rules="$txdir/input-rules"
  if ! iptables-save > "$snapshot"; then
    firewall_cleanup_transaction "$txdir"
    die "could not snapshot firewall state; refusing to remove $CHAIN"
  fi
  if ! firewall_snapshot_is_safe_for_management "$snapshot"; then
    firewall_cleanup_transaction "$txdir"
    warn "refusing to remove $CHAIN: missing ownership proof or unsafe chain reference"
    return 1
  fi
  if ! grep -Eq "^:${CHAIN}[[:space:]]" "$snapshot"; then
    if ! invalidate_firewall_ownership; then
      firewall_cleanup_transaction "$txdir"
      return 1
    fi
    firewall_cleanup_transaction "$txdir"
    return 0
  fi
  if ! iptables -S INPUT > "$input_rules"; then
    firewall_cleanup_transaction "$txdir"
    die "could not inspect firewall references; refusing to remove $CHAIN"
  fi
  input_jumps=$(awk -v chain="$CHAIN" '$1 == "-A" && $2 == "INPUT" { for (i=3; i<NF; i++) if ($i == "-j" && $(i+1) == chain) n++ } END { print n + 0 }' "$input_rules")
  while [[ $input_jumps -gt 0 ]]; do
    if ! iptables -D INPUT -j "$CHAIN"; then
      firewall_clear_abort "$snapshot" "$txdir" "could not remove INPUT jump to $CHAIN"
      return 1
    fi
    input_jumps=$((input_jumps - 1))
  done
  if ! firewall_recheck_no_live_reference "$CHAIN" "$txdir/before-flush"; then
    firewall_clear_abort "$snapshot" "$txdir" "refusing to flush $CHAIN: live reference check failed"
    return 1
  fi
  if ! iptables -F "$CHAIN"; then
    firewall_clear_abort "$snapshot" "$txdir" "could not flush dedicated firewall chain $CHAIN"
    return 1
  fi
  if ! firewall_recheck_no_live_reference "$CHAIN" "$txdir/before-delete"; then
    firewall_clear_abort "$snapshot" "$txdir" "refusing to delete $CHAIN: live reference check failed"
    return 1
  fi
  if ! iptables -X "$CHAIN"; then
    firewall_clear_abort "$snapshot" "$txdir" "could not delete dedicated firewall chain $CHAIN"
    return 1
  fi
  if [[ -e "$FIREWALL_OWNERSHIP" || -L "$FIREWALL_OWNERSHIP" ]] && ! rm -f "$FIREWALL_OWNERSHIP"; then
    firewall_clear_abort "$snapshot" "$txdir" "could not remove firewall ownership proof"
    return 1
  fi
  firewall_cleanup_transaction "$txdir"
}

firewall_list() {
  [[ -r "$WHITELIST_FILE" ]] || die "missing whitelist file"
  grep -Ev '^[[:space:]]*(#|$)' "$WHITELIST_FILE" || true
}

firewall_add() {
  require_root
  local entry=${1:-} txdir candidate
  entry=$(normalize_whitelist_line "$entry") || die "unsafe or invalid IPv4/CIDR: $entry"
  validate_allow_entry "$entry" || die "unsafe or invalid IPv4/CIDR: $entry"
  if ! init_config; then return 1; fi
  if ! txdir=$(mktemp -d) ||
     ! snapshot_file "$SERVICES_FILE" "$txdir/services" ||
     ! snapshot_file "$WHITELIST_FILE" "$txdir/whitelist"; then
    rm -rf "${txdir:-}"
    return 1
  fi
  candidate="$txdir/whitelist.new"
  if ! canonicalize_whitelist_file "$WHITELIST_FILE" "$candidate"; then
    rm -rf "$txdir"
    return 1
  fi
  if ! grep -Fxq "$entry" "$candidate"; then
    if ! printf '%s\n' "$entry" >> "$candidate"; then
      rm -rf "$txdir"
      return 1
    fi
  fi
  if ! validate_effective_allowlist_coverage "$candidate"; then
    rm -rf "$txdir"
    return 1
  fi
  if ! atomic_replace "$WHITELIST_FILE" < "$candidate"; then
    rm -rf "$txdir"
    return 1
  fi
  DSU_SOURCE_TX_DIR=$txdir
  if ! apply_all; then
    if ! restore_file_snapshot "$txdir/services" "$SERVICES_FILE"; then warn "UNSAFE STATE: could not restore services configuration"; fi
    if ! restore_file_snapshot "$txdir/whitelist" "$WHITELIST_FILE"; then warn "UNSAFE STATE: could not restore whitelist configuration"; fi
    if ! rm -rf "$txdir"; then warn "UNSAFE STATE: could not clean up firewall transaction directory"; fi
    DSU_SOURCE_TX_DIR=
    return 1
  fi
  DSU_SOURCE_TX_DIR=
  if ! rm -rf "$txdir"; then
    return 1
  fi
  log "allowed $entry on DNS/HTTP/HTTPS gateway ports"
}

firewall_delete() {
  require_root
  local entry=${1:-} canonical candidate txdir
  entry=$(normalize_whitelist_line "$entry") || die "unsafe or invalid IPv4/CIDR: $entry"
  validate_allow_entry "$entry" || die "unsafe or invalid IPv4/CIDR: $entry"
  [[ "$entry" != "127.0.0.1" ]] || die "cannot remove loopback"
  [[ -r "$WHITELIST_FILE" ]] || die "missing whitelist file: $WHITELIST_FILE"
  if ! txdir=$(mktemp -d) ||
     ! snapshot_file "$SERVICES_FILE" "$txdir/services" ||
     ! snapshot_file "$WHITELIST_FILE" "$txdir/whitelist"; then
    rm -rf "${txdir:-}"
    return 1
  fi
  canonical="$txdir/whitelist.canonical"
  if ! canonicalize_whitelist_file "$WHITELIST_FILE" "$canonical"; then
    rm -rf "$txdir"
    return 1
  fi
  if ! grep -Fxq "$entry" "$canonical"; then
    rm -rf "$txdir"
    die "allowlist entry not found: $entry"
  fi
  candidate="$txdir/whitelist.new"
  if ! awk -v wanted="$entry" '$0 != wanted' "$canonical" > "$candidate"; then
    rm -rf "$txdir"
    return 1
  fi
  if ! atomic_replace "$WHITELIST_FILE" < "$candidate"; then
    rm -rf "$txdir"
    return 1
  fi
  DSU_SOURCE_TX_DIR=$txdir
  if ! apply_all; then
    if ! restore_file_snapshot "$txdir/services" "$SERVICES_FILE"; then warn "UNSAFE STATE: could not restore services configuration"; fi
    if ! restore_file_snapshot "$txdir/whitelist" "$WHITELIST_FILE"; then warn "UNSAFE STATE: could not restore whitelist configuration"; fi
    if ! rm -rf "$txdir"; then warn "UNSAFE STATE: could not clean up firewall transaction directory"; fi
    DSU_SOURCE_TX_DIR=
    return 1
  fi
  DSU_SOURCE_TX_DIR=
  if ! rm -rf "$txdir"; then
    return 1
  fi
  log "removed $entry from gateway allowlist"
}

detect_os() {
  [[ -r /etc/os-release ]] || die "cannot detect operating system"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu) printf '%s' "$ID" ;;
    *) die "supported systems: Debian and Ubuntu (detected ${ID:-unknown})" ;;
  esac
}

install_packages() {
  [[ "$TEST_MODE" == "1" ]] && return 0
  if ! detect_os >/dev/null; then
    return 1
  fi
  export DEBIAN_FRONTEND=noninteractive
  if ! apt-get update; then
    return 1
  fi
  if ! apt-get install -y dnsmasq sniproxy iptables python3 curl ca-certificates; then
    return 1
  fi
}

detect_proxy_ip() {
  local candidate=''
  candidate=$(curl -4fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)
  if validate_ipv4 "$candidate"; then printf '%s' "$candidate"; return 0; fi
  candidate=$(ip -4 route get 1.1.1.1 2>/dev/null | tr ' ' '\n' | awk 'previous=="src"{print; exit}{previous=$0}')
  validate_ipv4 "$candidate" || die "could not detect proxy IPv4; pass --proxy-ip"
  printf '%s' "$candidate"
}

install_self() {
  if ! backup_unmanaged_file "$INSTALLED_BIN" installed-bin; then
    return 1
  fi
  if ! ensure_parent "$INSTALLED_BIN" ||
     ! command install -m 0755 "${BASH_SOURCE[0]}" "$INSTALLED_BIN"; then
    return 1
  fi
  if ! record_managed_file installed-bin "$INSTALLED_BIN"; then
    return 1
  fi
}

write_firewall_unit() {
  if ! backup_unmanaged_file "$FIREWALL_UNIT" firewall-unit; then
    return 1
  fi
  if ! cat <<EOF | atomic_replace "$FIREWALL_UNIT"
# $MANAGED_MARKER
[Unit]
Description=DNS SNI Unlock isolated firewall chain
After=network-online.target
Before=dnsmasq.service sniproxy.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dns-sni-unlock firewall apply
ExecStop=/usr/local/sbin/dns-sni-unlock firewall clear
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
  then
    return 1
  fi
  if ! record_managed_file firewall-unit "$FIREWALL_UNIT"; then
    return 1
  fi
}

validate_runtime_configs() {
  [[ "$TEST_MODE" == "1" ]] && return 0
  if ! dnsmasq --test >/dev/null; then
    return 1
  fi
  if ! grep -Fq "$MANAGED_MARKER" "$SNIPROXY_CONFIG"; then
    die "SNIProxy config is not managed"
  fi
}

restart_services() {
  [[ "$TEST_MODE" == "1" ]] && return 0
  if ! systemctl daemon-reload; then
    return 1
  fi
  if ! systemctl enable dnsmasq sniproxy dns-sni-unlock-firewall.service; then
    return 1
  fi
  if ! systemctl restart dns-sni-unlock-firewall.service; then
    return 1
  fi
  if ! systemctl restart dnsmasq sniproxy; then
    return 1
  fi
}

save_firewall_snapshot() {
  local output=$1
  [[ "$TEST_MODE" == "1" ]] && return 0
  need_cmd iptables-save
  if ! iptables-save > "$output"; then
    return 1
  fi
}

restore_firewall_snapshot() {
  local snapshot=$1
  [[ -f "$snapshot" ]] || return 0
  need_cmd iptables-restore
  if ! iptables-restore < "$snapshot" >/dev/null 2>&1; then
    warn "UNSAFE STATE: could not restore the pre-install firewall snapshot; inspect iptables immediately"
    return 1
  fi
}

install_gateway() (
  require_root
  if ! install_txdir=$(mktemp -d); then
    return 1
  fi
  install_config_existed=0
  install_state_existed=0
  install_state_restore_failed=0
  install_retain_evidence=0
  install_snapshots_complete=0
  [[ -e "$CONFIG_DIR" ]] && install_config_existed=1
  [[ -e "$STATE_DIR" ]] && install_state_existed=1
  # shellcheck disable=SC2329 # invoked indirectly by the EXIT trap
  install_rollback() {
    local result=$? install_reload_failed=0
    trap - EXIT
    install_mark_unsafe() {
      warn "$1"
      install_retain_evidence=1
      result=1
    }
    if [[ $result -ne 0 && $install_snapshots_complete -eq 1 ]]; then
      if ! restore_file_snapshot "$install_txdir/services" "$SERVICES_FILE"; then install_mark_unsafe "UNSAFE STATE: could not restore services configuration"; fi
      if ! restore_file_snapshot "$install_txdir/whitelist" "$WHITELIST_FILE"; then install_mark_unsafe "UNSAFE STATE: could not restore whitelist configuration"; fi
      if ! restore_file_snapshot "$install_txdir/dnsmasq" "$DNSMASQ_SNIPPET"; then install_mark_unsafe "UNSAFE STATE: could not restore dnsmasq configuration"; fi
      if ! restore_file_snapshot "$install_txdir/sniproxy" "$SNIPROXY_CONFIG"; then install_mark_unsafe "UNSAFE STATE: could not restore SNIProxy configuration"; fi
      if ! restore_file_snapshot "$install_txdir/installed-bin" "$INSTALLED_BIN"; then install_mark_unsafe "UNSAFE STATE: could not restore installed binary"; fi
      if ! restore_file_snapshot "$install_txdir/firewall-unit" "$FIREWALL_UNIT"; then install_mark_unsafe "UNSAFE STATE: could not restore firewall unit"; fi
      if [[ "$TEST_MODE" != "1" || "${DSU_TEST_SYSTEMCTL:-0}" == "1" ]]; then
        if ! command -v systemctl >/dev/null 2>&1 || ! systemctl daemon-reload; then
          install_mark_unsafe "UNSAFE STATE: could not reload systemd after restoring firewall unit"
          install_reload_failed=1
        fi
      fi
      if ! restore_file_snapshot "$install_txdir/ownership" "$OWNERSHIP_MANIFEST"; then
        install_mark_unsafe "UNSAFE STATE: could not restore ownership manifest"
        install_state_restore_failed=1
      fi
      if ! restore_file_snapshot "$install_txdir/dnsmasq.owned" "$STATE_DIR/managed/dnsmasq-snippet.conf.current"; then
        install_mark_unsafe "UNSAFE STATE: could not restore dnsmasq ownership state"
        install_state_restore_failed=1
      fi
      if ! restore_file_snapshot "$install_txdir/sniproxy.owned" "$STATE_DIR/managed/sniproxy.conf.current"; then
        install_mark_unsafe "UNSAFE STATE: could not restore SNIProxy ownership state"
        install_state_restore_failed=1
      fi
      if ! restore_file_snapshot "$install_txdir/installed-bin.owned" "$STATE_DIR/managed/installed-bin.current"; then
        install_mark_unsafe "UNSAFE STATE: could not restore binary ownership state"
        install_state_restore_failed=1
      fi
      if ! restore_file_snapshot "$install_txdir/firewall-unit.owned" "$STATE_DIR/managed/firewall-unit.current"; then
        install_mark_unsafe "UNSAFE STATE: could not restore firewall ownership state"
        install_state_restore_failed=1
      fi
      if ! restore_file_snapshot "$install_txdir/dnsmasq.backup" "$STATE_DIR/backups/dnsmasq-snippet.conf.original"; then
        install_mark_unsafe "UNSAFE STATE: could not restore dnsmasq backup state"
        install_state_restore_failed=1
      fi
      if ! restore_file_snapshot "$install_txdir/sniproxy.backup" "$STATE_DIR/backups/sniproxy.conf.original"; then
        install_mark_unsafe "UNSAFE STATE: could not restore SNIProxy backup state"
        install_state_restore_failed=1
      fi
      if ! restore_file_snapshot "$install_txdir/firewall-ownership" "$FIREWALL_OWNERSHIP"; then
        install_mark_unsafe "UNSAFE STATE: could not restore firewall ownership proof"
        install_state_restore_failed=1
      fi
      if ! restore_file_snapshot "$install_txdir/service-state" "$STATE_DIR/service-state"; then
        install_mark_unsafe "UNSAFE STATE: could not restore service-state file"
        install_state_restore_failed=1
      fi
      if ! restore_firewall_snapshot "$install_txdir/firewall.before"; then
        install_mark_unsafe "UNSAFE STATE: could not restore the pre-install firewall snapshot; install transaction directory: $install_txdir (snapshot: $install_txdir/firewall.before)"
      fi
      if [[ $install_config_existed -eq 0 ]]; then
        if ! rm -rf "$CONFIG_DIR"; then
          install_mark_unsafe "UNSAFE STATE: could not clean up newly created CONFIG_DIR: $CONFIG_DIR"
        fi
      fi
      if [[ $install_state_existed -eq 0 && $install_state_restore_failed -eq 0 ]]; then
        if ! rm -rf "$STATE_DIR"; then
          install_mark_unsafe "UNSAFE STATE: could not clean up newly created STATE_DIR: $STATE_DIR"
        fi
      fi
      if [[ $install_reload_failed -eq 0 ]] && ! restore_service_state "$install_txdir/service.before"; then
        install_mark_unsafe "UNSAFE STATE: could not restore prior service state"
      fi
    fi
    if [[ $install_retain_evidence -eq 1 ]]; then
      warn "UNSAFE STATE: install transaction evidence retained at $install_txdir"
    elif ! rm -rf "$install_txdir"; then
      install_retain_evidence=1
      warn "UNSAFE STATE: could not clean up install transaction directory; evidence retained at $install_txdir"
      result=1
    fi
    exit "$result"
  }
  trap install_rollback EXIT
  if ! snapshot_file "$SERVICES_FILE" "$install_txdir/services" ||
     ! snapshot_file "$WHITELIST_FILE" "$install_txdir/whitelist" ||
     ! snapshot_file "$DNSMASQ_SNIPPET" "$install_txdir/dnsmasq" ||
     ! snapshot_file "$SNIPROXY_CONFIG" "$install_txdir/sniproxy" ||
     ! snapshot_file "$INSTALLED_BIN" "$install_txdir/installed-bin" ||
     ! snapshot_file "$FIREWALL_UNIT" "$install_txdir/firewall-unit" ||
     ! snapshot_file "$OWNERSHIP_MANIFEST" "$install_txdir/ownership" ||
     ! snapshot_file "$STATE_DIR/managed/dnsmasq-snippet.conf.current" "$install_txdir/dnsmasq.owned" ||
     ! snapshot_file "$STATE_DIR/managed/sniproxy.conf.current" "$install_txdir/sniproxy.owned" ||
     ! snapshot_file "$STATE_DIR/managed/installed-bin.current" "$install_txdir/installed-bin.owned" ||
     ! snapshot_file "$STATE_DIR/managed/firewall-unit.current" "$install_txdir/firewall-unit.owned" ||
     ! snapshot_file "$STATE_DIR/backups/dnsmasq-snippet.conf.original" "$install_txdir/dnsmasq.backup" ||
     ! snapshot_file "$STATE_DIR/backups/sniproxy.conf.original" "$install_txdir/sniproxy.backup" ||
     ! snapshot_file "$FIREWALL_OWNERSHIP" "$install_txdir/firewall-ownership" ||
     ! snapshot_file "$STATE_DIR/service-state" "$install_txdir/service-state" ||
     ! save_preinstall_service_state "$install_txdir/service.before" ||
     ! save_firewall_snapshot "$install_txdir/firewall.before"; then
    return 1
  fi
  install_snapshots_complete=1
  local proxy_ip='' allow_list='' arg ssh_ip install_allow_candidate
  while [[ $# -gt 0 ]]; do
    arg=$1
    case "$arg" in
      --proxy-ip) [[ $# -ge 2 ]] || die "--proxy-ip requires a value"; proxy_ip=$2; shift 2 ;;
      --allow)
        [[ $# -ge 2 ]] || die "--allow requires a value"
        [[ -z "$allow_list" ]] || allow_list="${allow_list}"$'\n'
        allow_list="${allow_list}$2"
        shift 2
        ;;
      *) die "unknown install option: $arg" ;;
    esac
  done
  if [[ ! -e "$STATE_DIR/service-state" ]]; then
    if ! save_preinstall_service_state "$STATE_DIR/service-state"; then return 1; fi
  fi
  if ! install_packages; then return 1; fi
  if [[ -z "$proxy_ip" ]] && ! proxy_ip=$(detect_proxy_ip); then return 1; fi
  validate_ipv4 "$proxy_ip" || die "invalid proxy IPv4: $proxy_ip"
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    ssh_ip=${SSH_CONNECTION%% *}
    if validate_ipv4 "$ssh_ip"; then
      [[ -z "$allow_list" ]] || allow_list="${allow_list}"$'\n'
      allow_list="${allow_list}$ssh_ip"
    fi
  fi
  [[ -n "$allow_list" ]] || die "no client allowlist entry; pass --allow <IPv4/CIDR>"
  if ! init_config "$proxy_ip"; then return 1; fi
  install_allow_candidate="$install_txdir/whitelist.new"
  if ! canonicalize_whitelist_file "$WHITELIST_FILE" "$install_allow_candidate"; then return 1; fi
  while IFS= read -r arg; do
    [[ -n "$arg" ]] || continue
    if ! arg=$(normalize_whitelist_line "$arg"); then
      die "unsafe or invalid allowlist entry"
    fi
    validate_allow_entry "$arg" || die "unsafe or invalid allowlist entry: $arg"
    grep -Fxq "$arg" "$install_allow_candidate" || printf '%s\n' "$arg" >> "$install_allow_candidate"
  done <<< "$allow_list"
  if ! validate_effective_allowlist_coverage "$install_allow_candidate"; then
    return 1
  fi
  if ! atomic_replace "$WHITELIST_FILE" < "$install_allow_candidate" ||
     ! install_self ||
     ! render_configs ||
     ! write_firewall_unit ||
     ! validate_runtime_configs; then
    return 1
  fi
  if ! restart_services; then return 1; fi
  if ! doctor; then return 1; fi
  trap - EXIT
  if ! rm -rf "$install_txdir"; then
    return 1
  fi
  log "$PROGRAM installed; proxy IPv4: $proxy_ip"
)

apply_all() (
  require_root
  if ! apply_tmpdir=$(mktemp -d); then
    return 1
  fi
  # shellcheck disable=SC2329 # invoked indirectly by the EXIT trap
  apply_setup_cleanup() {
    local result=$?
    trap - EXIT
    if ! rm -rf "$apply_tmpdir"; then
      warn "UNSAFE STATE: could not clean up apply transaction directory; evidence retained at $apply_tmpdir"
      result=1
    fi
    exit "$result"
  }
  trap apply_setup_cleanup EXIT
  apply_firewall_attempted=0
  apply_services_attempted=0
  apply_service_state="$apply_tmpdir/services.state"
  if [[ -n "${DSU_SOURCE_TX_DIR:-}" ]]; then
    apply_source_dir=$DSU_SOURCE_TX_DIR
  else
    apply_source_dir="$apply_tmpdir/source"
    if ! snapshot_file "$SERVICES_FILE" "$apply_source_dir/services" ||
       ! snapshot_file "$WHITELIST_FILE" "$apply_source_dir/whitelist"; then
      return 1
    fi
  fi
  if ! snapshot_file "$DNSMASQ_SNIPPET" "$apply_tmpdir/dnsmasq.before" ||
     ! snapshot_file "$SNIPROXY_CONFIG" "$apply_tmpdir/sniproxy.before" ||
     ! snapshot_file "$OWNERSHIP_MANIFEST" "$apply_tmpdir/ownership.before" ||
     ! snapshot_file "$STATE_DIR/managed/dnsmasq-snippet.conf.current" "$apply_tmpdir/dnsmasq.owned.before" ||
     ! snapshot_file "$STATE_DIR/managed/sniproxy.conf.current" "$apply_tmpdir/sniproxy.owned.before" ||
     ! snapshot_file "$STATE_DIR/backups/dnsmasq-snippet.conf.original" "$apply_tmpdir/dnsmasq.backup.before" ||
     ! snapshot_file "$STATE_DIR/backups/sniproxy.conf.original" "$apply_tmpdir/sniproxy.backup.before" ||
     ! snapshot_file "$FIREWALL_OWNERSHIP" "$apply_tmpdir/firewall-ownership.before" ||
     ! save_service_state "$apply_service_state"; then
    return 1
  fi
  if ! save_firewall_snapshot "$apply_tmpdir/firewall.before"; then
    return 1
  fi
  # shellcheck disable=SC2329 # invoked indirectly by the EXIT trap
  rollback_apply() {
    local result=$? retain_evidence=0
    trap - EXIT
    apply_mark_unsafe() {
      warn "$1"
      retain_evidence=1
      result=1
    }
    if [[ $result -ne 0 ]]; then
      if ! restore_file_snapshot "$apply_source_dir/services" "$SERVICES_FILE"; then apply_mark_unsafe "UNSAFE STATE: could not restore services configuration"; fi
      if ! restore_file_snapshot "$apply_source_dir/whitelist" "$WHITELIST_FILE"; then apply_mark_unsafe "UNSAFE STATE: could not restore whitelist configuration"; fi
      if ! restore_file_snapshot "$apply_tmpdir/dnsmasq.before" "$DNSMASQ_SNIPPET"; then apply_mark_unsafe "UNSAFE STATE: could not restore dnsmasq configuration"; fi
      if ! restore_file_snapshot "$apply_tmpdir/sniproxy.before" "$SNIPROXY_CONFIG"; then apply_mark_unsafe "UNSAFE STATE: could not restore SNIProxy configuration"; fi
      if ! restore_file_snapshot "$apply_tmpdir/ownership.before" "$OWNERSHIP_MANIFEST"; then apply_mark_unsafe "UNSAFE STATE: could not restore ownership manifest"; fi
      if ! restore_file_snapshot "$apply_tmpdir/dnsmasq.owned.before" "$STATE_DIR/managed/dnsmasq-snippet.conf.current"; then apply_mark_unsafe "UNSAFE STATE: could not restore dnsmasq ownership state"; fi
      if ! restore_file_snapshot "$apply_tmpdir/sniproxy.owned.before" "$STATE_DIR/managed/sniproxy.conf.current"; then apply_mark_unsafe "UNSAFE STATE: could not restore SNIProxy ownership state"; fi
      if ! restore_file_snapshot "$apply_tmpdir/dnsmasq.backup.before" "$STATE_DIR/backups/dnsmasq-snippet.conf.original"; then apply_mark_unsafe "UNSAFE STATE: could not restore dnsmasq backup state"; fi
      if ! restore_file_snapshot "$apply_tmpdir/sniproxy.backup.before" "$STATE_DIR/backups/sniproxy.conf.original"; then apply_mark_unsafe "UNSAFE STATE: could not restore SNIProxy backup state"; fi
      if ! restore_file_snapshot "$apply_tmpdir/firewall-ownership.before" "$FIREWALL_OWNERSHIP"; then apply_mark_unsafe "UNSAFE STATE: could not restore firewall ownership proof"; fi
      if [[ $apply_firewall_attempted -eq 1 ]] && ! restore_firewall_snapshot "$apply_tmpdir/firewall.before"; then
        apply_mark_unsafe "UNSAFE STATE: could not restore prior firewall state; apply transaction directory: $apply_tmpdir (snapshot: $apply_tmpdir/firewall.before)"
      fi
      if [[ $apply_services_attempted -eq 1 ]] && ! restore_service_state "$apply_service_state"; then
        apply_mark_unsafe "UNSAFE STATE: could not restore prior service state"
      fi
    fi
    if [[ $retain_evidence -eq 1 ]]; then
      warn "UNSAFE STATE: apply transaction evidence retained at $apply_tmpdir"
    elif ! rm -rf "$apply_tmpdir"; then
      warn "UNSAFE STATE: could not clean up apply transaction directory; evidence retained at $apply_tmpdir"
      result=1
    fi
    exit "$result"
  }
  trap rollback_apply EXIT
  if ! render_configs; then return 1; fi
  if ! validate_runtime_configs; then return 1; fi
  apply_firewall_attempted=1
  if ! firewall_apply; then return 1; fi
  apply_services_attempted=1
  if ! restart_services; then return 1; fi
  trap - EXIT
  if ! rm -rf "$apply_tmpdir"; then
    return 1
  fi
  log "configuration applied"
)

service_list() {
  [[ -r "$SERVICES_FILE" ]] || die "missing services file"
  grep -Ev '^[[:space:]]*(#|$)' "$SERVICES_FILE" || true
}

service_add() {
  require_root
  local name=${1:-} ip=${2:-} txdir; shift 2 || true
  [[ $# -gt 0 ]] || die "service add requires at least one domain"
  validate_service_name "$name" || die "invalid service name"
  validate_ipv4 "$ip" || die "invalid IPv4: $ip"
  if ! init_config; then return 1; fi
  if awk -F '|' -v name="$name" '$1 == name { found=1 } END { exit(found ? 0 : 1) }' "$SERVICES_FILE"; then
    die "service already exists: $name"
  fi
  if ! txdir=$(mktemp -d) || ! snapshot_source_configs "$txdir"; then
    rm -rf "${txdir:-}"
    return 1
  fi
  local domains='' domain normalized candidate
  for domain in "$@"; do
    normalized=$(normalize_domain "$domain")
    validate_domain "$normalized" || die "invalid domain: $domain"
    domains="${domains}${domains:+ }$normalized"
  done
  candidate="$txdir/services.new"
  if ! awk -v name="$name" -v ip="$ip" -v domains="$domains" \
    'BEGIN { print name "|" ip "|" domains }' > "$candidate"; then
    rm -rf "$txdir"
    return 1
  fi
  if ! cat "$SERVICES_FILE" >> "$candidate" || ! atomic_replace "$SERVICES_FILE" < "$candidate"; then
    rm -rf "$txdir"
    return 1
  fi
  DSU_SOURCE_TX_DIR=$txdir
  if ! apply_all; then
    if ! restore_source_configs "$txdir"; then
      :
    fi
    if ! rm -rf "$txdir"; then
      warn "UNSAFE STATE: could not clean up service transaction directory"
    fi
    DSU_SOURCE_TX_DIR=
    return 1
  fi
  DSU_SOURCE_TX_DIR=
  if ! rm -rf "$txdir"; then
    return 1
  fi
}

service_remove() {
  require_root
  local name=${1:-} candidate txdir
  [[ -n "$name" ]] || die "service remove requires a name"
  if ! txdir=$(mktemp -d) || ! snapshot_source_configs "$txdir"; then
    rm -rf "${txdir:-}"
    return 1
  fi
  candidate="$txdir/services.new"
  if ! awk -F '|' -v n="$name" '$1 != n' "$SERVICES_FILE" > "$candidate"; then
    rm -rf "$txdir"
    return 1
  fi
  if cmp -s "$candidate" "$SERVICES_FILE"; then
    rm -rf "$txdir"
    die "service not found: $name"
  fi
  if ! atomic_replace "$SERVICES_FILE" < "$candidate"; then
    rm -rf "$txdir"
    return 1
  fi
  DSU_SOURCE_TX_DIR=$txdir
  if ! apply_all; then
    if ! restore_source_configs "$txdir"; then
      :
    fi
    if ! rm -rf "$txdir"; then
      warn "UNSAFE STATE: could not clean up service transaction directory"
    fi
    DSU_SOURCE_TX_DIR=
    return 1
  fi
  DSU_SOURCE_TX_DIR=
  if ! rm -rf "$txdir"; then
    return 1
  fi
}

service_set_ip() {
  require_root
  local name=${1:-} ip=${2:-} candidate txdir
  validate_ipv4 "$ip" || die "invalid IPv4: $ip"
  if ! txdir=$(mktemp -d) || ! snapshot_source_configs "$txdir"; then
    rm -rf "${txdir:-}"
    return 1
  fi
  candidate="$txdir/services.new"
  if ! awk -F '|' -v OFS='|' -v n="$name" -v ip="$ip" '$1==n{$2=ip; found=1} {print} END{if(!found) exit 3}' "$SERVICES_FILE" > "$candidate"; then
    rm -rf "$txdir"
    die "service not found: $name"
  fi
  if ! atomic_replace "$SERVICES_FILE" < "$candidate"; then
    rm -rf "$txdir"
    return 1
  fi
  DSU_SOURCE_TX_DIR=$txdir
  if ! apply_all; then
    if ! restore_source_configs "$txdir"; then
      :
    fi
    if ! rm -rf "$txdir"; then
      warn "UNSAFE STATE: could not clean up service transaction directory"
    fi
    DSU_SOURCE_TX_DIR=
    return 1
  fi
  DSU_SOURCE_TX_DIR=
  if ! rm -rf "$txdir"; then
    return 1
  fi
}

status() {
  printf '%s %s\n' "$PROGRAM" "$VERSION"
  if [[ "$TEST_MODE" == "1" ]]; then printf 'test mode\n'; return 0; fi
  local unit state
  for unit in dnsmasq sniproxy dns-sni-unlock-firewall.service; do
    state=$(systemctl is-active "$unit" 2>/dev/null || true)
    printf '%-36s %s\n' "$unit" "${state:-not-found}"
  done
  printf 'services: %s\n' "$(grep -Evc '^[[:space:]]*(#|$)' "$SERVICES_FILE" 2>/dev/null || true)"
  printf 'allowed clients: %s\n' "$(grep -Evc '^[[:space:]]*(#|$)' "$WHITELIST_FILE" 2>/dev/null || true)"
}

doctor_configs_match() {
  local tmpdir expected_dnsmasq expected_sniproxy
  tmpdir=$(mktemp -d) || return 1
  expected_dnsmasq="$tmpdir/dnsmasq"
  expected_sniproxy="$tmpdir/sniproxy"
  if ! generate_config_files "$expected_dnsmasq" "$expected_sniproxy" ||
     ! cmp -s "$expected_dnsmasq" "$DNSMASQ_SNIPPET" ||
     ! cmp -s "$expected_sniproxy" "$SNIPROXY_CONFIG"; then
    if ! rm -rf "$tmpdir"; then
      warn "UNSAFE STATE: could not clean up doctor transaction directory"
    fi
    return 1
  fi
  if ! rm -rf "$tmpdir"; then
    warn "UNSAFE STATE: could not clean up doctor transaction directory"
    return 1
  fi
}

doctor() {
  require_root
  local failed=0 unit
  for unit in dnsmasq sniproxy dns-sni-unlock-firewall.service; do
    if [[ "$TEST_MODE" != "1" ]] && [[ "$(systemctl is-active "$unit" 2>/dev/null || true)" != "active" ]]; then
      warn "$unit is not active"; failed=1
    fi
  done
  if [[ ! -s "$DNSMASQ_SNIPPET" ]]; then warn "missing dnsmasq snippet"; failed=1; fi
  if [[ ! -s "$SNIPROXY_CONFIG" ]]; then warn "missing sniproxy config"; failed=1; fi
  if ! doctor_configs_match; then
    warn "generated configuration does not match source files"
    failed=1
  fi
  if [[ "$TEST_MODE" != "1" || "${DSU_TEST_FIREWALL:-0}" == "1" ]]; then
    doctor_firewall || failed=1
  fi
  [[ $failed -eq 0 ]] || return 1
  log "doctor: all checks passed"
}

doctor_firewall() {
  local tmpdir allow
  need_cmd iptables
  need_cmd iptables-save
  if ! tmpdir=$(mktemp -d); then
    warn "could not create firewall inspection directory"
    return 1
  fi
  allow="$tmpdir/allow"
  if ! parse_whitelist "$allow" || ! firewall_verify_live_state "$allow"; then
    warn "live firewall chain is missing, unowned, or incorrect"
    if ! rm -rf "$tmpdir"; then
      warn "UNSAFE STATE: could not clean up firewall inspection directory"
    fi
    return 1
  fi
  if ! rm -rf "$tmpdir"; then
    warn "UNSAFE STATE: could not clean up firewall inspection directory"
    return 1
  fi
}

uninstall_gateway() {
  require_root
  [[ "${1:-}" == "--yes" ]] || die "uninstall is destructive; rerun with: uninstall --yes"
  local failed=0 preserved=0 restore_result restore_target restore_label uninstall_txdir=''
  if [[ "$TEST_MODE" != "1" ]]; then
    need_cmd iptables
    need_cmd iptables-save
    need_cmd iptables-restore
  fi
  if ! uninstall_txdir=$(mktemp -d) ||
     ! snapshot_file "$CONFIG_DIR" "$uninstall_txdir/config.before" ||
     ! snapshot_file "$STATE_DIR" "$uninstall_txdir/state.before" ||
     ! snapshot_file "$FIREWALL_UNIT" "$uninstall_txdir/firewall-unit.before" ||
     ! snapshot_file "$DNSMASQ_SNIPPET" "$uninstall_txdir/dnsmasq.before" ||
     ! snapshot_file "$SNIPROXY_CONFIG" "$uninstall_txdir/sniproxy.before" ||
     ! snapshot_file "$INSTALLED_BIN" "$uninstall_txdir/installed-bin.before"; then
    warn "INCOMPLETE UNINSTALL: could not snapshot file, ownership, and runtime state"
    [[ -n "$uninstall_txdir" ]] && warn "recovery evidence retained at $uninstall_txdir"
    return 1
  fi
  if [[ "$TEST_MODE" != "1" ]]; then
    if ! save_unit_state "$uninstall_txdir/services.before" dnsmasq sniproxy dns-sni-unlock-firewall.service ||
       ! save_firewall_snapshot "$uninstall_txdir/firewall.before"; then
      warn "INCOMPLETE UNINSTALL: could not snapshot service or firewall state; recovery evidence retained at $uninstall_txdir"
      return 1
    fi
  fi
  uninstall_abort() {
    local reason=$1 rollback_failed=0
    if [[ "$TEST_MODE" != "1" ]] && ! restore_firewall_snapshot "$uninstall_txdir/firewall.before"; then
      warn "UNSAFE STATE: could not restore firewall state during uninstall rollback"
      rollback_failed=1
    fi
    if ! restore_file_snapshot "$uninstall_txdir/firewall-unit.before" "$FIREWALL_UNIT"; then
      warn "UNSAFE STATE: could not restore firewall unit during uninstall rollback"
      rollback_failed=1
    fi
    if ! restore_file_snapshot "$uninstall_txdir/dnsmasq.before" "$DNSMASQ_SNIPPET"; then
      warn "UNSAFE STATE: could not restore dnsmasq configuration during uninstall rollback"
      rollback_failed=1
    fi
    if ! restore_file_snapshot "$uninstall_txdir/sniproxy.before" "$SNIPROXY_CONFIG"; then
      warn "UNSAFE STATE: could not restore SNIProxy configuration during uninstall rollback"
      rollback_failed=1
    fi
    if ! restore_file_snapshot "$uninstall_txdir/installed-bin.before" "$INSTALLED_BIN"; then
      warn "UNSAFE STATE: could not restore installed binary during uninstall rollback"
      rollback_failed=1
    fi
    if ! restore_file_snapshot "$uninstall_txdir/config.before" "$CONFIG_DIR"; then
      warn "UNSAFE STATE: could not restore configuration and ownership inputs during uninstall rollback"
      rollback_failed=1
    fi
    if ! restore_file_snapshot "$uninstall_txdir/state.before" "$STATE_DIR"; then
      warn "UNSAFE STATE: could not restore state and ownership evidence during uninstall rollback"
      rollback_failed=1
    fi
    if [[ "$TEST_MODE" != "1" ]]; then
      if ! systemctl daemon-reload >/dev/null 2>&1; then
        warn "UNSAFE STATE: could not reload systemd after uninstall rollback"
        rollback_failed=1
      fi
      if ! restore_service_state "$uninstall_txdir/services.before"; then
        warn "UNSAFE STATE: could not restore prior service state during uninstall rollback"
        rollback_failed=1
      fi
    fi
    if [[ $rollback_failed -ne 0 ]]; then
      warn "UNSAFE STATE: uninstall rollback failed; transaction evidence retained at $uninstall_txdir"
      return 1
    fi
    if ! rm -rf "$uninstall_txdir"; then
      warn "UNSAFE STATE: could not clean up uninstall transaction evidence; retained at $uninstall_txdir"
      return 1
    fi
    warn "INCOMPLETE UNINSTALL: $reason; rollback completed and prior state was restored"
    return 1
  }
  if ! ownership_manifest_proves_managed_files; then
    warn "INCOMPLETE UNINSTALL: ownership manifest is missing or does not prove ownership of all managed files"
    warn "recovery evidence retained at $uninstall_txdir"
    return 1
  fi
  if [[ "$TEST_MODE" != "1" ]]; then
    if ! systemctl disable --now dns-sni-unlock-firewall.service 2>/dev/null; then
      uninstall_abort "could not stop the firewall service"
      return 1
    fi
    if ! firewall_remove; then
      uninstall_abort "could not clear the firewall"
      return 1
    fi
    if ! systemctl stop sniproxy dnsmasq 2>/dev/null; then
      uninstall_abort "could not stop gateway services"
      return 1
    fi
  fi
  for restore_item in \
    "$FIREWALL_UNIT|firewall-unit" \
    "$DNSMASQ_SNIPPET|dnsmasq-snippet.conf" \
    "$SNIPROXY_CONFIG|sniproxy.conf" \
    "$INSTALLED_BIN|installed-bin"; do
    IFS='|' read -r restore_target restore_label <<< "$restore_item"
    if restore_original_or_remove_managed "$restore_target" "$restore_label"; then
      :
    else
      restore_result=$?
      if [[ $restore_result -eq 2 ]]; then
        preserved=1
      else
        failed=1
      fi
    fi
  done
  if [[ $failed -ne 0 || $preserved -ne 0 ]]; then
    uninstall_abort "managed files were not fully restored"
    return 1
  fi
  if [[ "$TEST_MODE" != "1" ]]; then
    if ! systemctl daemon-reload; then
      uninstall_abort "could not reload systemd after removing the firewall unit"
      return 1
    fi
  fi
  if ! rm -rf "$CONFIG_DIR" "$STATE_DIR"; then
    uninstall_abort "could not remove configuration and state directories"
    return 1
  fi
  if ! rm -rf "$uninstall_txdir"; then
    warn "INCOMPLETE UNINSTALL: could not clean up uninstall transaction evidence; recovery evidence retained at $uninstall_txdir"
    return 1
  fi
  log "$PROGRAM configuration removed; installed packages were preserved"
}

show_help() {
  cat <<'EOF'
dns-sni-unlock 3.0.0

Safely manage an allowlisted dnsmasq + SNIProxy gateway on Debian/Ubuntu.

Usage:
  dns-sni-unlock.sh install --allow <IPv4/CIDR> [--allow <IPv4/CIDR> ...] [--proxy-ip <IPv4>]
  dns-sni-unlock.sh apply
  dns-sni-unlock.sh status | doctor
  dns-sni-unlock.sh service list
  dns-sni-unlock.sh service add <name> <proxy-ip> <domain> [domain ...]
  dns-sni-unlock.sh service set-ip <name> <proxy-ip>
  dns-sni-unlock.sh service remove <name>
  dns-sni-unlock.sh firewall list
  dns-sni-unlock.sh firewall add <IPv4/CIDR>
  dns-sni-unlock.sh firewall remove <IPv4/CIDR>
  dns-sni-unlock.sh firewall apply | clear | plan
  dns-sni-unlock.sh uninstall --yes
  dns-sni-unlock.sh --help | --version

Developer/test commands:
  init-config [proxy-ip]
  render
  validate-ip <IPv4>
  validate-cidr <IPv4/CIDR>
  validate-domain <domain>
  firewall-plan

Security properties:
  - Never flushes INPUT/FORWARD/OUTPUT or changes their default policies.
  - Uses only the dedicated DNS_SNI_UNLOCK_IN chain.
  - Requires an explicit client allowlist and has no catch-all SNI route.
  - Backs up an existing /etc/sniproxy.conf before taking ownership.
EOF
}

show_menu() {
  require_root
  while true; do
    cat <<'EOF'

DNS + SNI gateway
1) Status
2) Doctor
3) List routes
4) List allowed clients
5) Apply configuration
0) Exit
EOF
    read -r -p 'Select [0-5]: ' choice
    case "$choice" in
      1) status ;;
      2) doctor ;;
      3) service_list ;;
      4) firewall_list ;;
      5) apply_all ;;
      0) return 0 ;;
      *) warn "invalid selection" ;;
    esac
  done
}

main() {
  local command=${1:-menu}
  [[ $# -eq 0 ]] || shift
  case "$command" in
    --version|-V|version) printf '%s %s\n' "$PROGRAM" "$VERSION" ;;
    --help|-h|help) show_help ;;
    validate-ip) validate_ipv4 "${1:-}" || exit 1 ;;
    validate-cidr) validate_cidr "${1:-}" || exit 1 ;;
    validate-domain) validate_domain "${1:-}" || exit 1 ;;
    init-config) init_config "${1:-127.0.0.1}" ;;
    render) render_configs ;;
    firewall-plan) firewall_plan ;;
    install) install_gateway "$@" ;;
    apply) apply_all ;;
    status) status ;;
    doctor) doctor ;;
    service)
      local sub=${1:-}; [[ $# -eq 0 ]] || shift
      case "$sub" in
        list) service_list ;;
        add) service_add "$@" ;;
        set-ip) service_set_ip "$@" ;;
        remove) service_remove "$@" ;;
        *) die "unknown service command: ${sub:-missing}" ;;
      esac ;;
    firewall)
      local sub=${1:-}; [[ $# -eq 0 ]] || shift
      case "$sub" in
        list) firewall_list ;;
        add) firewall_add "$@" ;;
        remove) firewall_delete "$@" ;;
        apply) firewall_apply ;;
        clear) firewall_remove ;;
        plan) firewall_plan ;;
        *) die "unknown firewall command: ${sub:-missing}" ;;
      esac ;;
    uninstall) uninstall_gateway "$@" ;;
    menu) show_menu ;;
    *) die "unknown command: $command (try --help)" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
