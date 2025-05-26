#!/bin/bash
# 流媒体解锁脚本 - 基于DNS+SNIProxy
# 支持Netflix、Disney+、TikTok、YouTube、OpenAI、Claude、Gemini、xAI等服务解锁
# 版本: 2.3

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PLAIN="\033[0m"
CONFIG_DIR="/etc/dnsmasq.d"
DNSMASQ_CONFIG="/etc/dnsmasq.conf"
SNIPROXY_CONFIG="/etc/sniproxy.conf"
SERVICE_CONFIG="/root/dns_unlock_services.conf"
WHITELIST_FILE="/root/firewall_whitelist_ips.txt"
DEFAULT_IP="127.0.0.1"
PROTECTED_PORTS=("53" "80" "443")

check_root() {
  [ "$(id -u)" != "0" ] && echo -e "${RED}错误: 请使用root权限运行此脚本!${PLAIN}" && exit 1
}

check_system() {
  if [ -f /etc/redhat-release ]; then RELEASE="centos"
  elif grep -Eqi "debian" /etc/issue; then RELEASE="debian"
  elif grep -Eqi "ubuntu" /etc/issue; then RELEASE="ubuntu"
  elif grep -Eqi "centos|red hat|redhat" /etc/issue; then RELEASE="centos"
  elif grep -Eqi "debian|raspbian" /proc/version; then RELEASE="debian"
  elif grep -Eqi "ubuntu" /proc/version; then RELEASE="ubuntu"
  elif grep -Eqi "centos|red hat|redhat" /proc/version; then RELEASE="centos"
  else echo -e "${RED}系统不支持，请使用CentOS/Debian/Ubuntu系统！${PLAIN}" && exit 1
  fi
}

install_packages() {
  echo -e "${BLUE}开始安装必要软件...${PLAIN}"
  if [ "${RELEASE}" == "centos" ]; then
    yum update -y
    yum install -y epel-release
    yum install -y bind-utils dnsmasq curl wget git make gcc openssl-devel libevent-devel iptables iptables-services
  elif [ "${RELEASE}" == "debian" ] || [ "${RELEASE}" == "ubuntu" ]; then
    apt-get update -y
    apt-get install -y dnsutils dnsmasq curl wget git build-essential libudns-dev libev-dev libpcre3-dev iptables iptables-persistent
  fi
  echo -e "${GREEN}必要软件安装完成!${PLAIN}"
}

install_sniproxy() {
  echo -e "${BLUE}安装SNIProxy...${PLAIN}"
  if [ "${RELEASE}" == "debian" ] || [ "${RELEASE}" == "ubuntu" ]; then
    apt-get update -y
    apt-get install -y sniproxy
  elif [ "${RELEASE}" == "centos" ]; then
    yum install -y epel-release
    yum install -y sniproxy
  else
    cd /tmp
    rm -rf sniproxy
    git clone https://github.com/dlundquist/sniproxy.git
    cd sniproxy
    ./autogen.sh
    ./configure
    make
    make install
    mkdir -p /etc/sniproxy
  fi
  echo -e "${GREEN}SNIProxy安装完成!${PLAIN}"
}

config_dnsmasq() {
  echo -e "${BLUE}配置dnsmasq...${PLAIN}"
  [ -f "$DNSMASQ_CONFIG" ] && cp "$DNSMASQ_CONFIG" "$DNSMASQ_CONFIG.bak.$(date +%Y%m%d%H%M%S)"
  mkdir -p $CONFIG_DIR
  cat > "$DNSMASQ_CONFIG" << EOF
server=8.8.8.8
server=8.8.4.4
listen-address=127.0.0.1
cache-size=1024
no-hosts
conf-dir=/etc/dnsmasq.d/,*.conf
EOF
  echo -e "${GREEN}dnsmasq配置完成!${PLAIN}"
}

config_sniproxy() {
  echo -e "${BLUE}配置SNIProxy...${PLAIN}"
  cat > "$SNIPROXY_CONFIG" << EOF
user nobody
listener 80 {
    protocol http
}
listener 443 {
    protocol tls
}
table {
    .* *
}
resolver {
    nameserver 8.8.8.8
    nameserver 1.1.1.1
}
EOF
  echo -e "${GREEN}SNIProxy配置完成!${PLAIN}"
}

create_service_files() {
  echo -e "${BLUE}创建服务文件...${PLAIN}"
  cat > /etc/systemd/system/sniproxy.service << EOF
[Unit]
Description=SNI Proxy
After=network.target
[Service]
Type=simple
ExecStart=/usr/sbin/sniproxy -c $SNIPROXY_CONFIG -f
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -TERM \$MAINPID
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  echo -e "${GREEN}服务文件创建完成!${PLAIN}"
}

fix_sniproxy() {
  echo -e "${BLUE}尝试修复SNIProxy...${PLAIN}"
  systemctl stop sniproxy
  config_sniproxy
  create_service_files
  systemctl restart sniproxy
  systemctl enable sniproxy
  if systemctl is-active sniproxy &> /dev/null; then
    echo -e "${GREEN}SNIProxy已修复并成功启动!${PLAIN}"
  else
    echo -e "${RED}SNIProxy启动失败，尝试重新安装...${PLAIN}"
    install_sniproxy
    config_sniproxy
    systemctl restart sniproxy
    if systemctl is-active sniproxy &> /dev/null; then
      echo -e "${GREEN}SNIProxy已重装并成功启动!${PLAIN}"
    else
      echo -e "${RED}SNIProxy仍然无法启动，请检查日志: journalctl -u sniproxy${PLAIN}"
    fi
  fi
}

init_service_config() {
  if [ ! -f "$SERVICE_CONFIG" ]; then
    echo -e "${BLUE}初始化服务配置...${PLAIN}"
    cat > "$SERVICE_CONFIG" << EOF
TikTok:${DEFAULT_IP}:tiktok.com tiktok.org bytedance.com tiktokv.com tiktokcdn.com musical.ly lemon8-app.com capcut.com
OpenAI:${DEFAULT_IP}:openai.com chat.openai.com platform.openai.com api.openai.com auth0.openai.com
Claude:${DEFAULT_IP}:anthropic.com claude.ai console.anthropic.com
Gemini:${DEFAULT_IP}:gemini.google.com generativelanguage.googleapis.com bard.google.com ai.google.dev makersuite.google.com
xAI:${DEFAULT_IP}:x.ai grok.x.ai api.x.ai
Netflix:${DEFAULT_IP}:netflix.com netflix.net nflxext.com nflximg.net nflxso.net nflxvideo.net netflixdnstest0.com netflixdnstest1.com netflixdnstest2.com netflixdnstest3.com netflixdnstest4.com netflixdnstest5.com
Disney:${DEFAULT_IP}:disney.com disneyjunior.com disney-plus.net disney-portal.my.onetrust.com disney.demdex.net disney.my.sentry.io disneyplus.bn5x.net disneyplus.com disneyplus.com.ssl.sc.omtrdc.net disneystreaming.com dssott.com bamgrid.com cdn.registerdisney.go.com cws.conviva.com
YouTube:${DEFAULT_IP}:youtube.com youtu.be googleapis.com gstatic.com ytimg.com googlevideo.com youtube-nocookie.com ggpht.com googleusercontent.com
EOF
    echo -e "${GREEN}服务配置初始化完成!${PLAIN}"
  fi
}

apply_service_config() {
  echo -e "${BLUE}应用服务配置...${PLAIN}"
  rm -f $CONFIG_DIR/*.conf
  while IFS=':' read -r service ip domains || [ -n "$service" ]; do
    [[ "$service" =~ ^#.*$ || -z "$service" ]] && continue
    conf_file="$CONFIG_DIR/${service,,}.conf"
    echo "# $service 解锁配置" > "$conf_file"
    for domain in $domains; do
      echo "address=/$domain/$ip" >> "$conf_file"
    done
    echo -e "${GREEN}已配置服务: $service (IP: $ip)${PLAIN}"
  done < "$SERVICE_CONFIG"
  echo -e "${GREEN}服务配置应用完成!${PLAIN}"
}

init_firewall_whitelist() {
  mkdir -p /root
  if [ ! -f "$WHITELIST_FILE" ]; then
    echo -e "${BLUE}初始化防火墙白名单...${PLAIN}"
    echo "127.0.0.1" > "$WHITELIST_FILE"
    CURRENT_IP=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me)
    if [ -n "$CURRENT_IP" ]; then
      echo "$CURRENT_IP" >> "$WHITELIST_FILE"
      echo -e "${GREEN}已添加当前IP: $CURRENT_IP 到白名单${PLAIN}"
    fi
    echo -e "${GREEN}防火墙白名单初始化完成!${PLAIN}"
  fi
}

apply_firewall_rules() {
  echo -e "${BLUE}正在应用防火墙规则...${PLAIN}"
  iptables -F
  iptables -X
  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -i lo -j ACCEPT
  while IFS= read -r IP; do
    for PORT in "${PROTECTED_PORTS[@]}"; do
      [ "$PORT" = "53" ] && iptables -A INPUT -p udp -s "$IP" --dport 53 -j ACCEPT
      iptables -A INPUT -p tcp -s "$IP" --dport "$PORT" -j ACCEPT
    done
  done < "$WHITELIST_FILE"
  for PORT in "${PROTECTED_PORTS[@]}"; do
    [ "$PORT" = "53" ] && iptables -A INPUT -p udp --dport 53 -j DROP
    iptables -A INPUT -p tcp --dport "$PORT" -j DROP
  done
  if [ "${RELEASE}" == "centos" ]; then
    service iptables save
  elif [ "${RELEASE}" == "debian" ] || [ "${RELEASE}" == "ubuntu" ]; then
    netfilter-persistent save > /dev/null 2>&1
    netfilter-persistent reload > /dev/null 2>&1
  fi
  echo -e "${GREEN}防火墙规则已应用!${PLAIN}"
}

add_ip_to_whitelist() {
  read -p "请输入要添加到白名单的IP: " new_ip
  if [ -z "$new_ip" ] || ! [[ $new_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}IP格式不正确!${PLAIN}"
    return
  fi
  if grep -Fxq "$new_ip" "$WHITELIST_FILE"; then
    echo -e "${YELLOW}IP $new_ip 已存在于白名单中.${PLAIN}"
    return
  fi
  echo "$new_ip" >> "$WHITELIST_FILE"
  echo -e "${GREEN}已添加IP: $new_ip 到白名单.${PLAIN}"
  apply_firewall_rules
}

remove_ip_from_whitelist() {
  echo -e "${BLUE}当前白名单IP:${PLAIN}"
  cat -n "$WHITELIST_FILE"
  read -p "请输入要移除的IP编号: " ip_num
  if ! [[ "$ip_num" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}无效选择!${PLAIN}"
    return
  fi
  selected_ip=$(sed -n "${ip_num}p" "$WHITELIST_FILE")
  if [ -z "$selected_ip" ]; then
    echo -e "${RED}IP不存在!${PLAIN}"
    return
  fi
  read -p "确定要移除IP $selected_ip? (y/n): " confirm
  if [ "$confirm" != "y" ]; then
    echo -e "${GREEN}操作已取消${PLAIN}"
    return
  fi
  sed -i "${ip_num}d" "$WHITELIST_FILE"
  echo -e "${GREEN}已移除IP: $selected_ip${PLAIN}"
  apply_firewall_rules
}

manage_firewall() {
  clear
  echo -e "防火墙管理"
  echo -e "----------------------------------------"
  echo -e "1. 查看白名单IP"
  echo -e "2. 添加IP到白名单"
  echo -e "3. 移除白名单IP"
  echo -e "4. 应用防火墙规则"
  echo -e "5. 关闭防火墙"
  echo -e "0. 返回主菜单"
  echo -e "----------------------------------------"
  read -p "请输入选项 [0-5]: " option
  case $option in
    1)
      echo -e "${YELLOW}当前白名单IP:${PLAIN}"
      [ -f "$WHITELIST_FILE" ] && cat -n "$WHITELIST_FILE" || echo -e "${RED}白名单文件不存在!${PLAIN}"
      ;;
    2) add_ip_to_whitelist ;;
    3) remove_ip_from_whitelist ;;
    4) apply_firewall_rules ;;
    5)
      echo -e "${YELLOW}警告: 关闭防火墙将允许所有IP访问您的服务。${PLAIN}"
      read -p "确定要继续吗? (y/n): " confirm
      if [ "$confirm" != "y" ]; then
        echo -e "${GREEN}操作已取消${PLAIN}"
        return
      fi
      iptables -F
      iptables -X
      if [ "${RELEASE}" == "centos" ]; then
        service iptables save
      elif [ "${RELEASE}" == "debian" ] || [ "${RELEASE}" == "ubuntu" ]; then
        netfilter-persistent save > /dev/null 2>&1
      fi
      echo -e "${GREEN}防火墙已关闭!${PLAIN}"
      ;;
    0) return ;;
    *) echo -e "${RED}无效选项!${PLAIN}" ;;
  esac
  read -p "按任意键继续..." key
  manage_firewall
}

start_services() {
  echo -e "${BLUE}启动服务...${PLAIN}"
  systemctl restart dnsmasq
  systemctl enable dnsmasq
  systemctl restart sniproxy
  systemctl enable sniproxy
  echo -e "${GREEN}服务已启动!${PLAIN}"
}

restart_services() {
  echo -e "${BLUE}重启服务...${PLAIN}"
  systemctl restart dnsmasq
  systemctl restart sniproxy
  echo -e "${GREEN}服务已重启!${PLAIN}"
}

check_status() {
  echo -e "${BLUE}服务状态:${PLAIN}"
  echo -e "${YELLOW}dnsmasq状态:${PLAIN}"
  systemctl status dnsmasq --no-pager
  echo -e "${YELLOW}sniproxy状态:${PLAIN}"
  systemctl status sniproxy --no-pager
  echo -e "${YELLOW}当前服务配置:${PLAIN}"
  grep -v "^#" "$SERVICE_CONFIG" | while IFS=':' read -r service ip domains; do
    [ -z "$service" ] && continue
    echo -e "${GREEN}$service${PLAIN} - IP: ${YELLOW}$ip${PLAIN}"
    echo -e "   域名: ${BLUE}$domains${PLAIN}"
  done
  echo -e "${YELLOW}防火墙白名单IP:${PLAIN}"
  [ -f "$WHITELIST_FILE" ] && cat -n "$WHITELIST_FILE" || echo -e "${RED}白名单文件不存在!${PLAIN}"
}

change_service_ip() {
  echo -e "${BLUE}当前服务配置:${PLAIN}"
  local services=()
  local i=1
  while IFS=':' read -r service ip domains; do
    [[ "$service" =~ ^#.*$ || -z "$service" ]] && continue
    services+=("$service")
    echo -e "$i. ${GREEN}$service${PLAIN} - 当前IP: ${YELLOW}$ip${PLAIN}"
    ((i++))
  done < "$SERVICE_CONFIG"
  read -p "请选择要更改IP的服务 [1-$((i-1))]: " service_num
  if ! [[ "$service_num" =~ ^[0-9]+$ ]] || [ "$service_num" -lt 1 ] || [ "$service_num" -gt $((i-1)) ]; then
    echo -e "${RED}无效选择!${PLAIN}"
    return
  fi
  selected_service="${services[$((service_num-1))]}"
  current_ip=$(grep "^$selected_service:" "$SERVICE_CONFIG" | cut -d':' -f2)
  read -p "当前 $selected_service 解锁IP为: $current_ip, 请输入新的解锁IP (留空则使用本机IP 127.0.0.1): " new_ip
  [ -z "$new_ip" ] && new_ip="127.0.0.1"
  if ! [[ $new_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}IP格式不正确!${PLAIN}"
    return
  fi
  cp "$SERVICE_CONFIG" "${SERVICE_CONFIG}.bak"
  sed -i "s/^$selected_service:$current_ip:/$selected_service:$new_ip:/" "$SERVICE_CONFIG"
  echo -e "${GREEN}$selected_service 解锁IP已更新为: $new_ip${PLAIN}"
  apply_service_config
  restart_services
}

add_custom_service() {
  read -p "请输入服务名称: " service_name
  if [ -z "$service_name" ]; then
    echo -e "${RED}服务名称不能为空!${PLAIN}"
    return
  fi
  if grep -q "^$service_name:" "$SERVICE_CONFIG"; then
    echo -e "${RED}服务 $service_name 已存在!${PLAIN}"
    return
  fi
  read -p "请输入解锁IP (留空则使用本机IP 127.0.0.1): " service_ip
  [ -z "$service_ip" ] && service_ip="127.0.0.1"
  if ! [[ $service_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}IP格式不正确!${PLAIN}"
    return
  fi
  read -p "请输入域名列表 (多个域名用空格分隔): " service_domains
  if [ -z "$service_domains" ]; then
    echo -e "${RED}域名列表不能为空!${PLAIN}"
    return
  fi
  echo "$service_name:$service_ip:$service_domains" >> "$SERVICE_CONFIG"
  echo -e "${GREEN}服务 $service_name 添加成功!${PLAIN}"
  apply_service_config
  restart_services
}

add_domains_to_service() {
  echo -e "${BLUE}当前服务配置:${PLAIN}"
  local services=()
  local i=1
  while IFS=':' read -r service ip domains; do
    [[ "$service" =~ ^#.*$ || -z "$service" ]] && continue
    services+=("$service")
    echo -e "$i. ${GREEN}$service${PLAIN}"
    ((i++))
  done < "$SERVICE_CONFIG"
  read -p "请选择要添加域名的服务 [1-$((i-1))]: " service_num
  if ! [[ "$service_num" =~ ^[0-9]+$ ]] || [ "$service_num" -lt 1 ] || [ "$service_num" -gt $((i-1)) ]; then
    echo -e "${RED}无效选择!${PLAIN}"
    return
  fi
  selected_service="${services[$((service_num-1))]}"
  current_line=$(grep "^$selected_service:" "$SERVICE_CONFIG")
  current_ip=$(echo "$current_line" | cut -d':' -f2)
  current_domains=$(echo "$current_line" | cut -d':' -f3)
  echo -e "${YELLOW}当前域名列表: $current_domains${PLAIN}"
  read -p "请输入要添加的域名 (多个域名用空格分隔): " new_domains
  if [ -z "$new_domains" ]; then
    echo -e "${RED}域名不能为空!${PLAIN}"
    return
  fi
  updated_domains="$current_domains $new_domains"
  sed -i "s/^$selected_service:$current_ip:.*/$selected_service:$current_ip:$updated_domains/" "$SERVICE_CONFIG"
  echo -e "${GREEN}域名已添加到 $selected_service!${PLAIN}"
  apply_service_config
  restart_services
}

remove_service() {
  echo -e "${BLUE}当前服务配置:${PLAIN}"
  local services=()
  local i=1
  while IFS=':' read -r service ip domains; do
    [[ "$service" =~ ^#.*$ || -z "$service" ]] && continue
    services+=("$service")
    echo -e "$i. ${GREEN}$service${PLAIN}"
    ((i++))
  done < "$SERVICE_CONFIG"
  read -p "请选择要移除的服务 [1-$((i-1))]: " service_num
  if ! [[ "$service_num" =~ ^[0-9]+$ ]] || [ "$service_num" -lt 1 ] || [ "$service_num" -gt $((i-1)) ]; then
    echo -e "${RED}无效选择!${PLAIN}"
    return
  fi
  selected_service="${services[$((service_num-1))]}"
  read -p "确定要移除服务 $selected_service? (y/n): " confirm
  if [ "$confirm" != "y" ]; then
    echo -e "${GREEN}操作已取消${PLAIN}"
    return
  fi
  cp "$SERVICE_CONFIG" "${SERVICE_CONFIG}.bak"
  sed -i "/^$selected_service:/d" "$SERVICE_CONFIG"
  echo -e "${GREEN}服务 $selected_service 已移除!${PLAIN}"
  apply_service_config
  restart_services
}

reset_config() {
  echo -e "${YELLOW}警告: 此操作将重置所有配置，包括已添加的解锁服务。${PLAIN}"
  read -p "确定要继续吗? (y/n): " confirm
  if [ "$confirm" != "y" ]; then
    echo -e "${GREEN}操作已取消${PLAIN}"
    return
  fi
  echo -e "${BLUE}重置配置...${PLAIN}"
  systemctl stop dnsmasq
  systemctl stop sniproxy
  rm -f $CONFIG_DIR/*.conf
  rm -f "$SERVICE_CONFIG"
  config_dnsmasq
  config_sniproxy
  init_service_config
  apply_service_config
  echo -e "${GREEN}配置已重置!${PLAIN}"
  restart_services
}

uninstall_service() {
  echo -e "${YELLOW}警告: 此操作将卸载解锁服务，所有配置将被删除。${PLAIN}"
  read -p "确定要继续吗? (y/n): " confirm
  if [ "$confirm" != "y" ]; then
    echo -e "${GREEN}操作已取消${PLAIN}"
    return
  fi
  echo -e "${BLUE}卸载服务...${PLAIN}"
  systemctl stop dnsmasq
  systemctl stop sniproxy
  systemctl disable dnsmasq
  systemctl disable sniproxy
  rm -f /etc/systemd/system/sniproxy.service
  rm -f $CONFIG_DIR/*.conf
  rm -f "$SERVICE_CONFIG"
  rm -f "$SNIPROXY_CONFIG"
  rm -f "$WHITELIST_FILE"
  iptables -F
  iptables -X
  if [ "${RELEASE}" == "centos" ]; then
    service iptables save
  elif [ "${RELEASE}" == "debian" ] || [ "${RELEASE}" == "ubuntu" ]; then
    netfilter-persistent save > /dev/null 2>&1
  fi
  systemctl daemon-reload
  echo -e "${GREEN}解锁服务已卸载!${PLAIN}"
}

install_service() {
  check_root
  check_system
  install_packages
  install_sniproxy
  config_dnsmasq
  config_sniproxy
  create_service_files
  init_service_config
  apply_service_config
  init_firewall_whitelist
  apply_firewall_rules
  start_services
  if ! systemctl is-active sniproxy &> /dev/null; then
    echo -e "${YELLOW}SNIProxy启动失败，尝试修复...${PLAIN}"
    fix_sniproxy
  fi
  echo -e "${GREEN}解锁服务安装完成!${PLAIN}"
  check_status
}

repair_service() {
  echo -e "${BLUE}开始修复服务...${PLAIN}"
  echo -e "${YELLOW}修复dnsmasq...${PLAIN}"
  systemctl stop dnsmasq
  config_dnsmasq
  systemctl restart dnsmasq
  systemctl enable dnsmasq
  echo -e "${YELLOW}修复SNIProxy...${PLAIN}"
  fix_sniproxy
  apply_service_config
  apply_firewall_rules
  echo -e "${GREEN}服务修复完成!${PLAIN}"
  check_status
}

show_menu() {
  clear
  echo -e "流媒体解锁脚本 - 基于DNS+SNIProxy"
  echo -e "支持Netflix、Disney+、TikTok、YouTube、OpenAI、Claude、Gemini、xAI等服务解锁"
  echo -e "版本: 2.3 (增强版)"
  echo -e "----------------------------------------"
  echo -e "1. 安装解锁服务"
  echo -e "2. 添加自定义服务"
  echo -e "3. 添加域名到现有服务"
  echo -e "4. 更改服务解锁IP"
  echo -e "5. 移除服务"
  echo -e "6. 重启服务"
  echo -e "7. 检查服务状态"
  echo -e "8. 防火墙管理"
  echo -e "9. 修复服务(SNIProxy问题)"
  echo -e "10. 重置配置"
  echo -e "11. 卸载服务"
  echo -e "0. 退出"
  echo -e "----------------------------------------"
  read -p "请输入选项 [0-11]: " option
  case $option in
    1) install_service ;;
    2) add_custom_service ;;
    3) add_domains_to_service ;;
    4) change_service_ip ;;
    5) remove_service ;;
    6) restart_services ;;
    7) check_status ;;
    8) manage_firewall ;;
    9) repair_service ;;
    10) reset_config ;;
    11) uninstall_service ;;
    0) exit 0 ;;
    *) echo -e "${RED}无效选项!${PLAIN}" ;;
  esac
  read -p "按任意键继续..." key
  show_menu
}

main() {
  check_root
  show_menu
}

main
