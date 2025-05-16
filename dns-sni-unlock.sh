#!/bin/bash

# 流媒体解锁脚本 - 基于DNS+SNIProxy
# 支持Netflix、Disney+、TikTok、OpenAI、Claude、Gemini等服务解锁
# 作者: Claude
# 版本: 1.0

# 颜色定义
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

# 全局变量
CONFIG_FILE="/etc/dnsmasq.d/custom_domains.conf"
DNSMASQ_CONFIG="/etc/dnsmasq.conf"
SNIPROXY_CONFIG="/etc/sniproxy.conf"
UNLOCK_IP="127.0.0.1"
CUSTOM_DOMAINS_FILE="/root/custom_domains.txt"

# 预设服务域名
TIKTOK_DOMAINS="tiktok.com tiktokv.com tiktokcdn.com musical.ly"
OPENAI_DOMAINS="openai.com chat.openai.com platform.openai.com api.openai.com"
CLAUDE_DOMAINS="anthropic.com claude.ai"
GEMINI_DOMAINS="gemini.google.com generativelanguage.googleapis.com"
DISNEY_DOMAINS="disney.com disneyplus.com dssott.com bamgrid.com disney-plus.net"
NETFLIX_DOMAINS="netflix.com netflix.net nflximg.com nflximg.net nflxvideo.net nflxso.net"

# 检查root权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误: 请使用root权限运行此脚本!${PLAIN}"
        exit 1
    fi
}

# 检查系统
check_system() {
    if [ -f /etc/redhat-release ]; then
        RELEASE="centos"
    elif grep -Eqi "debian" /etc/issue; then
        RELEASE="debian"
    elif grep -Eqi "ubuntu" /etc/issue; then
        RELEASE="ubuntu"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        RELEASE="centos"
    elif grep -Eqi "debian|raspbian" /proc/version; then
        RELEASE="debian"
    elif grep -Eqi "ubuntu" /proc/version; then
        RELEASE="ubuntu"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        RELEASE="centos"
    else
        echo -e "${RED}系统不支持，请使用 CentOS/Debian/Ubuntu 系统！${PLAIN}"
        exit 1
    fi
}

# 安装必要软件
install_packages() {
    echo -e "${BLUE}开始安装必要软件...${PLAIN}"
    
    if [ "${RELEASE}" == "centos" ]; then
        yum update -y
        yum install -y epel-release
        yum install -y bind-utils dnsmasq curl wget git make gcc openssl-devel libevent-devel
        
        # 安装SNIProxy
        if ! command -v sniproxy &> /dev/null; then
            cd /tmp
            git clone https://github.com/dlundquist/sniproxy.git
            cd sniproxy
            ./autogen.sh
            ./configure
            make
            make install
            mkdir -p /etc/sniproxy
            cd ..
            rm -rf sniproxy
        fi
        
    elif [ "${RELEASE}" == "debian" ] || [ "${RELEASE}" == "ubuntu" ]; then
        apt-get update -y
        apt-get install -y dnsutils dnsmasq curl wget git build-essential libudns-dev libev-dev libpcre3-dev pkg-config autotools-dev cdbs debhelper dh-autoreconf dpkg-dev gettext libev-dev libpcre3-dev libudns-dev pkg-config fakeroot devscripts
        
        # 安装SNIProxy
        if ! command -v sniproxy &> /dev/null; then
            cd /tmp
            git clone https://github.com/dlundquist/sniproxy.git
            cd sniproxy
            ./autogen.sh
            ./configure
            make
            make install
            mkdir -p /etc/sniproxy
            cd ..
            rm -rf sniproxy
        fi
    fi
    
    echo -e "${GREEN}必要软件安装完成!${PLAIN}"
}

# 配置dnsmasq
config_dnsmasq() {
    echo -e "${BLUE}配置dnsmasq...${PLAIN}"
    
    # 备份原始配置
    if [ -f "$DNSMASQ_CONFIG" ]; then
        cp "$DNSMASQ_CONFIG" "$DNSMASQ_CONFIG.bak.$(date +%Y%m%d%H%M%S)"
    fi
    
    # 创建dnsmasq配置目录
    mkdir -p /etc/dnsmasq.d
    
    # 创建基本dnsmasq配置
    cat > "$DNSMASQ_CONFIG" << EOF
# DNS服务器设置
server=8.8.8.8
server=8.8.4.4

# 监听地址
listen-address=127.0.0.1

# 缓存设置
cache-size=1024

# 不使用hosts文件
no-hosts

# 解析域名配置文件
conf-dir=/etc/dnsmasq.d/,*.conf
EOF
    
    # 确保自定义域名配置文件存在
    touch "$CONFIG_FILE"
    
    echo -e "${GREEN}dnsmasq配置完成!${PLAIN}"
}

# 配置SNIProxy
config_sniproxy() {
    echo -e "${BLUE}配置SNIProxy...${PLAIN}"
    
    # 创建SNIProxy配置文件
    cat > "$SNIPROXY_CONFIG" << EOF
# SNIProxy 配置
user daemon
pidfile /var/run/sniproxy.pid

listener 80 {
    proto http
    table https_hosts
}

listener 443 {
    proto tls
    table https_hosts
}

table https_hosts {
    .* *:$1
}

resolver {
    nameserver 8.8.8.8
    nameserver 8.8.4.4
    mode ipv4_only
}
EOF
    
    echo -e "${GREEN}SNIProxy配置完成!${PLAIN}"
}

# 创建服务文件
create_service_files() {
    echo -e "${BLUE}创建服务文件...${PLAIN}"
    
    # 创建SNIProxy服务文件
    cat > /etc/systemd/system/sniproxy.service << EOF
[Unit]
Description=SNI Proxy
After=network.target

[Service]
Type=forking
PIDFile=/var/run/sniproxy.pid
ExecStart=/usr/local/sbin/sniproxy -c $SNIPROXY_CONFIG
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -TERM \$MAINPID

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载systemd配置
    systemctl daemon-reload
    
    echo -e "${GREEN}服务文件创建完成!${PLAIN}"
}

# 添加解锁域名
add_domains() {
    local service_name=$1
    local domains=$2
    
    echo -e "${BLUE}添加 ${service_name} 解锁域名...${PLAIN}"
    
    for domain in $domains; do
        # 检查域名是否已存在
        if grep -q "address=/${domain}/${UNLOCK_IP}" "$CONFIG_FILE"; then
            echo -e "${YELLOW}域名 ${domain} 已存在，跳过.${PLAIN}"
            continue
        fi
        
        # 添加域名
        echo "address=/${domain}/${UNLOCK_IP}" >> "$CONFIG_FILE"
        echo "${domain}" >> "$CUSTOM_DOMAINS_FILE"
        echo -e "${GREEN}已添加域名: ${domain}${PLAIN}"
    done
}

# 添加自定义域名
add_custom_domain() {
    read -p "请输入要解锁的域名 (多个域名请用空格分隔): " custom_domains
    
    if [ -z "$custom_domains" ]; then
        echo -e "${RED}域名不能为空!${PLAIN}"
        return
    fi
    
    add_domains "自定义" "$custom_domains"
    echo -e "${GREEN}自定义域名添加完成!${PLAIN}"
    restart_services
}

# 移除解锁域名
remove_domain() {
    echo -e "${BLUE}现有解锁域名列表:${PLAIN}"
    if [ -f "$CUSTOM_DOMAINS_FILE" ]; then
        cat "$CUSTOM_DOMAINS_FILE" | nl
    else
        echo -e "${RED}无解锁域名!${PLAIN}"
        return
    fi
    
    read -p "请输入要移除的域名序号 (多个序号请用空格分隔): " domain_nums
    
    if [ -z "$domain_nums" ]; then
        echo -e "${RED}序号不能为空!${PLAIN}"
        return
    fi
    
    # 临时文件
    temp_file=$(mktemp)
    config_temp=$(mktemp)
    
    # 保留未被选中的行
    for num in $domain_nums; do
        domain=$(sed -n "${num}p" "$CUSTOM_DOMAINS_FILE")
        if [ -n "$domain" ]; then
            echo -e "${YELLOW}正在移除域名: ${domain}${PLAIN}"
            sed -i "/address=\/${domain//\./\\.}\/${UNLOCK_IP//\./\\.}/d" "$CONFIG_FILE"
            sed -i "${num}d" "$CUSTOM_DOMAINS_FILE"
        fi
    done
    
    echo -e "${GREEN}域名移除完成!${PLAIN}"
    restart_services
}

# 更改解锁IP
change_unlock_ip() {
    read -p "当前解锁IP为: ${UNLOCK_IP}, 请输入新的解锁IP (留空则使用默认本机IP): " new_ip
    
    if [ -z "$new_ip" ]; then
        new_ip="127.0.0.1"
    fi
    
    if ! [[ $new_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}IP格式不正确!${PLAIN}"
        return
    fi
    
    echo -e "${BLUE}更新解锁IP到 ${new_ip}...${PLAIN}"
    
    # 备份原始配置文件
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    # 替换IP
    if [ -f "$CUSTOM_DOMAINS_FILE" ]; then
        while read -r domain; do
            if [ -n "$domain" ]; then
                sed -i "s/address=\/${domain//\./\\.}\/${UNLOCK_IP//\./\\.}/address=\/${domain//\./\\.}\/${new_ip//\./\\.}/g" "$CONFIG_FILE"
            fi
        done < "$CUSTOM_DOMAINS_FILE"
    fi
    
    # 更新全局变量
    UNLOCK_IP="$new_ip"
    
    # 更新SNIProxy配置
    config_sniproxy "$UNLOCK_IP"
    
    echo -e "${GREEN}解锁IP已更新为: ${UNLOCK_IP}${PLAIN}"
    restart_services
}

# 重置配置
reset_config() {
    echo -e "${YELLOW}警告: 此操作将重置所有配置，包括已添加的解锁域名。${PLAIN}"
    read -p "确定要继续吗? (y/n): " confirm
    
    if [ "$confirm" != "y" ]; then
        echo -e "${GREEN}操作已取消${PLAIN}"
        return
    fi
    
    echo -e "${BLUE}重置配置...${PLAIN}"
    
    # 停止服务
    systemctl stop dnsmasq
    systemctl stop sniproxy
    
    # 删除配置文件
    rm -f "$CONFIG_FILE"
    rm -f "$CUSTOM_DOMAINS_FILE"
    
    # 重新配置
    config_dnsmasq
    config_sniproxy "$UNLOCK_IP"
    
    echo -e "${GREEN}配置已重置!${PLAIN}"
    restart_services
}

# 重置dnsmasq配置
reset_dnsmasq() {
    echo -e "${YELLOW}警告: 此操作将重置dnsmasq配置，包括已添加的解锁域名。${PLAIN}"
    read -p "确定要继续吗? (y/n): " confirm
    
    if [ "$confirm" != "y" ]; then
        echo -e "${GREEN}操作已取消${PLAIN}"
        return
    fi
    
    echo -e "${BLUE}重置dnsmasq配置...${PLAIN}"
    
    # 停止服务
    systemctl stop dnsmasq
    
    # 删除配置文件
    rm -f "$CONFIG_FILE"
    rm -f "$CUSTOM_DOMAINS_FILE"
    
    # 重新配置
    config_dnsmasq
    
    echo -e "${GREEN}dnsmasq配置已重置!${PLAIN}"
    systemctl start dnsmasq
}

# 启动服务
start_services() {
    echo -e "${BLUE}启动服务...${PLAIN}"
    
    systemctl start dnsmasq
    systemctl enable dnsmasq
    
    systemctl start sniproxy
    systemctl enable sniproxy
    
    echo -e "${GREEN}服务已启动!${PLAIN}"
}

# 重启服务
restart_services() {
    echo -e "${BLUE}重启服务...${PLAIN}"
    
    systemctl restart dnsmasq
    systemctl restart sniproxy
    
    echo -e "${GREEN}服务已重启!${PLAIN}"
}

# 检查服务状态
check_status() {
    echo -e "${BLUE}服务状态:${PLAIN}"
    
    echo -e "${YELLOW}dnsmasq状态:${PLAIN}"
    systemctl status dnsmasq --no-pager
    
    echo -e "${YELLOW}sniproxy状态:${PLAIN}"
    systemctl status sniproxy --no-pager
    
    if [ -f "$CUSTOM_DOMAINS_FILE" ]; then
        echo -e "${YELLOW}当前解锁域名:${PLAIN}"
        cat "$CUSTOM_DOMAINS_FILE"
    fi
    
    echo -e "${YELLOW}当前解锁IP: ${UNLOCK_IP}${PLAIN}"
}

# 初始化配置
init_config() {
    echo -e "${BLUE}初始化配置...${PLAIN}"
    
    # 创建必要目录和文件
    mkdir -p /etc/dnsmasq.d
    touch "$CUSTOM_DOMAINS_FILE"
    
    # 配置dnsmasq和SNIProxy
    config_dnsmasq
    config_sniproxy "$UNLOCK_IP"
    create_service_files
    
    echo -e "${GREEN}初始化配置完成!${PLAIN}"
}

# 安装解锁服务
install_service() {
    check_root
    check_system
    install_packages
    init_config
    
    # 添加预设服务域名
    echo -e "${BLUE}添加预设服务域名...${PLAIN}"
    add_domains "TikTok" "$TIKTOK_DOMAINS"
    add_domains "OpenAI" "$OPENAI_DOMAINS"
    add_domains "Claude" "$CLAUDE_DOMAINS"
    add_domains "Gemini" "$GEMINI_DOMAINS"
    add_domains "Disney+" "$DISNEY_DOMAINS"
    add_domains "Netflix" "$NETFLIX_DOMAINS"
    
    # 启动服务
    start_services
    
    echo -e "${GREEN}解锁服务安装完成!${PLAIN}"
    echo -e "${YELLOW}当前解锁IP: ${UNLOCK_IP}${PLAIN}"
    echo -e "${YELLOW}如需更改解锁IP，请使用选项4${PLAIN}"
}

# 卸载服务
uninstall_service() {
    echo -e "${YELLOW}警告: 此操作将卸载解锁服务，所有配置将被删除。${PLAIN}"
    read -p "确定要继续吗? (y/n): " confirm
    
    if [ "$confirm" != "y" ]; then
        echo -e "${GREEN}操作已取消${PLAIN}"
        return
    fi
    
    echo -e "${BLUE}卸载服务...${PLAIN}"
    
    # 停止服务
    systemctl stop dnsmasq
    systemctl stop sniproxy
    
    systemctl disable dnsmasq
    systemctl disable sniproxy
    
    # 删除服务文件
    rm -f /etc/systemd/system/sniproxy.service
    
    # 删除配置文件
    rm -f "$CONFIG_FILE"
    rm -f "$CUSTOM_DOMAINS_FILE"
    rm -f "$SNIPROXY_CONFIG"
    
    # 重新加载systemd配置
    systemctl daemon-reload
    
    echo -e "${GREEN}解锁服务已卸载!${PLAIN}"
}

# 显示菜单
show_menu() {
    clear
    echo -e "流媒体解锁脚本 - 基于DNS+SNIProxy"
    echo -e "支持Netflix、Disney+、TikTok、OpenAI、Claude、Gemini等服务解锁"
    echo -e "----------------------------------------"
    echo -e "1. 安装解锁服务"
    echo -e "2. 添加自定义解锁域名"
    echo -e "3. 移除解锁域名"
    echo -e "4. 更改解锁IP (当前: ${UNLOCK_IP})"
    echo -e "5. 重启服务"
    echo -e "6. 检查服务状态"
    echo -e "7. 重置配置"
    echo -e "8. 重置dnsmasq配置"
    echo -e "9. 卸载服务"
    echo -e "0. 退出"
    echo -e "----------------------------------------"
    read -p "请输入选项 [0-9]: " option
    
    case $option in
        1) install_service ;;
        2) add_custom_domain ;;
        3) remove_domain ;;
        4) change_unlock_ip ;;
        5) restart_services ;;
        6) check_status ;;
        7) reset_config ;;
        8) reset_dnsmasq ;;
        9) uninstall_service ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效选项!${PLAIN}" ;;
    esac
    
    read -p "按任意键继续..." key
    show_menu
}

# 程序入口
main() {
    check_root
    show_menu
}

main