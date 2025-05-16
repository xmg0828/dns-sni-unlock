#!/bin/bash

# 流媒体解锁脚本 - 基于DNS+SNIProxy
# 支持Netflix、Disney+、TikTok、OpenAI、Claude、Gemini等服务解锁
# 版本: 2.0

# 颜色定义
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

# 配置文件路径
CONFIG_DIR="/etc/dnsmasq.d"
DNSMASQ_CONFIG="/etc/dnsmasq.conf"
SNIPROXY_CONFIG="/etc/sniproxy.conf"
SERVICE_CONFIG="/root/dns_unlock_services.conf"
DEFAULT_IP="127.0.0.1"

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
        echo -e "${RED}系统不支持，请使用CentOS/Debian/Ubuntu系统！${PLAIN}"
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
        apt-get install -y dnsutils dnsmasq curl wget git build-essential libudns-dev libev-dev libpcre3-dev
        
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
    mkdir -p $CONFIG_DIR
    
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
    
    echo -e "${GREEN}dnsmasq配置完成!${PLAIN}"
}

# 配置SNIProxy
config_sniproxy() {
    echo -e "${BLUE}配置SNIProxy...${PLAIN}"
    
    # 创建SNIProxy配置文件
    cat > "$SNIPROXY_CONFIG" << EOF
# SNIProxy配置
user daemon
pidfile /var/run/sniproxy.pid

listener 80 {
    proto http
}

listener 443 {
    proto tls
}

table {
    # 默认规则
    .* *:443
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

# 初始化服务配置文件
init_service_config() {
    if [ ! -f "$SERVICE_CONFIG" ]; then
        echo -e "${BLUE}初始化服务配置...${PLAIN}"
        cat > "$SERVICE_CONFIG" << EOF
# 服务配置文件
# 格式: 服务名称:解锁IP:域名列表(用空格分隔)

TikTok:${DEFAULT_IP}:tiktok.com tiktokv.com tiktokcdn.com musical.ly
OpenAI:${DEFAULT_IP}:openai.com chat.openai.com platform.openai.com api.openai.com
Claude:${DEFAULT_IP}:anthropic.com claude.ai
Gemini:${DEFAULT_IP}:gemini.google.com generativelanguage.googleapis.com
Disney:${DEFAULT_IP}:disney.com disneyplus.com dssott.com bamgrid.com disney-plus.net
Netflix:${DEFAULT_IP}:netflix.com netflix.net nflximg.com nflximg.net nflxvideo.net nflxso.net
EOF
        echo -e "${GREEN}服务配置初始化完成!${PLAIN}"
    fi
}

# 应用服务配置
apply_service_config() {
    echo -e "${BLUE}应用服务配置...${PLAIN}"
    
    # 清除旧配置
    rm -f $CONFIG_DIR/*.conf
    
    # 读取服务配置并应用
    while IFS=':' read -r service ip domains || [ -n "$service" ]; do
        # 跳过注释和空行
        [[ "$service" =~ ^#.*$ || -z "$service" ]] && continue
        
        # 创建配置文件
        conf_file="$CONFIG_DIR/${service,,}.conf"
        echo "# $service 解锁配置" > "$conf_file"
        
        # 添加域名解析
        for domain in $domains; do
            echo "address=/$domain/$ip" >> "$conf_file"
        done
        
        echo -e "${GREEN}已配置服务: $service (IP: $ip)${PLAIN}"
    done < "$SERVICE_CONFIG"
    
    echo -e "${GREEN}服务配置应用完成!${PLAIN}"
}

# 启动服务
start_services() {
    echo -e "${BLUE}启动服务...${PLAIN}"
    
    systemctl restart dnsmasq
    systemctl enable dnsmasq
    
    systemctl restart sniproxy
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
    
    echo -e "${YELLOW}当前服务配置:${PLAIN}"
    grep -v "^#" "$SERVICE_CONFIG" | while IFS=':' read -r service ip domains; do
        [[ -z "$service" ]] && continue
        echo -e "${GREEN}$service${PLAIN} - IP: ${YELLOW}$ip${PLAIN}"
        echo -e "   域名: ${BLUE}$domains${PLAIN}"
    done
}

# 更改服务IP
change_service_ip() {
    echo -e "${BLUE}当前服务配置:${PLAIN}"
    local services=()
    local i=1
    
    # 显示当前服务列表
    while IFS=':' read -r service ip domains; do
        # 跳过注释和空行
        [[ "$service" =~ ^#.*$ || -z "$service" ]] && continue
        
        services+=("$service")
        echo -e "$i. ${GREEN}$service${PLAIN} - 当前IP: ${YELLOW}$ip${PLAIN}"
        ((i++))
    done < "$SERVICE_CONFIG"
    
    # 选择服务
    read -p "请选择要更改IP的服务 [1-$((i-1))]: " service_num
    
    if ! [[ "$service_num" =~ ^[0-9]+$ ]] || [ "$service_num" -lt 1 ] || [ "$service_num" -gt $((i-1)) ]; then
        echo -e "${RED}无效选择!${PLAIN}"
        return
    fi
    
    selected_service="${services[$((service_num-1))]}"
    
    # 获取当前IP
    current_ip=$(grep "^$selected_service:" "$SERVICE_CONFIG" | cut -d':' -f2)
    
    # 输入新IP
    read -p "当前 $selected_service 解锁IP为: $current_ip, 请输入新的解锁IP (留空则使用本机IP 127.0.0.1): " new_ip
    
    if [ -z "$new_ip" ]; then
        new_ip="127.0.0.1"
    fi
    
    if ! [[ $new_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}IP格式不正确!${PLAIN}"
        return
    fi
    
    # 备份配置
    cp "$SERVICE_CONFIG" "${SERVICE_CONFIG}.bak"
    
    # 更新配置
    sed -i "s/^$selected_service:$current_ip:/$selected_service:$new_ip:/" "$SERVICE_CONFIG"
    
    echo -e "${GREEN}$selected_service 解锁IP已更新为: $new_ip${PLAIN}"
    
    # 应用新配置
    apply_service_config
    restart_services
}

# 添加自定义服务
add_custom_service() {
    read -p "请输入服务名称: " service_name
    
    if [ -z "$service_name" ]; then
        echo -e "${RED}服务名称不能为空!${PLAIN}"
        return
    fi
    
    # 检查是否已存在
    if grep -q "^$service_name:" "$SERVICE_CONFIG"; then
        echo -e "${RED}服务 $service_name 已存在!${PLAIN}"
        return
    fi
    
    read -p "请输入解锁IP (留空则使用本机IP 127.0.0.1): " service_ip
    
    if [ -z "$service_ip" ]; then
        service_ip="127.0.0.1"
    fi
    
    if ! [[ $service_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}IP格式不正确!${PLAIN}"
        return
    fi
    
    read -p "请输入域名列表 (多个域名用空格分隔): " service_domains
    
    if [ -z "$service_domains" ]; then
        echo -e "${RED}域名列表不能为空!${PLAIN}"
        return
    fi
    
    # 添加到配置
    echo "$service_name:$service_ip:$service_domains" >> "$SERVICE_CONFIG"
    
    echo -e "${GREEN}服务 $service_name 添加成功!${PLAIN}"
    
    # 应用新配置
    apply_service_config
    restart_services
}

# 添加域名到服务
add_domains_to_service() {
    echo -e "${BLUE}当前服务配置:${PLAIN}"
    local services=()
    local i=1
    
    # 显示当前服务列表
    while IFS=':' read -r service ip domains; do
        # 跳过注释和空行
        [[ "$service" =~ ^#.*$ || -z "$service" ]] && continue
        
        services+=("$service")
        echo -e "$i. ${GREEN}$service${PLAIN}"
        ((i++))
    done < "$SERVICE_CONFIG"
    
    # 选择服务
    read -p "请选择要添加域名的服务 [1-$((i-1))]: " service_num
    
    if ! [[ "$service_num" =~ ^[0-9]+$ ]] || [ "$service_num" -lt 1 ] || [ "$service_num" -gt $((i-1)) ]; then
        echo -e "${RED}无效选择!${PLAIN}"
        return
    fi
    
    selected_service="${services[$((service_num-1))]}"
    
    # 获取当前配置
    current_line=$(grep "^$selected_service:" "$SERVICE_CONFIG")
    current_ip=$(echo "$current_line" | cut -d':' -f2)
    current_domains=$(echo "$current_line" | cut -d':' -f3)
    
    echo -e "${YELLOW}当前域名列表: $current_domains${PLAIN}"
    
    # 输入新域名
    read -p "请输入要添加的域名 (多个域名用空格分隔): " new_domains
    
    if [ -z "$new_domains" ]; then
        echo -e "${RED}域名不能为空!${PLAIN}"
        return
    fi
    
    # 更新配置
    updated_domains="$current_domains $new_domains"
    sed -i "s/^$selected_service:$current_ip:.*/$selected_service:$current_ip:$updated_domains/" "$SERVICE_CONFIG"
    
    echo -e "${GREEN}域名已添加到 $selected_service!${PLAIN}"
    
    # 应用新配置
    apply_service_config
    restart_services
}

# 移除服务
remove_service() {
    echo -e "${BLUE}当前服务配置:${PLAIN}"
    local services=()
    local i=1
    
    # 显示当前服务列表
    while IFS=':' read -r service ip domains; do
        # 跳过注释和空行
        [[ "$service" =~ ^#.*$ || -z "$service" ]] && continue
        
        services+=("$service")
        echo -e "$i. ${GREEN}$service${PLAIN}"
        ((i++))
    done < "$SERVICE_CONFIG"
    
    # 选择服务
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
    
    # 备份配置
    cp "$SERVICE_CONFIG" "${SERVICE_CONFIG}.bak"
    
    # 移除服务
    sed -i "/^$selected_service:/d" "$SERVICE_CONFIG"
    
    echo -e "${GREEN}服务 $selected_service 已移除!${PLAIN}"
    
    # 应用新配置
    apply_service_config
    restart_services
}

# 重置配置
reset_config() {
    echo -e "${YELLOW}警告: 此操作将重置所有配置，包括已添加的解锁服务。${PLAIN}"
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
    rm -f $CONFIG_DIR/*.conf
    rm -f "$SERVICE_CONFIG"
    
    # 重新配置
    config_dnsmasq
    config_sniproxy
    init_service_config
    apply_service_config
    
    echo -e "${GREEN}配置已重置!${PLAIN}"
    restart_services
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
    rm -f $CONFIG_DIR/*.conf
    rm -f "$SERVICE_CONFIG"
    rm -f "$SNIPROXY_CONFIG"
    
    # 重新加载systemd配置
    systemctl daemon-reload
    
    echo -e "${GREEN}解锁服务已卸载!${PLAIN}"
}

# 安装解锁服务
install_service() {
    check_root
    check_system
    install_packages
    
    # 配置服务
    config_dnsmasq
    config_sniproxy
    create_service_files
    init_service_config
    apply_service_config
    
    # 启动服务
    start_services
    
    echo -e "${GREEN}解锁服务安装完成!${PLAIN}"
    check_status
}

# 显示菜单
show_menu() {
    clear
    echo -e "流媒体解锁脚本 - 基于DNS+SNIProxy"
    echo -e "支持Netflix、Disney+、TikTok、OpenAI、Claude、Gemini等服务解锁"
    echo -e "----------------------------------------"
    echo -e "1. 安装解锁服务"
    echo -e "2. 添加自定义服务"
    echo -e "3. 添加域名到现有服务"
    echo -e "4. 更改服务解锁IP"
    echo -e "5. 移除服务"
    echo -e "6. 重启服务"
    echo -e "7. 检查服务状态"
    echo -e "8. 重置配置"
    echo -e "9. 卸载服务"
    echo -e "0. 退出"
    echo -e "----------------------------------------"
    read -p "请输入选项 [0-9]: " option
    
    case $option in
        1) install_service ;;
        2) add_custom_service ;;
        3) add_domains_to_service ;;
        4) change_service_ip ;;
        5) remove_service ;;
        6) restart_services ;;
        7) check_status ;;
        8) reset_config ;;
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
