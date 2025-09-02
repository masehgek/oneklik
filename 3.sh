#!/bin/bash
set -e

# --- Color Codes ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Global Variables ---
DOMAIN=""

# --- Helper Functions ---
info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run as root. Please use 'sudo -i' or 'sudo su'."
    fi
}

check_os() {
    source /etc/os-release
    info "Operating system detected: ${NAME} ${VERSION_ID}"
}

install_dependencies() {
    info "Updating package lists..."
    apt-get update >/dev/null 2>&1

    info "Installing base dependencies..."
    apt-get install -y \
        wget curl socat htop cron \
        build-essential libnss3-dev \
        zlib1g-dev libssl-dev libgmp-dev \
        ufw fail2ban \
        unzip zip \
        python3 python3-pip \
        jq certbot dnsutils git cmake
    info "Base dependencies installed."
}

ask_domain() {
    info "Untuk sertifikat SSL, Anda memerlukan sebuah domain."
    read -p "Silakan masukkan nama domain Anda (contoh: mydomain.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        error "Domain tidak boleh kosong."
    fi
    info "Domain Anda akan diatur ke: $DOMAIN"

    echo "$DOMAIN" > /root/domain.txt
}

setup_xray() {
    info "Setting up XRAY (Vmess/Vless/Trojan)..."
    DOMAIN=$(cat /root/domain.txt)

    info "Installing XRAY core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata >/dev/null 2>&1

    info "Checking DNS for $DOMAIN..."
    local_ip=$(curl -s ifconfig.me)
    resolved_ip=$(dig +short "$DOMAIN" @8.8.8.8)

    if [[ "$local_ip" != "$resolved_ip" ]]; then
        error "DNS validation failed. Domain '$DOMAIN' points to '$resolved_ip', but VPS IP is '$local_ip'."
    fi
    info "DNS check passed."

    info "Obtaining SSL certificate for $DOMAIN..."
    systemctl stop xray || true
    ufw allow 80/tcp
    certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" || error "Failed to obtain SSL certificate."
    ufw deny 80/tcp
    systemctl start xray || true
    info "SSL certificate obtained."

    info "Generating UUIDs and passwords..."
    VLESS_UUID=$(/usr/local/bin/xray uuid)
    VMESS_UUID=$(/usr/local/bin/xray uuid)
    TROJAN_PASSWORD=$(openssl rand -base64 16)

    echo "VLESS_UUID=${VLESS_UUID}" > /root/xray_credentials.txt
    echo "VMESS_UUID=${VMESS_UUID}" >> /root/xray_credentials.txt
    echo "TROJAN_PASSWORD=${TROJAN_PASSWORD}" >> /root/xray_credentials.txt

    info "Creating XRAY configuration..."
    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": { "loglevel": "warning" },
  "stats": {},
  "api": {
    "tag": "api",
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ]
  },
  "policy": {
    "levels": {
      "0": {
        "statsUser    Uplink": true,
        "statsUser    Downlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    },
    {
      "port": 443,
      "protocol": "vless",
      "tag": "vless-in",
      "settings": {
        "clients": [ { "id": "${VLESS_UUID}", "level": 0, "email": "user@${DOMAIN}" } ],
        "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 8082, "xver": 1 },
          { "path": "/trojan", "dest": 8083, "xver": 1 }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
            }
          ]
        },
        "wsSettings": { "path": "/vless" }
      }
    },
    {
      "port": 8082, "listen": "127.0.0.1", "protocol": "vmess", "tag": "vmess-in",
      "settings": { "clients": [{"id": "${VMESS_UUID}", "alterId": 0, "email": "user@${DOMAIN}"}] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } }
    },
    {
      "port": 8083, "listen": "127.0.0.1", "protocol": "trojan", "tag": "trojan-in",
      "settings": { "clients": [{"password": "${TROJAN_PASSWORD}", "email": "user@${DOMAIN}"}] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": {} },
    { "protocol": "blackhole", "settings": {}, "tag": "blocked" }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": [ "api-in" ],
        "outboundTag": "api"
      }
    ]
  }
}
EOF

    chmod 644 /usr/local/etc/xray/config.json

    systemctl daemon-reload
    systemctl enable xray
    systemctl restart xray

    info "XRAY setup completed."
}

setup_support_services() {
    info "Setting up Squid Proxy and Badvpn..."

    # Squid config
    if [ -f /etc/squid/squid.conf ]; then
        sed -i 's/http_access deny all/http_access allow all/' /etc/squid/squid.conf
        grep -q -F "http_port 8080" /etc/squid/squid.conf || echo "http_port 8080" >> /etc/squid/squid.conf
        grep -q -F "http_port 3128" /etc/squid/squid.conf || echo "http_port 3128" >> /etc/squid/squid.conf
        DOMAIN=$(cat /root/domain.txt)
        sed -i "s/# visible_hostname .*/visible_hostname $DOMAIN/" /etc/squid/squid.conf
        systemctl enable squid >/dev/null 2>&1
        systemctl restart squid
    else
        warn "Squid configuration file not found. Skipping."
    fi

    # Badvpn install
    cd /root
    if ! command -v git &> /dev/null; then
        info "Installing git..."
        apt-get install -y git >/dev/null 2>&1
    fi
    if ! command -v cmake &> /dev/null; then
        info "Installing cmake..."
        apt-get install -y cmake >/dev/null 2>&1
    fi
    if [ ! -f /usr/local/bin/badvpn-udpgw ]; then
        git clone https://github.com/ambrop72/badvpn.git >/dev/null 2>&1
        mkdir -p /root/badvpn/build
        cd /root/badvpn/build
        cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null 2>&1
        make >/dev/null 2>&1
        mv udpgw/badvpn-udpgw /usr/local/bin/
        cd /root
        rm -rf /root/badvpn
    fi

    cat > /etc/systemd/system/badvpn@.service << EOF
[Unit]
Description=Badvpn UDP Gateway for Port %i
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:%i --max-clients 512
Restart=always
User =nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    for port in 7100 7200 7300; do
        systemctl enable badvpn@$port
        systemctl start badvpn@$port
    done

    info "Support services setup completed."
}

setup_security() {
    info "Setting up Firewall, Fail2Ban, and BBR..."

    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1

    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 3128/tcp
    ufw allow 8080/tcp

    yes | ufw enable

    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban

    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi
    sysctl -p >/dev/null 2>&1

    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        info "TCP BBR enabled successfully."
    else
        warn "TCP BBR could not be enabled."
    fi

    info "Security and performance enhancements completed."
}

setup_management_menu() {
    info "Setting up user management menu..."

    mkdir -p /etc/regarstore
    if [ ! -f /etc/regarstore/users.db ]; then
        cat > /etc/regarstore/users.db << EOF
# User database: username;protocol;uuid_or_pass;quota_gb;ip_limit;exp_date
EOF
    fi

    if ! command -v jq &>/dev/null; then
        info "Installing jq..."
        apt-get install -y jq >/dev/null 2>&1
    fi

    cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash
# XRAY User Management Menu (VLESS/VMess/Trojan only)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

USER_DB="/etc/regarstore/users.db"
XRAY_BIN="/usr/local/bin/xray"

press_enter_to_continue() {
    echo ""
    read -p "Press Enter to continue..."
}

show_menu() {
    clear
    echo "========================================"
    echo -e "    ${YELLOW}REGAR STORE - XRAY USER MENU${NC}"
    echo "========================================"
    echo " 1. Add XRAY User (VLESS/VMess/Trojan)"
    echo " 2. Delete XRAY User"
    echo " 3. List XRAY Users"
    echo " 4. Show XRAY Share Links"
    echo " 5. Check XRAY Service Status"
    echo " 6. Renew SSL Certificate"
    echo " 7. Show User Data Usage"
    echo " 8. Exit"
    echo " 9. Uninstall All Installed Packages and Configurations"
    echo "----------------------------------------"
}

add_xray_user() {
    echo "--- Add XRAY User ---"
    read -p "Enter username (email format): " email
    read -p "Select Protocol [1=VLESS, 2=VMess, 3=Trojan]: " proto_choice
    read -p "Enter Quota (GB, 0 for unlimited): " quota_gb
    read -p "Enter IP Limit (0 for unlimited): " ip_limit
    read -p "Enter expiration days (e.g., 30): " days

    exp_date=$(date -d "+$days days" +"%Y-%m-%d")

    local protocol_name inbound_tag new_client creds_for_db

    case $proto_choice in
        1) protocol_name="vless"; inbound_tag="vless-in"; creds_for_db=$($XRAY_BIN uuid); new_client=$(jq -n --arg id "$creds_for_db" --arg email "$email" '{id: $id, email: $email, level: 0}') ;;
        2) protocol_name="vmess"; inbound_tag="vmess-in"; creds_for_db=$($XRAY_BIN uuid); new_client=$(jq -n --arg id "$creds_for_db" --arg email "$email" '{id: $id, email: $email, level: 0}') ;;
        3) protocol_name="trojan"; inbound_tag="trojan-in"; creds_for_db=$(openssl rand -base64 12); new_client=$(jq -n --arg pass "$creds_for_db" --arg email "$email" '{password: $pass, email: $email, level: 0}') ;;
        *) echo -e "${RED}Invalid protocol choice.${NC}"; return ;;
    esac

    config_file="/usr/local/etc/xray/config.json"
    temp_config=$(mktemp)

    jq "(.inbounds[] | select(.tag == \"$inbound_tag\").settings.clients) += [$new_client]" "$config_file" > "$temp_config" && mv "$temp_config" "$config_file"

    if [[ $? -eq 0 ]]; then
        echo "$email;$protocol_name;$creds_for_db;$quota_gb;$ip_limit;$exp_date" >> "$USER_DB"
        echo -e "${GREEN}User           '$email' for $protocol_name added. Restarting XRAY...${NC}"
        systemctl restart xray
        echo "UUID/Password: $creds_for_db"
    else
        echo -e "${RED}Failed to modify xray config file.${NC}"
    fi
}

delete_xray_user() {
    read -p "Enter username (email) to delete: " email
    user_line=$(grep "^$email;" "$USER_DB")
    if [[ -z "$user_line" ]]; then
        echo -e "${RED}User           '$email' not found in database.${NC}"; return
    fi

    protocol_name=$(echo "$user_line" | cut -d';' -f2)
    inbound_tag="${protocol_name}-in"
    config_file="/usr/local/etc/xray/config.json"
    temp_config=$(mktemp)

    jq "del(.inbounds[] | select(.tag == \"$inbound_tag\").settings.clients[] | select(.email == \"$email\"))" "$config_file" > "$temp_config" && mv "$temp_config" "$config_file"

    if [[ $? -eq 0 ]]; then
        sed -i "/^$email;/d" "$USER_DB"
        echo -e "${GREEN}User           '$email' removed. Restarting XRAY...${NC}"
        systemctl restart xray
    else
        echo -e "${RED}Failed to modify xray config file.${NC}"
    fi
}

list_xray_users() {
    echo "--- XRAY User List ---"
    printf "%-25s | %-8s | %-10s | %-10s | %-12s\n" "Email" "Protocol" "Quota(GB)" "IP Limit" "Expires"
    echo "-----------------------------------------------------------------------------"
    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        [[ "$email" == \#* ]] && continue
        printf "%-25s | %-8s | %-10s | %-10s | %-12s\n" "$email" "$protocol" "$quota_gb" "$ip_limit" "$exp_date"
    done < "$USER_DB"
    echo "-----------------------------------------------------------------------------"
}

show_xray_share_links() {
    DOMAIN=$(cat /root/domain.txt)
    echo "--- XRAY Shareable Links ---"
    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        if [[ "$email" == \#* || -z "$email" ]]; then continue; fi

        echo -e "\n${YELLOW}:User           ${email}${NC}"
        case $protocol in
            vless)
                link="vless://${creds}@${DOMAIN}:443?type=ws&path=%2Fvless&security=tls#${email}"
                echo -e "${GREEN}$link${NC}"
                ;;
            vmess)
                json="{\"v\":\"2\",\"ps\":\"${email}\",\"add\":\"${DOMAIN}\",\"port\":\"443\",\"id\":\"${creds}\",\"aid\":0,\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DOMAIN}\",\"path\":\"/vmess\",\"tls\":\"tls\"}"
                link="vmess://$(echo -n $json | base64 -w 0)"
                                echo -e "${GREEN}$link${NC}"
                ;;
            trojan)
                link="trojan://${creds}@${DOMAIN}:443?type=ws&path=%2Ftrojan&security=tls#${email}"
                echo -e "${GREEN}$link${NC}"
                ;;
        esac
    done < "$USER_DB"
    echo "----------------------------"
}

check_xray_status() {
    systemctl is-active --quiet xray && echo -e "${GREEN}XRAY service is running.${NC}" || echo -e "${RED}XRAY service is NOT running.${NC}"
}

renew_ssl_certificate() {
    DOMAIN=$(cat /root/domain.txt)
    echo -e "${GREEN}Renewing SSL certificate for $DOMAIN...${NC}"
    systemctl stop xray || true
    certbot renew --non-interactive --quiet
    systemctl start xray || true
    echo -e "${GREEN}SSL certificate renewed.${NC}"
}

show_user_data_usage() {
    echo "--- User Data Usage ---"
    # Placeholder: implement actual data usage retrieval if XRAY API supports it
    echo "Feature not implemented yet."
}

uninstall_all() {
    echo -e "${YELLOW}Starting uninstall process...${NC}"

    # Stop and disable services
    systemctl stop xray squid fail2ban >/dev/null 2>&1 || true
    systemctl disable xray squid fail2ban badvpn@7100 badvpn@7200 badvpn@7300 >/dev/null 2>&1 || true

    # Remove xray files
    rm -f /usr/local/bin/xray
    rm -rf /usr/local/etc/xray
    rm -f /root/xray_credentials.txt
    rm -f /root/domain.txt

    # Backup squid config if exists
    if [ -f /etc/squid/squid.conf ]; then
        mv /etc/squid/squid.conf /etc/squid/squid.conf.bak_$(date +%s)
    fi

    # Remove badvpn binary and service files
    rm -f /usr/local/bin/badvpn-udpgw
    rm -f /etc/systemd/system/badvpn@.service
    systemctl daemon-reload

    # Remove user database and menu
    rm -rf /etc/regarstore
    rm -f /usr/local/bin/menu

    # Remove ufw rules added by script
    ufw delete allow 22/tcp || true
    ufw delete allow 80/tcp || true
    ufw delete allow 443/tcp || true
    ufw delete allow 3128/tcp || true
    ufw delete allow 8080/tcp || true

    # Optionally reset ufw (commented out)
    # ufw reset -y

    # Remove installed packages
    apt-get remove --purge -y \
        wget curl socat htop cron \
        build-essential libnss3-dev \
        zlib1g-dev libssl-dev libgmp-dev \
        ufw fail2ban \
        unzip zip \
        python3 python3-pip \
        jq certbot dnsutils \
        squid git cmake

    apt-get autoremove -y
    apt-get clean

    echo -e "${GREEN}Uninstall process completed.${NC}"
}

main() {
    while true; do
        show_menu
        read -p "Select an option [1-9]: " choice
        case $choice in
            1) add_xray_user; press_enter_to_continue ;;
            2) delete_xray_user; press_enter_to_continue ;;
            3) list_xray_users; press_enter_to_continue ;;
            4) show_xray_share_links; press_enter_to_continue ;;
            5) check_xray_status; press_enter_to_continue ;;
            6) renew_ssl_certificate; press_enter_to_continue ;;
            7) show_user_data_usage; press_enter_to_continue ;;
            8) echo "Exiting..."; exit 0 ;;
            9)
                read -p "Are you sure you want to uninstall everything? [y/N]: " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    uninstall_all
                    echo "Exiting menu after uninstall."
                    exit 0
                else
                    echo "Uninstall cancelled."
                    press_enter_to_continue
                fi
                ;;
            *) echo -e "${RED}Invalid option.${NC}"; press_enter_to_continue ;;
        esac
    done
}

main
EOF

    chmod +x /usr/local/bin/menu
    info "User  management menu installed at /usr/local/bin/menu"
}

# --- Uninstall function for main script ---
uninstall_all() {
    echo -e "${YELLOW}Starting uninstall process...${NC}"

    # Stop and disable services
    systemctl stop xray squid fail2ban >/dev/null 2>&1 || true
    systemctl disable xray squid fail2ban badvpn@7100 badvpn@7200 badvpn@7300 >/dev/null 2>&1 || true

    # Remove xray files
    rm -f /usr/local/bin/xray
    rm -rf /usr/local/etc/xray
    rm -f /root/xray_credentials.txt
    rm -f /root/domain.txt

    # Backup squid config if exists
    if [ -f /etc/squid/squid.conf ]; then
        mv /etc/squid/squid.conf /etc/squid/squid.conf.bak_$(date +%s)
    fi

    # Remove badvpn binary and service files
    rm -f /usr/local/bin/badvpn-udpgw
    rm -f /etc/systemd/system/badvpn@.service
    systemctl daemon-reload

    # Remove user database and menu
    rm -rf /etc/regarstore
    rm -f /usr/local/bin/menu

    # Remove ufw rules added by script
    ufw delete allow 22/tcp || true
    ufw delete allow 80/tcp || true
    ufw delete allow 443/tcp || true
    ufw delete allow 3128/tcp || true
    ufw delete allow 8080/tcp || true

    # Optionally reset ufw (commented out)
    # ufw reset -y

    # Remove installed packages
    apt-get remove --purge -y \
        wget curl socat htop cron \
        build-essential libnss3-dev \
        zlib1g-dev libssl-dev libgmp-dev \
        ufw fail2ban \
        unzip zip \
        python3 python3-pip \
        jq certbot dnsutils \
        squid git cmake

    apt-get autoremove -y
    apt-get clean

    echo -e "${GREEN}Uninstall process completed.${NC}"
}

# --- Main menu ---
show_main_menu() {
    echo "========================================"
    echo " 1. Setup XRAY and Services"
    echo " 2. Run User Management Menu"
    echo " 3. Uninstall All Installed Packages and Configurations"
    echo " 4. Exit"
    echo "========================================"
}

main_menu() {
    while true; do
        show_main_menu
        read -p "Select an option [1-4]: " opt
        case $opt in
            1)
                check_root
                check_os
                install_dependencies
                ask_domain
                setup_xray
                setup_support_services
                setup_security
                setup_management_menu
                echo -e "${GREEN}Setup completed. You can run the user management menu by executing: menu${NC}"
                ;;
            2)
                if [ -x /usr/local/bin/menu ]; then
                    /usr/local/bin/menu
                else
                    echo -e "${RED}User  management menu not found. Please run setup first.${NC}"
                fi
                ;;
            3)
                read -p "Are you sure you want to uninstall everything? [y/N]: " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    uninstall_all
                else
                    echo "Uninstall cancelled."
                fi
                ;;
            4)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option.${NC}"
                ;;
        esac
    done
}

# --- Script entrypoint ---
check_root
main_menu
