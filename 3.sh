#!/bin/bash
set -e

# =================================================================================
# Script Name   : VPN Tunnel Premium Installer (No OpenVPN, SSH, Stunnel)
# Description   : Setup VPN server with XRAY, Squid, Badvpn, firewall, user menu.
# Author        : Jules for Regar Store (modified)
# =================================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

DOMAIN=""

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run as root."
    fi
}

install_dependencies() {
    info "Updating package lists..."
    apt-get update -y >/dev/null 2>&1

    info "Installing base dependencies..."
    apt-get install -y \
        wget curl socat htop cron \
        build-essential libnss3-dev \
        zlib1g-dev libssl-dev libgmp-dev \
        ufw fail2ban \
        unzip zip \
        python3 python3-pip \
        squid haveged certbot acl jq dnsutils git cmake

    info "Installing Python WebSocket proxy..."
    pip3 install proxy.py >/dev/null 2>&1
    info "Base dependencies installed."
}

ask_domain() {
    info "Untuk sertifikat SSL, Anda memerlukan sebuah domain."
    read -rp "Silakan masukkan nama domain Anda (contoh: mydomain.com): " DOMAIN
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

    info "Performing DNS pre-flight check for $DOMAIN..."
    local_ip=$(curl -s ifconfig.me)
    resolved_ip=$(dig +short "$DOMAIN" @8.8.8.8)

    if [[ "$local_ip" != "$resolved_ip" ]]; then
        error "DNS validation failed. Domain '$DOMAIN' points to '$resolved_ip', VPS IP is '$local_ip'."
    fi
    info "DNS check passed."

    info "Obtaining SSL certificate for $DOMAIN..."
    ufw allow 80/tcp
    systemctl stop xray >/dev/null 2>&1 || true
    if ! certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" --preferred-challenges http; then
        error "Failed to obtain SSL certificate."
    fi
    ufw deny 80/tcp
    systemctl start xray

    info "SSL certificate obtained."

    VLESS_UUID=$(xray uuid)
    VMESS_UUID=$(xray uuid)
    TROJAN_PASSWORD=$(openssl rand -base64 16)

    echo "VLESS_UUID=${VLESS_UUID}" > /root/xray_credentials.txt
    echo "VMESS_UUID=${VMESS_UUID}" >> /root/xray_credentials.txt
    echo "TROJAN_PASSWORD=${TROJAN_PASSWORD}" >> /root/xray_credentials.txt

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
        "statsUser  Uplink": true,
        "statsUser  Downlink": true
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
        "decryption": "none"
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
      "port": 80,
      "protocol": "vmess",
      "tag": "vmess-in",
      "settings": { "clients": [ { "id": "${VMESS_UUID}", "alterId": 0, "email": "user@${DOMAIN}" } ] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } }
    },
    {
      "port": 8083,
      "protocol": "trojan",
      "tag": "trojan-in",
      "settings": { "clients": [ { "password": "${TROJAN_PASSWORD}", "email": "user@${DOMAIN}" } ] },
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
    systemctl enable xray >/dev/null 2>&1
    systemctl restart xray

    if ! systemctl is-active --quiet xray; then
        error "XRAY service failed to start. Periksa 'journalctl -u xray'."
    fi

    info "XRAY setup completed."
}

setup_support_services() {
    info "Setting up Squid Proxy and Badvpn..."

    # Configure Squid Proxy
    info "Configuring Squid Proxy on ports 3128 & 8080..."
    if [ -f /etc/squid/squid.conf ]; then
        sed -i 's/http_access deny all/http_access allow all/' /etc/squid/squid.conf
        sed -i 's/http_access allow localhost/#http_access allow localhost/' /etc/squid/squid.conf
        grep -q -F "http_port 8080" /etc/squid/squid.conf || echo "http_port 8080" >> /etc/squid/squid.conf
        grep -q -F "http_port 3128" /etc/squid/squid.conf || echo "http_port 3128" >> /etc/squid/squid.conf
        DOMAIN=$(cat /root/domain.txt)
        sed -i "s/# visible_hostname .*/visible_hostname $DOMAIN/" /etc/squid/squid.conf

        systemctl enable squid >/dev/null 2>&1
        systemctl restart squid
    else
        warn "Squid configuration file not found. Skipping."
    fi

    # Compile and install Badvpn UDP Gateway
    info "Compiling and installing Badvpn UDP Gateway..."
    cd /root
    if [ ! -d badvpn ]; then
        git clone https://github.com/ambrop72/badvpn.git >/dev/null 2>&1
    fi
    mkdir -p /root/badvpn/build
    cd /root/badvpn/build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null 2>&1
    make >/dev/null 2>&1

    if [ -f /root/badvpn/build/udpgw/badvpn-udpgw ]; then
        mv /root/badvpn/build/udpgw/badvpn-udpgw /usr/local/bin/
    else
        error "Badvpn compilation failed."
    fi
    cd /root
    rm -rf /root/badvpn

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
        systemctl enable badvpn@${port} >/dev/null 2>&1
        systemctl start badvpn@${port}
    done

    info "Support services setup completed."
}

setup_security() {
    info "Setting up Firewall, Fail2Ban, and BBR..."

    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1

    ufw allow 80/tcp      # XRAY Non-TLS
    ufw allow 443/tcp     # XRAY TLS
    ufw allow 3128/tcp    # Squid
    ufw allow 8080/tcp    # Squid

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
    touch /etc/regarstore/users.db

    cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

USER_DB="/etc/regarstore/users.db"
XRAY_BIN="/usr/local/bin/xray"
XRAY_API_ADDR="127.0.0.1:10085"

function press_enter() {
    echo
    read -rp "Press Enter to continue..."
}

function add_user() {
    echo "=== Add XRAY User ==="
    read -rp "Username (email): " email
    read -rp "Protocol [vless/vmess/trojan]: " proto
    read -rp "Quota (GB, 0 unlimited): " quota
    read -rp "IP Limit (0 unlimited): " ip_limit
    read -rp "Expire days: " days

    exp_date=$(date -d "+$days days" +"%Y-%m-%d")

    case $proto in
        vless)
            id=$($XRAY_BIN uuid)
            client="{\"id\":\"$id\",\"level\":0,\"email\":\"$email\"}"
            inbound="vless-in"
            ;;
        vmess)
            id=$($XRAY_BIN uuid)
            client="{\"id\":\"$id\",\"alterId\":0,\"email\":\"$email\"}"
            inbound="vmess-in"
            ;;
        trojan)
            id=$(openssl rand -base64 12)
            client="{\"password\":\"$id\",\"email\":\"$email\"}"
            inbound="trojan-in"
            ;;
        *)
            echo -e "${RED}Protocol tidak valid.${NC}"
            return
            ;;
    esac

    tmpfile=$(mktemp)
    jq ".inbounds[] | select(.tag==\"$inbound\").settings.clients += [$client]" /usr/local/etc/xray/config.json > "$tmpfile" && \
    jq ".inbounds" /usr/local/etc/xray/config.json > /dev/null 2>&1

    # Update config.json clients array
    jq "(.inbounds[] | select(.tag==\"$inbound\").settings.clients) += [$client]" /usr/local/etc/xray/config.json > "$tmpfile" && mv "$tmpfile" /usr/local/etc/xray/config.json

    echo "$email;$proto;$id;$quota;$ip_limit;$exp_date" >> "$USER_DB"
    systemctl restart xray
    echo -e "${GREEN}User  $email ditambahkan.${NC}"
    echo "ID/Password: $id"
}

function list_users() {
    echo "=== Daftar User XRAY ==="
    printf "%-25s %-8s %-8s %-8s %-12s\n" "Email" "Proto" "Quota" "IP Lim" "Expire"
    echo "-------------------------------------------------------------"
    while IFS=';' read -r email proto id quota ip_limit exp; do
        [[ "$email" =~ ^#.*$ ]] && continue
        printf "%-25s %-8s %-8s %-8s %-12s\n" "$email" "$proto" "$quota" "$ip_limit" "$exp"
    done < "$USER_DB"
}

function del_user() {
    read -rp "Username (email) to delete: " email
    if ! grep -q "^$email;" "$USER_DB"; then
        echo -e "${RED}User  tidak ditemukan.${NC}"
        return
    fi
    proto=$(grep "^$email;" "$USER_DB" | cut -d';' -f2)
    inbound="${proto}-in"
    tmpfile=$(mktemp)
    jq "del(.inbounds[] | select(.tag==\"$inbound\").settings.clients[] | select(.email==\"$email\"))" /usr/local/etc/xray/config.json > "$tmpfile" && mv "$tmpfile" /usr/local/etc/xray/config.json
    sed -i "/^$email;/d" "$USER_DB"
    systemctl restart xray
    echo -e "${GREEN}User  $email dihapus.${NC}"
}

function show_menu() {
    clear
    echo "=== Regar Store VPN Menu ==="
    echo "1) Tambah User XRAY"
    echo "2) Hapus User XRAY"
    echo "3) List User XRAY"
    echo "4) Keluar"
}

while true; do
    show_menu
    read -rp "Pilih opsi [1-4]: " opt
    case $opt in
        1) add_user; press_enter ;;
        2) del_user; press_enter ;;
        3) list_users; press_enter ;;
        4) exit 0 ;;
        *) echo "Opsi tidak valid." ;;
    esac
done
EOF

    chmod +x /usr/local/bin/menu
    info "Menu manajemen dibuat. Jalankan dengan perintah 'menu'."
}

finalize_installation() {
    info "Finalizing installation..."

    cat > /usr/local/bin/motd_generator << 'EOF'
#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

domain=$(cat /root/domain.txt)
ip=$(curl -s ifconfig.me)
date_now=$(date +"%Y-%m-%d %H:%M:%S")

echo -e "${GREEN}==============================================${NC}"
echo -e "   Selamat datang di Regar Store VPN Server"
echo -e "   Domain: ${YELLOW}$domain${NC}"
echo -e "   IP VPS: ${YELLOW}$ip${NC}"
echo -e "   Waktu : ${YELLOW}$date_now${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "Ketik 'menu' untuk membuka menu manajemen."
EOF

    chmod +x /usr/local/bin/motd_generator
    echo "/usr/local/bin/motd_generator" > /etc/profile.d/99-regarstore-motd.sh

    # Setup cron jobs
    (crontab -l 2>/dev/null; echo "0 5 * * * /usr/bin/certbot renew --quiet --pre-hook 'systemctl stop xray' --post-hook 'systemctl start xray'") | crontab -
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/vpn-monitor >> /var/log/vpn-monitor.log 2>&1") | crontab -

    info "Instalasi selesai! Silakan reboot server Anda."
}

create_vpn_monitor() {
    cat > /usr/local/bin/vpn-monitor << 'EOF'
#!/bin/bash
USER_DB="/etc/regarstore/users.db"
XRAY_API_ADDR="127.0.0.1:10085"
XRAY_BIN="/usr/local/bin/xray"
LOG_FILE="/var/log/vpn-monitor.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

remove_user() {
    local email="$1"
    local proto="$2"
    local inbound="${proto}-in"

    log "Removing user $email due to quota or expiration."
    # Hapus user dari config XRAY via API
    $XRAY_BIN api inbound remove --server=$XRAY_API_ADDR --tag="$inbound" --email="$email" >/dev/null 2>&1

    # Hapus dari database lokal
    sed -i "/^$email;/d" "$USER_DB"
    log "User  $email removed."
}

check_users() {
    if [ ! -f "$USER_DB" ]; then
        log "User  database not found."
        exit 1
    fi

    current_date_s=$(date +%s)

    while IFS=';' read -r email proto id quota ip_limit exp_date; do
        [[ "$email" =~ ^#.*$ ]] && continue
        [[ -z "$email" ]] && continue

        exp_date_s=$(date -d "$exp_date" +%s)
        if (( current_date_s > exp_date_s )); then
            remove_user "$email" "$proto"
            continue
        fi

        if (( quota > 0 )); then
            uplink=$($XRAY_BIN api stats --server=$XRAY_API_ADDR --query "user>>>$email>>>traffic>>>uplink" --reset 2>/dev/null || echo 0)
            downlink=$($XRAY_BIN api stats --server=$XRAY_API_ADDR --query "user>>>$email>>>traffic>>>downlink" --reset 2>/dev/null || echo 0)

            usage_file="/etc/regarstore/usage/${email}.usage"
            mkdir -p /etc/regarstore/usage
            prev_usage=$(cat "$usage_file" 2>/dev/null || echo 0)
            total_usage=$((prev_usage + uplink + downlink))
            echo "$total_usage" > "$usage_file"

            quota_bytes=$((quota * 1024 * 1024 * 1024))
            if (( total_usage > quota_bytes )); then
                remove_user "$email" "$proto"
                rm -f "$usage_file"
            fi
        fi
    done < "$USER_DB"
}

log "VPN monitor started."
check_users
log "VPN monitor finished."
EOF

    chmod +x /usr/local/bin/vpn-monitor
    info "VPN monitor script created at /usr/local/bin/vpn-monitor"
}

main() {
    check_root
    warn "Pastikan domain Anda sudah di-pointing ke IP Address VPS ini."
    ask_domain
    install_dependencies
    setup_xray
    setup_support_services
    setup_security
    setup_management_menu
    create_vpn_monitor
    finalize_installation
    info "Instalasi selesai! Silakan reboot server Anda."
    # reboot
}

main
