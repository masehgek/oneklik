#!/bin/bash
set -e

# =================================================================================
# Script Name   : XRAY Installer + User Management (Fixed JSON edit)
# Description   : Install XRAY dan kelola user dengan edit config JSON langsung.
# Author        : Modified for user request
# =================================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

CONFIG_FILE="/usr/local/etc/xray/config.json"
USER_DB="/etc/regarstore/users.db"

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Script harus dijalankan sebagai root."
    fi
}

install_dependencies() {
    info "Update dan install dependensi..."
    apt-get update -y
    apt-get install -y wget curl socat htop cron build-essential libnss3-dev zlib1g-dev libssl-dev libgmp-dev ufw fail2ban unzip zip python3 python3-pip certbot jq git cmake
    pip3 install proxy.py >/dev/null 2>&1
}

ask_domain() {
    read -rp "Masukkan domain Anda (contoh: example.com): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        error "Domain tidak boleh kosong."
    fi
    echo "$DOMAIN" > /root/domain.txt
    info "Domain disimpan: $DOMAIN"
}

install_xray() {
    info "Menginstal XRAY core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata >/dev/null 2>&1
}

obtain_ssl() {
    DOMAIN=$(cat /root/domain.txt)
    info "Mendapatkan sertifikat SSL untuk $DOMAIN..."
    ufw allow 80/tcp
    if ! certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN"; then
        error "Gagal mendapatkan sertifikat SSL. Pastikan domain sudah diarahkan ke IP VPS."
    fi
    ufw deny 80/tcp
    info "Sertifikat SSL berhasil didapatkan."
}

generate_uuids() {
    VLESS_UUID=$(xray uuid)
    VMESS_UUID=$(xray uuid)
    TROJAN_PASS=$(openssl rand -base64 16)
    echo "VLESS_UUID=$VLESS_UUID" > /root/xray_credentials.txt
    echo "VMESS_UUID=$VMESS_UUID" >> /root/xray_credentials.txt
    echo "TROJAN_PASS=$TROJAN_PASS" >> /root/xray_credentials.txt
}

create_xray_config() {
    DOMAIN=$(cat /root/domain.txt)
    source /root/xray_credentials.txt

    mkdir -p /usr/local/etc/xray
    cat > "$CONFIG_FILE" << EOF
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
        "statsUser     Uplink": true,
        "statsUser     Downlink": true
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
      "port": 8082,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "tag": "vmess-in",
      "settings": { "clients": [{"id": "${VMESS_UUID}", "alterId": 0, "email": "user@${DOMAIN}"}] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } }
    },
    {
      "port": 8083,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "tag": "trojan-in",
      "settings": { "clients": [{"password": "${TROJAN_PASS}", "email": "user@${DOMAIN}"}] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } }
    },
    {
      "port": 80,
      "protocol": "vmess",
      "tag": "vmess-http-in",
      "settings": { "clients": [ { "id": "${VMESS_UUID}", "alterId": 0, "email": "user@${DOMAIN}" } ] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess-http" } }
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

    chown root:root "$CONFIG_FILE"
    chmod 644 "$CONFIG_FILE"
    info "Konfigurasi XRAY dibuat."
}

start_xray() {
    systemctl daemon-reload
    systemctl enable xray
    systemctl restart xray
    sleep 3
    if systemctl is-active --quiet xray; then
        info "XRAY service berjalan dengan baik."
    else
        error "XRAY gagal dijalankan. Cek log dengan: journalctl -xeu xray"
    fi
}

setup_security() {
    info "Mengatur Firewall, Fail2Ban, dan BBR..."

    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 443/tcp
    ufw allow 80/tcp
    yes | ufw enable

    systemctl enable fail2ban
    systemctl restart fail2ban

    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi

    sysctl -p >/dev/null 2>&1

    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        info "TCP BBR berhasil diaktifkan."
    else
        warn "TCP BBR gagal diaktifkan."
    fi

    info "Pengaturan keamanan dan performa selesai."
}

setup_management_menu() {
    info "Membuat menu manajemen pengguna..."

    mkdir -p /etc/regarstore
    if [ ! -f "$USER_DB" ]; then
        echo "# Format: username;protocol;uuid_or_pass;quota_gb;ip_limit;exp_date" > "$USER_DB"
    fi

    cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

USER_DB="/etc/regarstore/users.db"
CONFIG_FILE="/usr/local/etc/xray/config.json"
XRAY_SERVICE="xray"

press_enter_to_continue() {
    echo ""
    read -p "Press Enter to continue..."
}

show_menu() {
    clear
    echo "========================================"
    echo -e "    ${YELLOW}REGAR STORE - VPN SERVER MENU${NC}"
    echo "========================================"
    echo " 1. Add XRAY User (VLESS/VMess/Trojan)"
    echo " 2. Delete XRAY User"
    echo " 3. List XRAY Users"
    echo " 4. Check XRAY Service Status"
    echo " 5. Renew SSL Certificate"
    echo " 6. Reboot Server"
    echo " 7. Exit"
    echo "----------------------------------------"
}

add_user() {
    echo "--- Add XRAY User ---"
    read -p "Enter username (email format): " email
    read -p "Select Protocol [1=VLESS, 2=VMess, 3=Trojan]: " proto_choice
    read -p "Enter Quota (GB, 0 for unlimited): " quota_gb
    read -p "Enter IP Limit (0 for unlimited): " ip_limit
    read -p "Enter expiration days (e.g., 30): " days

    exp_date=$(date -d "+$days days" +"%Y-%m-%d")

    local protocol inbound_tag client_id client_pass

    case $proto_choice in
        1)
            protocol="vless"
            inbound_tag="vless-in"
            client_id=$(xray uuid)
            ;;
        2)
            protocol="vmess"
            inbound_tag="vmess-in"
            client_id=$(xray uuid)
            ;;
        3)
            protocol="trojan"
            inbound_tag="trojan-in"
            client_pass=$(openssl rand -base64 12)
            ;;
        *)
            echo -e "${RED}Invalid protocol choice.${NC}"
            return
            ;;
    esac

    # Backup config
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"

    if [[ "$protocol" == "trojan" ]]; then
        # Add trojan client
        tmpfile=$(mktemp)
        jq --arg pass "$client_pass" --arg email "$email" \
           '(.inbounds[] | select(.tag == "trojan-in") | .settings.clients) += [{"password": $pass, "email": $email}]' \
           "$CONFIG_FILE" > "$tmpfile" && mv "$tmpfile" "$CONFIG_FILE"
        creds="$client_pass"
    else
        # Add vless or vmess client
        tmpfile=$(mktemp)
        jq --arg id "$client_id" --arg email "$email" \
           '(.inbounds[] | select(.tag == $inbound_tag) | .settings.clients) += [{"id": $id, "level": 0, "email": $email}]' \
           --arg inbound_tag "$inbound_tag" "$CONFIG_FILE" > "$tmpfile" && mv "$tmpfile" "$CONFIG_FILE"
        creds="$client_id"
    fi

    systemctl restart "$XRAY_SERVICE"

    echo "$email;$protocol;$creds;$quota_gb;$ip_limit;$exp_date" >> "$USER_DB"
    echo -e "${GREEN}User  '$email' ($protocol) berhasil ditambahkan.${NC}"
    echo "UUID/Password: $creds"
}

delete_user() {
    echo "--- Delete XRAY User ---"
    read -p "Enter username (email) to delete: " email

    if ! grep -q "^$email;" "$USER_DB"; then
        echo -e "${RED}User  '$email' tidak ditemukan.${NC}"
        return
    fi

    protocol=$(grep "^$email;" "$USER_DB" | cut -d';' -f2)
    creds=$(grep "^$email;" "$USER_DB" | cut -d';' -f3)
    inbound_tag="${protocol}-in"

    # Backup config
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"

    if [[ "$protocol" == "trojan" ]]; then
        tmpfile=$(mktemp)
        jq --arg pass "$creds" \
           '(.inbounds[] | select(.tag == "trojan-in") | .settings.clients) |= map(select(.password != $pass))' \
           "$CONFIG_FILE" > "$tmpfile" && mv "$tmpfile" "$CONFIG_FILE"
    else
        tmpfile=$(mktemp)
        jq --arg id "$creds" \
           '(.inbounds[] | select(.tag == "'$inbound_tag'") | .settings.clients) |= map(select(.id != $id))' \
           "$CONFIG_FILE" > "$tmpfile" && mv "$tmpfile" "$CONFIG_FILE"
    fi

    systemctl restart "$XRAY_SERVICE"

    sed -i "/^$email;/d" "$USER_DB"
    echo -e "${GREEN}User  '$email' berhasil dihapus.${NC}"
}

list_users() {
    echo "--- Daftar User XRAY ---"
    printf "%-25s | %-8s | %-36s | %-10s | %-10s | %-12s\n" "Email" "Protocol" "UUID/Password" "Quota(GB)" "IP Limit" "Expires"
    echo "---------------------------------------------------------------------------------------------------------------"
    grep -v '^#' "$USER_DB" | while IFS=';' read -r email protocol creds quota ip_limit exp_date; do
        printf "%-25s | %-8s | %-36s | %-10s | %-10s | %-12s\n" "$email" "$protocol" "$creds" "$quota" "$ip_limit" "$exp_date"
    done
    echo "---------------------------------------------------------------------------------------------------------------"
}

check_service() {
    echo "--- Status Service XRAY ---"
    if systemctl is-active --quiet xray; then
        echo -e "xray: ${GREEN}Running${NC}"
    else
        echo -e "xray: ${RED}Stopped${NC}"
    fi
}

renew_ssl() {
    echo "Renewing SSL certificate..."
    certbot renew --quiet
    echo "Selesai."
}

while true; do
    show_menu
    read -rp "Pilih menu [1-7]: " choice
    case $choice in
        1) add_user; press_enter_to_continue ;;
        2) delete_user; press_enter_to_continue ;;
        3) list_users; press_enter_to_continue ;;
        4) check_service; press_enter_to_continue ;;
        5) renew_ssl; press_enter_to_continue ;;
        6) reboot ;;
        7) exit 0 ;;
        *) echo -e "${RED}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
done
EOF

    chmod +x /usr/local/bin/menu
    info "Menu manajemen pengguna siap. Ketik 'menu' untuk menggunakannya."
}

finalize_installation() {
    info "Finalisasi instalasi..."

    echo "========================================" > /etc/motd
    echo "" >> /etc/motd
    echo "   Welcome to REGAR STORE VPN Server    " >> /etc/motd
    echo "" >> /etc/motd
    echo "   Ketik 'menu' untuk mengelola pengguna dan layanan " >> /etc/motd
    echo "" >> /etc/motd
    echo "========================================" >> /etc/motd

    (crontab -l 2>/dev/null; echo "0 5 * * * /usr/bin/certbot renew --quiet") | crontab -

    info "Instalasi selesai! Silakan reboot server."
}

main() {
    check_root
    warn "Pastikan domain Anda sudah di-pointing ke IP Address VPS ini."
    ask_domain
    install_dependencies
    setup_management_menu
    install_xray
    obtain_ssl
    generate_uuids
    create_xray_config
    start_xray
    setup_security
    finalize_installation
}

main
