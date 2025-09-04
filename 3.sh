#!/bin/bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

DOMAIN=""

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root."
    fi
}

install_dependencies() {
    info "Updating package lists..."
    apt-get update -y >/dev/null 2>&1

    info "Installing dependencies..."
    apt-get install -y wget curl socat htop cron build-essential libnss3-dev \
        zlib1g-dev libssl-dev libgmp-dev ufw fail2ban unzip zip python3 python3-pip \
        haveged certbot jq git cmake >/dev/null 2>&1

    info "Installing Python WebSocket proxy..."
    pip3 install proxy.py >/dev/null 2>&1
    info "Dependencies installed."
}

ask_domain() {
    info "Untuk sertifikat SSL, Anda memerlukan sebuah domain."
    read -rp "Masukkan nama domain Anda (contoh: mydomain.com): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        error "Domain tidak boleh kosong."
    fi
    info "Domain diset ke: $DOMAIN"
    echo "$DOMAIN" > /root/domain.txt
}

setup_xray() {
    info "Menginstall XRAY core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata >/dev/null 2>&1

    DOMAIN=$(cat /root/domain.txt)

    info "Mendapatkan sertifikat SSL untuk $DOMAIN..."
    ufw allow 80/tcp
    if ! certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" --preferred-challenges http; then
        error "Gagal mendapatkan sertifikat SSL. Pastikan domain sudah diarahkan ke IP VPS."
    fi
    ufw deny 80/tcp
    info "Sertifikat SSL berhasil didapatkan."

    info "Membuat konfigurasi XRAY..."
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
      "settings": { "clients": [{"password": "${TROJAN_PASSWORD}", "email": "user@${DOMAIN}"}] },
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

    systemctl enable xray >/dev/null 2>&1
    systemctl restart xray

    info "XRAY setup selesai."
}

setup_security() {
    info "Mengatur Firewall, Fail2Ban, dan BBR..."

    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1

    ufw allow 80/tcp
    ufw allow 443/tcp

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
        info "TCP BBR berhasil diaktifkan."
    else
        warn "TCP BBR gagal diaktifkan."
    fi

    info "Pengaturan keamanan selesai."
}

generate_vless_url() {
    local uuid="$1"
    local domain="$2"
    local port=443
    local path="%252fvless"  # URL encoded "/vless"
    local host="${domain}"
    local sni="${domain}"
    local tag="${uuid}"

    echo "vless://${uuid}@${domain}:${port}/?security=tls&encryption=none&headerType=none&type=ws&flow=none&host=${host}&path=${path}&fp=random&sni=${sni}#${tag}"
}

generate_trojan_url() {
    local password="$1"
    local domain="$2"
    local port=443
    local path="%2ftrojan"  # URL encoded "/trojan"
    local host="${domain}"
    local sni="${domain}"
    local tag="${password}"

    echo "trojan://${password}@${domain}:${port}/?security=tls&type=ws&host=${host}&headerType=none&path=${path}&sni=${sni}#${tag}"
}

setup_management_menu() {
    info "Membuat menu manajemen pengguna..."

    mkdir -p /etc/regarstore
    cat > /etc/regarstore/users.db << EOF
# Format: username;protocol;uuid_or_pass;quota_gb;ip_limit;exp_date
EOF

    cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

USER_DB="/etc/regarstore/users.db"
XRAY_API_ADDR="127.0.0.1:10085"
XRAY_BIN="/usr/local/bin/xray"
DOMAIN=$(cat /root/domain.txt)

press_enter_to_continue() {
    echo ""
    read -p "Tekan Enter untuk melanjutkan..."
}

generate_vless_url() {
    local uuid="$1"
    local domain="$2"
    local port=443
    local path="%252fvless"
    local host="${domain}"
    local sni="${domain}"
    local tag="${uuid}"

    echo "vless://${uuid}@${domain}:${port}/?security=tls&encryption=none&headerType=none&type=ws&flow=none&host=${host}&path=${path}&fp=random&sni=${sni}#${tag}"
}

generate_trojan_url() {
    local password="$1"
    local domain="$2"
    local port=443
    local path="%2ftrojan"
    local host="${domain}"
    local sni="${domain}"
    local tag="${password}"

    echo "trojan://${password}@${domain}:${port}/?security=tls&type=ws&host=${host}&headerType=none&path=${path}&sni=${sni}#${tag}"
}

show_menu() {
    clear
    echo "========================================"
    echo -e "    ${YELLOW}REGAR STORE - VPN SERVER MENU${NC}"
    echo "========================================"
    echo " 1. Tambah User XRAY (VLESS/VMess/Trojan)"
    echo " 2. Hapus User XRAY"
    echo " 3. Daftar User XRAY"
    echo " 4. Cek Status Service"
    echo " 5. Perbarui Sertifikat SSL"
    echo " 6. Reboot Server"
    echo " 7. Keluar"
    echo "----------------------------------------"
}

add_xray_user() {
    echo "--- Tambah User XRAY ---"
    read -rp "Masukkan username (format email, misal user@domain.com): " email
    read -rp "Pilih protokol [1=VLESS, 2=VMess, 3=Trojan]: " proto_choice
    read -rp "Masukkan kuota (GB, 0 untuk unlimited): " quota_gb
    read -rp "Masukkan batas IP (0 untuk unlimited): " ip_limit
    read -rp "Masukkan masa aktif (hari, misal 30): " days

    exp_date=$(date -d "+$days days" +"%Y-%m-%d")

    local protocol_name inbound_tag creds_id creds_pass settings

    case $proto_choice in
        1) protocol_name="vless"; inbound_tag="vless-in"; creds_id=$($XRAY_BIN uuid) ;;
        2) protocol_name="vmess"; inbound_tag="vmess-in"; creds_id=$($XRAY_BIN uuid) ;;
        3) protocol_name="trojan"; inbound_tag="trojan-in"; creds_pass=$(openssl rand -base64 12) ;;
        *) echo -e "${RED}Pilihan protokol tidak valid.${NC}"; return ;;
    esac

    if [[ -n "$creds_pass" ]]; then
        settings="{\"clients\": [{\"password\": \"$creds_pass\", \"email\": \"$email\", \"level\": 0}]}"
        creds_for_db=$creds_pass
    else
        settings="{\"clients\": [{\"id\": \"$creds_id\", \"email\": \"$email\", \"level\": 0}]}"
        creds_for_db=$creds_id
    fi

    result=$($XRAY_BIN api inbound add --server=$XRAY_API_ADDR --tag=$inbound_tag --protocol=$protocol_name --settings="$settings" 2>&1)

    if [[ $? -eq 0 ]]; then
        echo "$email;$protocol_name;$creds_for_db;$quota_gb;$ip_limit;$exp_date" >> "$USER_DB"
        echo -e "${GREEN}User   '$email' untuk $protocol_name berhasil ditambahkan.${NC}"
        if [[ "$protocol_name" == "vless" ]]; then
            vless_url=$(generate_vless_url "$creds_for_db" "$DOMAIN")
            echo -e "${GREEN}URL VLESS:${NC} $vless_url"
        elif [[ "$protocol_name" == "trojan" ]]; then
            trojan_url=$(generate_trojan_url "$creds_for_db" "$DOMAIN")
            echo -e "${GREEN}URL Trojan:${NC} $trojan_url"
        else
            echo "Credentials: $creds_for_db"
        fi
    else
        echo -e "${RED}Gagal menambahkan user ke XRAY. Error: $result${NC}"
    fi
}

delete_xray_user() {
    read -rp "Masukkan username (email) yang akan dihapus: " email

    user_line=$(grep "^$email;" "$USER_DB")
    if [[ -z "$user_line" ]]; then
        echo -e "${RED}User   '$email' tidak ditemukan di database.${NC}"
        return
    fi

    protocol_name=$(echo "$user_line" | cut -d';' -f2)
    inbound_tag="${protocol_name}-in"

    result=$($XRAY_BIN api inbound remove --server=$XRAY_API_ADDR --tag="$inbound_tag" --email="$email" 2>&1)

    if [[ $? -eq 0 ]]; then
        sed -i "/^$email;/d" "$USER_DB"
        echo -e "${GREEN}User   '$email' berhasil dihapus dari $protocol_name.${NC}"
    else
        echo -e "${RED}Gagal menghapus user dari XRAY. Error: $result${NC}"
    fi
}

list_xray_users() {
    echo "--- Daftar User XRAY ---"
    printf "%-30s | %-8s | %-10s | %-10s | %-12s\n" "Email" "Protokol" "Kuota(GB)" "Batas IP" "Kadaluarsa"
    echo "--------------------------------------------------------------------------------"
    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        [[ "$email" == \#* ]] && continue
        printf "%-30s | %-8s | %-10s | %-10s | %-12s\n" "$email" "$protocol" "$quota_gb" "$ip_limit" "$exp_date"
    done < "$USER_DB"
    echo "--------------------------------------------------------------------------------"
}

check_services() {
    echo "--- Status Service ---"
    SERVICES=("xray")
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "$service: ${GREEN}Berjalan${NC}"
        else
            echo -e "$service: ${RED}Berhenti${NC}"
        fi
    done
    echo "----------------------"
}

renew_ssl() {
    echo "Memperbarui Sertifikat SSL..."
    certbot renew --quiet
    systemctl restart xray
    echo "Selesai."
}

while true; do
    show_menu
    read -rp "Pilih menu [1-7]: " choice
    case $choice in
        1) add_xray_user; press_enter_to_continue ;;
        2) delete_xray_user; press_enter_to_continue ;;
        3) list_xray_users; press_enter_to_continue ;;
        4) check_services; press_enter_to_continue ;;
        5) renew_ssl; press_enter_to_continue ;;
        6) reboot ;;
        7) exit 0 ;;
        *) echo -e "${RED}Pilihan tidak valid. Coba lagi.${NC}"; sleep 1 ;;
    esac
done
EOF

    chmod +x /usr/local/bin/menu
    info "Menu manajemen dibuat. Ketik 'menu' untuk menggunakannya."
}

finalize_installation() {
    info "Menyelesaikan instalasi..."

    cat > /etc/motd << EOF
========================================

   Welcome to REGAR STORE VPN Server

   Ketik 'menu' untuk mengelola pengguna dan layanan

========================================
EOF

    (crontab -l 2>/dev/null; echo "0 5 * * * /usr/bin/certbot renew --quiet --pre-hook 'systemctl stop xray' --post-hook 'systemctl start xray'") | crontab -

    info "Instalasi selesai! Silakan reboot server."
}

main() {
    check_root
    ask_domain
    install_dependencies
    setup_xray
    setup_security
    setup_management_menu
    finalize_installation
}

main
