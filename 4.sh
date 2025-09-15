#!/bin/bash
set -e

# --- Color Codes ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Global Variables ---
DOMAIN=""

# --- Helper Functions ---
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- Pre-flight Checks ---
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "Script ini harus dijalankan sebagai root."
    fi
}

# --- Installation Functions ---
install_dependencies() {
    info "Menginstall dependensi dasar..."
    apt-get update >/dev/null 2>&1
    apt-get install -y wget curl certbot ufw fail2ban jq cron >/dev/null 2>&1
}

ask_domain() {
    read -p "Masukkan nama domain Anda: " DOMAIN
    if [ -z "$DOMAIN" ]; then
        error "Domain tidak boleh kosong."
    fi
    echo "$DOMAIN" > /root/domain.txt
}

setup_xray() {
    info "Menginstall XRAY core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
    
    info "Downloading Geodata files..."
    mkdir -p /usr/local/share/xray
    wget -q -O /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    wget -q -O /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
    
    info "Membuat sertifikat SSL..."
    ufw allow 80/tcp
    ufw allow 443/tcp
    systemctl stop xray 2>/dev/null || true
    certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN"
    
    info "Membuat konfigurasi XRAY..."
    VLESS_UUID=$(xray uuid)
    
    cat > /usr/local/etc/xray/config.json << END
{
  "log": { "loglevel": "warning" },
  "api": { "tag": "api", "services": ["StatsService"] },
  "stats": {},
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
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
      "tag": "vless-tls",
      "settings": {
        "clients": [ { "id": "${VLESS_UUID}", "email": "default@${DOMAIN}" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
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
      "protocol": "vless",
      "tag": "vless-nontls",
      "settings": {
        "clients": [ { "id": "${VLESS_UUID}", "email": "default@${DOMAIN}" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "path": "/vless" }
      }
    }
  ],
  "outbounds": [ 
    { "protocol": "freedom" },
    { "protocol": "blackhole", "tag": "blocked" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": [ "api-in" ], "outboundTag": "api" },
      { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "blocked" }
    ]
  }
}
END
    
    setfacl -R -m u:nobody:r-x /etc/letsencrypt/live/
    setfacl -R -m u:nobody:r-x /etc/letsencrypt/archive/
    systemctl restart xray
    info "Setup XRAY selesai."
}

setup_firewall() {
    info "Menyiapkan Firewall..."
    ufw allow 22/tcp >/dev/null
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban
    yes | ufw enable >/dev/null
}

setup_management_menu() {
    info "Membuat menu manajemen..."
    mkdir -p /etc/setang/usage
    cat > /etc/setang/users.db << EOF
# Format: email;uuid;quota_gb;ip_limit;exp_date
EOF

    cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash
USER_DB="/etc/setang/users.db"
CONFIG_FILE="/usr/local/etc/xray/config.json"
USAGE_DIR="/etc/setang/usage"
DOMAIN=$(cat /root/domain.txt)
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

add_user() {
    read -p "Masukkan username (email): " email
    read -p "Masukkan Kuota (GB, 0 = unlimited): " quota_gb
    read -p "Masukkan Batas IP (0 = unlimited): " ip_limit
    read -p "Masukkan masa aktif (hari): " days
    if ! [[ "$days" =~ ^[0-9]+$ && "$quota_gb" =~ ^[0-9]+$ && "$ip_limit" =~ ^[0-9]+$ ]]; then echo -e "${RED}Input harus berupa angka.${NC}"; return; fi
    if grep -q "^${email};" "$USER_DB"; then echo "Error: User '$email' sudah ada."; return; fi
    
    uuid=$(xray uuid)
    exp_date=$(date -d "+$days days" +"%Y-%m-%d")
    
    new_client=$(jq -n --arg id "$uuid" --arg email "$email" '{id: $id, email: $email, level: 0}')
    
    jq "(.inbounds[] | select(.tag == \"vless-tls\").settings.clients) += [$new_client]" "$CONFIG_FILE" | \
    jq "(.inbounds[] | select(.tag == \"vless-nontls\").settings.clients) += [$new_client]" > "${CONFIG_FILE}.tmp"
    
    if [[ $? -eq 0 ]]; then
        mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        echo "$email;$uuid;$quota_gb;$ip_limit;$exp_date" >> "$USER_DB"
        systemctl restart xray
        echo -e "${GREEN}User '$email' berhasil ditambahkan.${NC}"
    else
        echo -e "${RED}Gagal menambah user.${NC}"
    fi
}

delete_user() {
    declare -a users
    i=1
    while IFS=';' read -r email _; do
        echo " ${i}. ${email}"
        users+=("$email")
        ((i++))
    done < <(grep -v '^#' "$USER_DB")
    
    if [ ${#users[@]} -eq 0 ]; then echo "Tidak ada user untuk dihapus."; return; fi

    read -p "Pilih nomor user yang akan dihapus (0 untuk batal): " choice
    choice=$(echo "$choice" | tr -dc '0-9')
    
    if [[ "$choice" -gt 0 && "$choice" -le ${#users[@]} ]]; then
        email_to_delete=${users[$((choice-1))]}
        echo "Menghapus user '$email_to_delete'..."
        jq "del(.inbounds[].settings.clients[] | select(.email == \"$email_to_delete\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp"
        mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        sed -i.bak "/^${email_to_delete};/d" "$USER_DB"
        rm -f "${USAGE_DIR}/${email_to_delete}.usage"
        systemctl restart xray
        echo "User berhasil dihapus."
    else
        echo "Pilihan tidak valid atau dibatalkan."
    fi
}

list_users() {
    local fake_host="support.zoom.us"
    echo "--- Daftar Pengguna & Link ---"
    while IFS=';' read -r email uuid quota_gb ip_limit exp_date; do
        [[ "$email" == \#* ]] && continue
        used_bytes=$(cat "$USAGE_DIR/${email}.usage" 2>/dev/null || echo 0); used_gb="0.00"
        if [[ "$used_bytes" -gt 0 ]]; then used_gb=$(echo "scale=2; $used_bytes / 1073741824" | bc); fi
        echo "------------------------------------------------------------"
        echo "Email         : $email"
        echo "Kuota         : $quota_gb GB"
        echo "Terpakai      : $used_gb GB"
        echo "Batas IP      : $ip_limit"
        echo "Kedaluwarsa   : $exp_date"
        echo "Link TLS      : vless://${uuid}@${fake_host}:443?security=tls&encryption=none&headerType=none&type=ws&flow=none&host=${DOMAIN}&path=%2Fvless&sni=${DOMAIN}#${email}_TLS"
        echo "Link non-TLS  : vless://${uuid}@${fake_host}:80?security=none&encryption=none&headerType=none&type=ws&flow=none&host=${DOMAIN}&path=%2Fvless#${email}_nonTLS"
    done < "$USER_DB"
    echo "------------------------------------------------------------"
}

while true; do
    clear
    echo -e "==============================\n    ${YELLOW}MENU MANAJEMEN VLESS${NC}\n=============================="
    echo " 1. Tambah Pengguna"
    echo " 2. Hapus Pengguna"
    echo " 3. Daftar Pengguna & Link"
    echo " 4. Keluar"
    echo "------------------------------"
    read -p "Pilih opsi: " choice
    choice=$(echo "$choice" | tr -dc '0-9')
    
    case $choice in
        1) add_user ;;
        2) delete_user ;;
        3) list_users ;;
        4) exit 0 ;;
        *) echo "Pilihan tidak valid." ;;
    esac
    read -p "Tekan Enter untuk kembali ke menu..."
done
EOF

    chmod +x /usr/local/bin/menu
    info "Menu manajemen dibuat. Ketik 'menu' untuk menjalankan."
}

setup_monitoring_cronjob() {
    info "Membuat script monitoring kuota..."
    cat > /usr/local/bin/vpn-monitor << 'EOF'
#!/bin/bash
USER_DB="/etc/setang/users.db"; USAGE_DIR="/etc/setang/usage"; CONFIG_FILE="/usr/local/etc/xray/config.json"; TODAY=$(date +"%Y-%m-%d")
NEEDS_RESTART=0
while IFS=';' read -r email uuid quota_gb ip_limit exp_date; do
    [[ "$email" == \#* || -z "$email" ]] && continue
    # Cek kedaluwarsa
    if [[ $(date -d "$exp_date" +%s) -lt $(date -d "$TODAY" +%s) ]]; then
        sed -i "/^$email;/d" "$USER_DB"; NEEDS_RESTART=1; continue
    fi
    # Cek kuota
    if [[ "$quota_gb" -gt 0 ]]; then
        uplink=$(xray api stats --server=127.0.0.1:10085 -name "user>>>$email>>>traffic>>>uplink" -reset 2>/dev/null | awk '{print $1}')
        downlink=$(xray api stats --server=127.0.0.1:10085 -name "user>>>$email>>>traffic>>>downlink" -reset 2>/dev/null | awk '{print $1}')
        if [[ -n "$uplink" && -n "$downlink" ]]; then
            usage_file="$USAGE_DIR/${email}.usage"; current_usage=$(cat "$usage_file" 2>/dev/null || echo 0)
            total_new_usage=$((uplink + downlink)); updated_usage=$((current_usage + total_new_usage)); echo "$updated_usage" > "$usage_file"
            quota_bytes=$((quota_gb * 1073741824))
            if [[ "$updated_usage" -gt "$quota_bytes" ]]; then
                sed -i.bak "/^$email;/d" "$USER_DB"; NEEDS_RESTART=1
            fi
        fi
    fi
done < "$USER_DB"
if [ "$NEEDS_RESTART" -eq 1 ]; then
    # Hapus semua user dari config kecuali default
    jq 'del(.inbounds[].settings.clients[]? | select(.email | startswith("default@") | not))' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp1"
    # Tambahkan kembali user yang masih aktif
    while IFS=';' read -r email uuid _ _ _; do
        [[ "$email" == \#* || -z "$email" ]] && continue
        new_client=$(jq -n --arg id "$uuid" --arg email "$email" '{id: $id, email: $email, level: 0}')
        jq "(.inbounds[] | select(.tag == \"vless-tls\").settings.clients) += [$new_client]" "${CONFIG_FILE}.tmp1" | \
        jq "(.inbounds[] | select(.tag == \"vless-nontls\").settings.clients) += [$new_client]" > "${CONFIG_FILE}.tmp2"
        mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp1"
    done < "$USER_DB"
    mv "${CONFIG_FILE}.tmp1" "$CONFIG_FILE"
    systemctl restart xray
fi
EOF

    chmod +x /usr/local/bin/vpn-monitor
    (crontab -l 2>/dev/null | grep -v "vpn-monitor"; echo "*/5 * * * * /usr/local/bin/vpn-monitor") | crontab -
    info "Script monitoring kuota diaktifkan."
}

# --- Main Execution ---
main() {
    clear
    echo "========================================"
    echo "     Setang VLESS-Only Script"
    echo "========================================"
    echo ""
    check_root
    install_dependencies
    ask_domain
    setup_xray
    setup_firewall
    setup_management_menu
    setup_monitoring_cronjob
    
    info "Instalasi selesai!"
    info "Ketik 'menu' untuk mengelola pengguna."
}

main
