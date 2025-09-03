#!/bin/bash
set -e

# --- Warna ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Fungsi Bantuan ---
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Jalankan script ini sebagai root."
    fi
}

install_dependencies() {
    info "Update dan install dependensi..."
    apt-get update -y
    apt-get install -y wget curl socat htop cron build-essential libnss3-dev zlib1g-dev libssl-dev libgmp-dev ufw fail2ban unzip zip python3 python3-pip jq certbot dnsutils git cmake squid
}

ask_domain() {
    read -rp "Masukkan domain Anda (contoh: mydomain.com): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        error "Domain tidak boleh kosong."
    fi
    echo "$DOMAIN" > /root/domain.txt
    info "Domain disimpan: $DOMAIN"
}

install_xray() {
    info "Install Xray core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata >/dev/null 2>&1
}

obtain_cert() {
    DOMAIN=$(cat /root/domain.txt)
    info "Cek IP VPS dan DNS domain..."
    VPS_IP=$(curl -s ifconfig.me)
    DNS_IP=$(dig +short "$DOMAIN" @8.8.8.8)

    if [[ "$VPS_IP" != "$DNS_IP" ]]; then
        error "DNS domain ($DNS_IP) tidak cocok dengan IP VPS ($VPS_IP)."
    fi

    info "Menghentikan Xray sementara..."
    systemctl stop xray || true

    info "Membuka port 80 untuk certbot..."
    ufw allow 80/tcp

    info "Mendapatkan sertifikat SSL untuk $DOMAIN..."
    certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" || error "Gagal mendapatkan sertifikat SSL."

    info "Menutup port 80..."
    ufw deny 80/tcp

    # Set permission agar user nobody bisa akses sertifikat
    chmod 755 /etc/letsencrypt/live
    chmod 755 /etc/letsencrypt/archive
    chmod 640 /etc/letsencrypt/live/${DOMAIN}/*.pem
    chgrp nogroup /etc/letsencrypt/live/${DOMAIN}/*.pem

    systemctl start xray || true
    info "Sertifikat SSL berhasil diperoleh."
}

generate_credentials() {
    VLESS_UUID=$(/usr/local/bin/xray uuid)
    VMESS_UUID=$(/usr/local/bin/xray uuid)
    TROJAN_PASSWORD=$(openssl rand -base64 16)

    echo "VLESS_UUID=${VLESS_UUID}" > /root/xray_credentials.txt
    echo "VMESS_UUID=${VMESS_UUID}" >> /root/xray_credentials.txt
    echo "TROJAN_PASSWORD=${TROJAN_PASSWORD}" >> /root/xray_credentials.txt
}

create_xray_config() {
    DOMAIN=$(cat /root/domain.txt)
    VLESS_UUID=$(grep VLESS_UUID /root/xray_credentials.txt | cut -d= -f2)
    VMESS_UUID=$(grep VMESS_UUID /root/xray_credentials.txt | cut -d= -f2)
    TROJAN_PASSWORD=$(grep TROJAN_PASSWORD /root/xray_credentials.txt | cut -d= -f2)

    info "Membuat konfigurasi Xray..."

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
      "settings": {
        "address": "127.0.0.1",
        "port": 10085,
        "network": "tcp"
      }
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
      "settings": {
        "clients": [ { "id": "${VMESS_UUID}", "alterId": 0, "email": "user@${DOMAIN}" } ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "path": "/vmess" }
      }
    },
    {
      "port": 8083,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "tag": "trojan-in",
      "settings": {
        "clients": [ { "password": "${TROJAN_PASSWORD}", "email": "user@${DOMAIN}" } ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "path": "/trojan" }
      }
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
    info "Konfigurasi Xray selesai dan service dijalankan."
}

setup_badvpn() {
    info "Menginstall dan mengatur Badvpn..."

    cd /root
    if ! command -v git &>/dev/null; then
        apt-get install -y git
    fi
    if ! command -v cmake &>/dev/null; then
        apt-get install -y cmake
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
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    for port in 7100 7200 7300; do
        systemctl enable badvpn@$port
        systemctl start badvpn@$port
    done
    info "Badvpn service berjalan."
}

setup_squid() {
    info "Mengatur Squid Proxy..."
    if [ -f /etc/squid/squid.conf ]; then
        sed -i 's/http_access deny all/http_access allow all/' /etc/squid/squid.conf
        grep -q "http_port 8080" /etc/squid/squid.conf || echo "http_port 8080" >> /etc/squid/squid.conf
        grep -q "http_port 3128" /etc/squid/squid.conf || echo "http_port 3128" >> /etc/squid/squid.conf
        DOMAIN=$(cat /root/domain.txt)
        sed -i "s/# visible_hostname .*/visible_hostname $DOMAIN/" /etc/squid/squid.conf
        systemctl enable squid
        systemctl restart squid
        info "Squid Proxy siap."
    else
        warn "File konfigurasi squid tidak ditemukan, melewati."
    fi
}

setup_firewall_fail2ban_bbr() {
    info "Mengatur firewall, fail2ban, dan BBR..."

    ufw default deny incoming
    ufw default allow outgoing

    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 3128/tcp
    ufw allow 8080/tcp

    yes | ufw enable

    systemctl enable fail2ban
    systemctl restart fail2ban

    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi
    sysctl -p

    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        info "TCP BBR aktif."
    else
        warn "TCP BBR gagal diaktifkan."
    fi
}

setup_user_db() {
    mkdir -p /etc/regarstore
    if [ ! -f /etc/regarstore/users.db ]; then
        echo "# email;protocol;uuid_or_pass;quota_gb;ip_limit;exp_date" > /etc/regarstore/users.db
    fi
}

add_xray_user() {
    echo "--- Tambah User XRAY ---"
    read -rp "Masukkan email (username): " email
    read -rp "Pilih protokol [1=VLESS, 2=VMess, 3=Trojan]: " proto_choice
    read -rp "Quota (GB, 0 unlimited): " quota_gb
    read -rp "Limit IP (0 unlimited): " ip_limit
    read -rp "Masa aktif (hari): " days

    exp_date=$(date -d "+$days days" +"%Y-%m-%d")

    local protocol_name inbound_tag new_client creds_for_db

    case $proto_choice in
        1)
            protocol_name="vless"
            inbound_tag="vless-in"
            creds_for_db=$(/usr/local/bin/xray uuid)
            new_client=$(jq -n --arg id "$creds_for_db" --arg email "$email" '{id: $id, email: $email, level: 0}')
            ;;
        2)
            protocol_name="vmess"
            inbound_tag="vmess-in"
            creds_for_db=$(/usr/local/bin/xray uuid)
            new_client=$(jq -n --arg id "$creds_for_db" --arg email "$email" '{id: $id, email: $email, level: 0}')
            ;;
        3)
            protocol_name="trojan"
            inbound_tag="trojan-in"
            creds_for_db=$(openssl rand -base64 12)
            new_client=$(jq -n --arg pass "$creds_for_db" --arg email "$email" '{password: $pass, email: $email, level: 0}')
            ;;
        *)
            echo -e "${RED}Pilihan protokol tidak valid.${NC}"
            return
            ;;
    esac

    config_file="/usr/local/etc/xray/config.json"
    backup_file="/usr/local/etc/xray/config.json.bak.$(date +%s)"
    temp_config=$(mktemp)

    cp "$config_file" "$backup_file"

    if jq "(.inbounds[] | select(.tag == \"$inbound_tag\").settings.clients) += [$new_client]" "$config_file" > "$temp_config"; then
        if jq empty "$temp_config"; then
            mv "$temp_config" "$config_file"
            echo "$email;$protocol_name;$creds_for_db;$quota_gb;$ip_limit;$exp_date" >> /etc/regarstore/users.db
            echo -e "${GREEN}User  $email berhasil ditambahkan. Restart Xray...${NC}"
            if systemctl restart xray; then
                echo "UUID/Password: $creds_for_db"
            else
                echo -e "${RED}Gagal restart Xray, mengembalikan konfigurasi lama...${NC}"
                mv "$backup_file" "$config_file"
                systemctl restart xray
            fi
        else
            echo -e "${RED}Konfigurasi baru tidak valid. Batal menambah user.${NC}"
            rm "$temp_config"
        fi
    else
        echo -e "${RED}Gagal memodifikasi konfigurasi Xray.${NC}"
        rm "$temp_config"
    fi
}

show_xray_share_links() {
    DOMAIN=$(cat /root/domain.txt)
    echo "--- Link Share XRAY ---"
    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        [[ "$email" == \#* || -z "$email" ]] && continue

        echo -e "\n${YELLOW}:User              ${email}${NC}"
        case $protocol in
            vless)
                path_encoded="%252fvless"
                host="${DOMAIN}"
                sni="${DOMAIN}"
                link="vless://${creds}@${DOMAIN}:443/?security=tls&encryption=none&headerType=none&type=ws&flow=none&host=${host}&path=${path_encoded}&fp=random&sni=${sni}#${email}"
                echo -e "${GREEN}$link${NC}"
                ;;
            vmess)
                json="{\"v\":\"2\",\"ps\":\"${email}\",\"add\":\"${DOMAIN}\",\"port\":\"443\",\"id\":\"${creds}\",\"aid\":0,\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DOMAIN}\",\"path\":\"/vmess\",\"tls\":\"tls\"}"
                link="vmess://$(echo -n $json | base64 -w 0)"
                echo -e "${GREEN}$link${NC}"
                ;;
            trojan)
                path_encoded="%252ftrojan"
                host="${DOMAIN}"
                sni="${DOMAIN}"
                link="trojan://${creds}@${DOMAIN}:443/?type=ws&security=tls&host=${host}&path=${path_encoded}&sni=${sni}#${email}"
                echo -e "${GREEN}$link${NC}"
                ;;
            *)
                echo -e "${YELLOW}Protokol $protocol tidak didukung untuk link share.${NC}"
                ;;
        esac
    done < /etc/regarstore/users.db
    echo "----------------------------"
}

menu() {
    while true; do
        clear
        echo "=============================="
        echo -e "${YELLOW}Menu Manajemen XRAY${NC}"
        echo "1) Tambah User XRAY"
        echo "2) Tampilkan Link Share User"
        echo "3) Keluar"
        echo "=============================="
        read -rp "Pilih menu: " choice
        case $choice in
            1) add_xray_user; read -rp "Tekan Enter untuk kembali ke menu...";;
            2) show_xray_share_links; read -rp "Tekan Enter untuk kembali ke menu...";;
            3) exit 0;;
            *) echo "Pilihan tidak valid.";;
        esac
    done
}

main() {
    check_root
    install_dependencies
    ask_domain
    install_xray
    obtain_cert
    generate_credentials
    create_xray_config
    setup_badvpn
    setup_squid
    setup_firewall_fail2ban_bbr
    setup_user_db
    info "Instalasi selesai. Jalankan menu dengan perintah: menu"
}

main
