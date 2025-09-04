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
    chmod 600 /root/domain.txt
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
    chown root:root /etc/letsencrypt/live/${DOMAIN}/*.pem

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
    chmod 600 /root/xray_credentials.txt
}

create_xray_config() {
    DOMAIN=$(cat /root/domain.txt)
    VLESS_UUID=$(grep VLESS_UUID /root/xray_credentials.txt | cut -d= -f2)
    VMESS_UUID=$(grep VMESS_UUID /root/xray_credentials.txt | cut -d= -f2)
    TROJAN_PASSWORD=$(grep TROJAN_PASSWORD /root/xray_credentials.txt | cut -d= -f2)

    info "Membuat konfigurasi Xray..."

    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "error": "/var/log/xray/error.log",
    "access": "/var/log/xray/access.log"
  },
  "api": {
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ],
    "tag": "api"
  },
  "stats": {},
  "policy": {
    "levels": {
      "0": {
        "handshake": 2,
        "connIdle": 128,
        "statsUser   Uplink": true,
        "statsUser   Downlink": true
      }
    }
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10000,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0",
            "email": "default1"
          },
          {
            "id": "ea1aade2-090d-4847-9ce1-f674063179a3",
            "email": "default2"
          },
          {
            "id": "486faa2d-f393-4f86-840b-736f3bd308e9",
            "email": "default3"
          },
          {
            "id": "16b635df-2768-4693-94f7-29143d471914",
            "email": "default4"
          },
          {
            "id": "97329ab5-5448-4a61-b002-072ac92fa7fc",
            "email": "default5"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless"
        }
      },
      "tag": "vless-in"
    },
    {
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess"
        }
      },
      "tag": "vmess-in"
    },
    {
      "listen": "127.0.0.1",
      "port": 10003,
      "protocol": "trojan",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
          }
        ],
        "udp": true
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/trojan-ws"
        }
      },
      "tag": "trojan-in"
    },
    {
      "listen": "127.0.0.1",
      "port": 10004,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "aes-128-gcm",
            "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/ss-ws"
        }
      },
      "tag": "ss-in"
    },
    {
      "listen": "127.0.0.1",
      "port": 10005,
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0",
            "email": "default1"
          },
          {
            "id": "ea1aade2-090d-4847-9ce1-f674063179a3",
            "email": "default2"
          },
          {
            "id": "486faa2d-f393-4f86-840b-736f3bd308e9",
            "email": "default3"
          },
          {
            "id": "16b635df-2768-4693-94f7-29143d471914",
            "email": "default4"
          },
          {
            "id": "97329ab5-5448-4a61-b002-072ac92fa7fc",
            "email": "default5"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vless-grpc"
        }
      },
      "tag": "vless-grpc-in"
    },
    {
      "listen": "127.0.0.1",
      "port": 10006,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vmess-grpc"
        }
      },
      "tag": "vmess-grpc-in"
    },
    {
      "listen": "127.0.0.1",
      "port": 10007,
      "protocol": "trojan",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "trojan-grpc"
        }
      },
      "tag": "trojan-grpc-in"
    },
    {
      "listen": "127.0.0.1",
      "port": 10008,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "aes-128-gcm",
            "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "ss-grpc"
        }
      },
      "tag": "ss-grpc-in"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "inboundTag": ["dnsIn"],
        "outboundTag": "dnsOut",
        "type": "field"
      },
      {
        "inboundTag": ["dnsQuery"],
        "outboundTag": "direct",
        "type": "field"
      },
      {
        "outboundTag": "direct",
        "protocol": ["bittorrent"],
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "block",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ]
      },
      {
        "inboundTag": ["api"],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": ["bittorrent"]
      },
      {
        "type": "field",
        "outboundTag": "proxy",
        "ip": [
          "8.8.8.8/32",
          "8.8.4.4/32",
          "geoip:us",
          "geoip:ca",
          "geoip:cloudflare",
          "geoip:cloudfront",
          "geoip:facebook",
          "geoip:fastly",
          "geoip:google",
          "geoip:googlecn",
          "geoip:youtube",
          "geoip:tw",
          "geoip:jp"
        ]
      },
      {
        "type": "field",
        "outboundTag": "block",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": [
          "223.5.5.5/32",
          "119.29.29.29/32",
          "180.76.76.76/32",
          "114.114.114.114/32",
          "geoip:cn",
          "geoip:jp",
          "geoip:in",
          "geoip:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "reject",
        "domain": ["geosite:category-ads-all"]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "network": "tcp,udp"
      }
    ]
  },
  "stats": {},
  "api": {
    "services": ["StatsService"],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUser   Downlink": true,
        "statsUser   Uplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "dns": {
    "hosts": {
      "dns.google": "8.8.8.8",
      "dns.pub": "119.29.29.29",
      "dns.alidns.com": "223.5.5.5",
      "geosite:category-ads-all": "127.0.0.1"
    },
    "servers": [
      {
        "address": "https://dns.google/dns-query",
        "domains": ["geosite:geolocation-!cn"],
        "expectIPs": ["geoip:!cn"]
      },
      "8.8.8.8",
      {
        "address": "114.114.114.114",
        "port": 53,
        "domains": ["geosite:cn", "geosite:category-games@cn"],
        "expectIPs": ["geoip:cn"],
        "skipFallback": true
      },
      {
        "address": "localhost",
        "skipFallback": true
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
    systemctl restart fail2ban

    # Aktifkan BBR
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
        chmod 600 /etc/regarstore/users.db
    fi
}

add_xray_user() {
    echo "--- Tambah User XRAY ---"
    read -rp "Masukkan email (username): " email
    if [[ -z "$email" ]]; then
        echo -e "${RED}Email tidak boleh kosong.${NC}"
        return
    fi

    read -rp "Pilih protokol [1=VLESS, 2=VMess, 3=Trojan]: " proto_choice
    if ! [[ "$proto_choice" =~ ^[123]$ ]]; then
        echo -e "${RED}Pilihan protokol tidak valid.${NC}"
        return
    fi

    read -rp "Quota (GB, 0 unlimited): " quota_gb
    if ! [[ "$quota_gb" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Quota harus angka.${NC}"
        return
    fi

    read -rp "Limit IP (0 unlimited): " ip_limit
    if ! [[ "$ip_limit" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Limit IP harus angka.${NC}"
        return
    fi

    read -rp "Masa aktif (hari): " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Masa aktif harus angka.${NC}"
        return
    fi

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
    esac

    config_file="/usr/local/etc/xray/config.json"
    backup_file="/usr/local/etc/xray/config.json.bak.$(date +%s)"
    temp_config=$(mktemp)

    cp "$config_file" "$backup_file"

    if jq "(.inbounds[] | select(.tag == \"$inbound_tag\").settings.clients) += [$new_client]" "$config_file" > "$temp_config"; then
        if jq empty "$temp_config"; then
            mv "$temp_config" "$config_file"
            echo "$email;$protocol_name;$creds_for_db;$quota_gb;$ip_limit;$exp_date" >> /etc/regarstore/users.db
            echo -e "${GREEN}User     $email berhasil ditambahkan. Restart Xray...${NC}"
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

        echo -e "\n${YELLOW}:User                  ${email}${NC}"
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

show_bandwidth_usage() {
    echo "Mengambil data bandwidth dari Xray..."

    API_SOCK="/var/run/xray.sock"

    if [ ! -S "$API_SOCK" ]; then
        echo -e "${RED}Socket API Xray tidak ditemukan di $API_SOCK${NC}"
        return
    fi

    read -r -d '' REQ << EOF
{
  "command": "stats",
  "arguments": {
    "name": "user>>>"
  },
  "tag": "api"
}
EOF

    RESPONSE=$(echo "$REQ" | socat - UNIX-CONNECT:"$API_SOCK")

    if [ -z "$RESPONSE" ]; then
        echo -e "${RED}Gagal mengambil data dari Xray API${NC}"
        return
    fi

    echo "Bandwidth usage per user (bytes):"
    echo "$RESPONSE" | jq -r '.stats[] | select(.name | test("user>>>")) | "\$.name) : Uplink=\$.value.uplink) Downlink=\$.value.downlink)"'
}

menu() {
    while true; do
        clear
        echo "=============================="
        echo -e "${YELLOW}Menu Manajemen XRAY${NC}"
        echo "1) Tambah User XRAY"
        echo "2) Tampilkan Link Share User"
        echo "3) Tampilkan Bandwidth Penggunaan User"
        echo "4) Keluar"
        echo "=============================="
        read -rp "Pilih menu: " choice
        case $choice in
            1) add_xray_user; read -rp "Tekan Enter untuk kembali ke menu...";;
            2) show_xray_share_links; read -rp "Tekan Enter untuk kembali ke menu...";;
            3) show_bandwidth_usage; read -rp "Tekan Enter untuk kembali ke menu...";;
            4) exit 0;;
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
    setup_squid
    setup_firewall_fail2ban_bbr
    setup_user_db
    info "Instalasi selesai."
    menu
}

main
    ufw allow 3128/tcp
    ufw allow 8080/tcp

    echo "y" | ufw enable

    systemctl enable fail2ban
    
