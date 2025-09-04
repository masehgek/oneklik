#!/bin/bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Jalankan script ini sebagai root."
    fi
}

read_domain() {
    if [[ -f /root/domain.txt ]]; then
        DOMAIN=$(cat /root/domain.txt)
    else
        read -p "Masukkan domain Anda (contoh: mydomain.com): " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            error "Domain tidak boleh kosong."
        fi
        echo "$DOMAIN" > /root/domain.txt
    fi
}

install_xray() {
    info "Memperbarui paket dan menginstal dependensi..."
    apt update
    apt install -y curl socat xz-utils wget unzip certbot ufw jq

    info "Menginstal XRAY Core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata

    info "Menghentikan layanan XRAY sementara untuk sertifikat SSL..."
    systemctl stop xray 2>/dev/null || true

    info "Membuka port 80 untuk challenge sertifikat SSL..."
    ufw allow 80/tcp

    read_domain

    info "Mendapatkan sertifikat SSL dari Let's Encrypt untuk domain $DOMAIN..."
    certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN"

    info "Menutup port 80 kembali..."
    ufw deny 80/tcp

    UUID_VLESS=$(xray uuid)
    UUID_VMESS=$(xray uuid)
    PASSWORD_TROJAN=$(openssl rand -base64 16)

    info "Membuat konfigurasi XRAY..."

    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID_VLESS",
            "email": "vless@$DOMAIN"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "/vless"
        }
      }
    },
    {
      "port": 443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID_VMESS",
            "alterId": 0,
            "email": "vmess@$DOMAIN"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "/vmess"
        }
      }
    },
    {
      "port": 443,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$PASSWORD_TROJAN",
            "email": "trojan@$DOMAIN"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "/trojan"
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom" }
  ]
}
EOF

    systemctl enable xray
    systemctl restart xray

    ufw allow 443/tcp
    ufw --force enable

    echo -e "\n${GREEN}======================================${NC}"
    echo -e "${GREEN}XRAY WS (VLESS, VMess, Trojan) sudah terpasang!${NC}"
    echo -e "Domain: $DOMAIN"
    echo -e "Port: 443 (WS + TLS)"
    echo ""
    echo -e "VLESS:"
    echo -e "  UUID: $UUID_VLESS"
    echo -e "  Path: /vless"
    echo ""
    echo -e "VMess:"
    echo -e "  UUID: $UUID_VMESS"
    echo -e "  Path: /vmess"
    echo ""
    echo -e "Trojan:"
    echo -e "  Password: $PASSWORD_TROJAN"
    echo -e "  Path: /trojan"
    echo -e "======================================"
}

add_xray_user() {
    read_domain
    echo "Menambah user XRAY baru"
    read -p "Pilih protokol (vless/vmess/trojan): " protocol
    protocol=$(echo "$protocol" | tr '[:upper:]' '[:lower:]')

    if [[ "$protocol" != "vless" && "$protocol" != "vmess" && "$protocol" != "trojan" ]]; then
        echo -e "${RED}Protokol tidak valid.${NC}"
        return
    fi

    read -p "Masukkan username (untuk email tag): " username
    if [[ -z "$username" ]]; then
        echo -e "${RED}Username tidak boleh kosong.${NC}"
        return
    fi

    if [[ "$protocol" == "trojan" ]]; then
        read -p "Masukkan password untuk Trojan (kosongkan untuk generate otomatis): " pass
        if [[ -z "$pass" ]]; then
            pass=$(openssl rand -base64 16)
            echo "Password di-generate: $pass"
        fi
    else
        pass=""
    fi

    config_file="/usr/local/etc/xray/config.json"
    if [[ ! -f "$config_file" ]]; then
        echo -e "${RED}File konfigurasi XRAY tidak ditemukan.${NC}"
        return
    fi

    if [[ "$protocol" != "trojan" ]]; then
        id=$(xray uuid)
    else
        id="$pass"
    fi

    # Tambah user ke config JSON menggunakan jq
    if [[ "$protocol" == "trojan" ]]; then
        jq --arg prot "$protocol" --arg password "$id" --arg email "$username@$DOMAIN" \
           '(.inbounds[] | select(.protocol == $prot) | .settings.clients) += [{"password": $password, "email": $email}]' \
           "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"
    else
        jq --arg prot "$protocol" --arg id "$id" --arg email "$username@$DOMAIN" \
           '(.inbounds[] | select(.protocol == $prot) | .settings.clients) += [{"id": $id, "email": $email}]' \
           "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"
    fi

    systemctl restart xray
    echo -e "${GREEN}User  $username berhasil ditambahkan ke protokol $protocol.${NC}"
}

show_info() {
    read_domain
    echo -e "${GREEN}Informasi XRAY saat ini:${NC}"
    echo "Domain: $DOMAIN"
    echo "Port: 443 (WS + TLS)"
    echo "Konfigurasi file: /usr/local/etc/xray/config.json"
    echo ""
    echo "Daftar user per protokol:"
    jq -r '.inbounds[] | "\$.protocol):" + (.settings.clients[]?.email // "Tidak ada user")' /usr/local/etc/xray/config.json 2>/dev/null || echo "Tidak ada data user."
}

show_bandwidth() {
    echo -e "${GREEN}Menampilkan bandwidth per user...${NC}"
    echo "Fitur ini memerlukan konfigurasi monitoring tambahan (misal XRAY stats API atau tools eksternal)."
    echo "Saat ini belum tersedia data bandwidth per user secara otomatis."
    echo "Anda bisa mengaktifkan XRAY stats API dan mengolah datanya, atau menggunakan tools monitoring lain."
    echo ""
    echo "Contoh sederhana: cek penggunaan bandwidth total server dengan vnstat:"
    echo "  sudo apt install vnstat"
    echo "  vnstat -i eth0"
    echo ""
    echo "Atau gunakan perintah berikut untuk melihat trafik realtime (butuh instalasi nethogs):"
    echo "  sudo apt install nethogs"
    echo "  sudo nethogs"
}

menu() {
    check_root
    while true; do
        echo -e "\n${GREEN}=== Menu XRAY WS ===${NC}"
        echo "1) Install XRAY (jika belum)"
        echo "2) Tambah user XRAY"
        echo "3) Tampilkan info XRAY"
        echo "4) Tampilkan bandwidth per user"
        echo "5) Keluar"
        read -p "Pilih menu [1-5]: " choice
        case $choice in
            1) install_xray ;;
            2) add_xray_user ;;
            3) show_info ;;
            4) show_bandwidth ;;
            5) echo "Keluar."; exit 0 ;;
            *) echo "Pilihan tidak valid." ;;
        esac
    done
}

menu
