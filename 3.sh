#!/bin/bash

CONFIG_DIR="/etc/xray"
USER_DB="$CONFIG_DIR/users.json"
XRAY_CONFIG="$CONFIG_DIR/config.json"
CONFIG_FILE="$CONFIG_DIR/config.conf"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
BOT_SCRIPT="$CONFIG_DIR/bot.py"
MAIN_SCRIPT_PATH=$(readlink -f "$0")

function info() {
    echo "[*] $1"
}

function error() {
    echo "ERROR: $1"
    exit 1
}

function pause() {
  read -p "Tekan Enter untuk melanjutkan..."
}

function load_config() {
  if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
  fi
}

function save_config() {
  cat > "$CONFIG_FILE" <<EOF
DOMAIN="$DOMAIN"
EMAIL="$EMAIL"
EOF
}

function is_installed() {
  if command -v xray >/dev/null 2>&1; then
    echo "Xray: Terinstall"
  else
    echo "Xray: Belum terinstall"
  fi

  if command -v nginx >/dev/null 2>&1; then
    echo "Nginx: Terinstall"
  else
    echo "Nginx: Belum terinstall"
  fi
}

function is_running() {
  if systemctl is-active --quiet xray; then
    echo "Xray service: Berjalan"
  else
    echo "Xray service: Tidak berjalan"
  fi

  if systemctl is-active --quiet nginx; then
    echo "Nginx service: Berjalan"
  else
    echo "Nginx service: Tidak berjalan"
  fi
}

function install_dependencies() {
  info "Update dan install dependencies..."
  apt update && apt upgrade -y
  apt install -y curl wget unzip jq nginx iptables-persistent socat certbot python3-certbot-nginx python3-pip
}

function install_xray() {
  info "Mengunduh dan memasang Xray core..."
  bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
  mkdir -p "$CONFIG_DIR"
  if [ ! -f "$USER_DB" ]; then
    echo '{"users":[]}' > "$USER_DB"
  fi
}

function check_dns() {
  info "Mengecek DNS domain $DOMAIN..."
  local_ip=$(curl -s https://ipinfo.io/ip)
  resolved_ip=$(dig +short "$DOMAIN" @8.8.8.8)

  if [[ "$local_ip" != "$resolved_ip" ]]; then
      error "DNS validation failed. Domain '$DOMAIN' points to '$resolved_ip', but this VPS IP is '$local_ip'. Please check your DNS records."
  fi
  info "DNS domain sudah benar mengarah ke IP server."
}

function setup_certbot_standalone() {
  info "Menghentikan layanan yang menggunakan port 80..."
  systemctl stop nginx 2>/dev/null

  info "Membuka port 80 untuk validasi certbot..."
  ufw allow 80/tcp 2>/dev/null

  info "Memperoleh sertifikat SSL menggunakan Certbot --standalone..."
  if ! certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --preferred-challenges http; then
      error "Gagal mendapatkan sertifikat SSL dari Let's Encrypt. Pastikan domain Anda sudah di-pointing ke IP VPS ini."
  fi

  info "Menutup kembali port 80..."
  ufw deny 80/tcp 2>/dev/null

  info "Sertifikat SSL berhasil diperoleh."
}

function remove_default_nginx_conf() {
  if [ -f "/etc/nginx/sites-enabled/default" ]; then
    info "Menonaktifkan konfigurasi default nginx untuk menghindari konflik..."
    rm -f /etc/nginx/sites-enabled/default
    systemctl reload nginx
  fi
}

function setup_nginx() {
  info "Mengkonfigurasi Nginx sebagai reverse proxy..."
  remove_default_nginx_conf
  local conf_path="$NGINX_SITES_AVAILABLE/$DOMAIN"
  
  # Cari direktori sertifikat terbaru
  CERT_PATH="/etc/letsencrypt/live/$DOMAIN"
  if [ ! -d "$CERT_PATH" ]; then
    CERT_PATH=$(find /etc/letsencrypt/live/ -maxdepth 1 -type d -name "$DOMAIN-*" | sort -V | tail -n 1)
    if [ -z "$CERT_PATH" ]; then
      error "Tidak dapat menemukan direktori sertifikat Certbot."
    fi
  fi

  cat > "$conf_path" <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    location / {
        return 301 https://\$host\$request_uri;
    }
}
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate $CERT_PATH/fullchain.pem;
    ssl_certificate_key $CERT_PATH/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # Konfigurasi untuk WebSocket
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location /vless-ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location /vmess-ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location /trojan-ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    # Konfigurasi untuk gRPC
    location /vless-grpc {
        grpc_pass grpc://127.0.0.1:8080;
    }
    location /vmess-grpc {
        grpc_pass grpc://127.0.0.1:8080;
    }
    location /trojan-grpc {
        grpc_pass grpc://127.0.0.1:8080;
    }
}
EOF
  ln -sf "$conf_path" "$NGINX_SITES_ENABLED/$DOMAIN"
  nginx -t
  if [ $? -ne 0 ]; then
    error "Error konfigurasi nginx, silakan cek manual."
  fi
  systemctl start nginx
  systemctl reload nginx
  info "Nginx reverse proxy sudah dikonfigurasi dan direload."
}

function set_xray_config_path() {
  info "Mengubah jalur konfigurasi Xray ke /etc/xray/config.json..."
  XRAY_SERVICE_FILE="/etc/systemd/system/xray.service"
  
  if [ ! -f "$XRAY_SERVICE_FILE" ]; then
    error "File layanan Xray tidak ditemukan: $XRAY_SERVICE_FILE"
  fi
  
  # Hapus file drop-in yang mengganggu
  if [ -f "/etc/systemd/system/xray.service.d/10-donot_touch_single_conf.conf" ]; then
    info "Menghapus file drop-in yang mengganggu jalur konfigurasi..."
    rm /etc/systemd/system/xray.service.d/10-donot_touch_single_conf.conf
  fi

  # Menggunakan sed untuk mengubah jalur konfigurasi
  sed -i 's|ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json|ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json|g' "$XRAY_SERVICE_FILE"

  systemctl daemon-reload
  info "Jalur konfigurasi Xray berhasil diubah."
}

function generate_xray_config() {
  info "Membuat konfigurasi Xray multi-protokol (WS & gRPC)..."
  local users_json
  users_json=$(cat "$USER_DB")
  local vless_clients vmess_clients trojan_clients
  
  vless_clients=$(echo "$users_json" | jq '[.users[] | {id: .id, email: .username}]')
  vmess_clients=$(echo "$users_json" | jq '[.users[] | {id: .id, alterId: 0, email: .username}]')
  trojan_clients=$(echo "$users_json" | jq '[.users[] | {password: .id, email: .username}]')

  cat > "$XRAY_CONFIG" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 8080,
      "protocol": "vless",
      "settings": {
        "clients": $vless_clients,
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless-ws"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8080,
      "protocol": "vmess",
      "settings": {
        "clients": $vmess_clients
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess-ws"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8080,
      "protocol": "trojan",
      "settings": {
        "clients": $trojan_clients
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/trojan-ws"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8080,
      "protocol": "vless",
      "settings": {
        "clients": $vless_clients,
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vless-grpc"
        },
        "tlsSettings": {
          "allowInsecure": false,
          "serverName": "$DOMAIN"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8080,
      "protocol": "vmess",
      "settings": {
        "clients": $vmess_clients
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vmess-grpc"
        },
        "tlsSettings": {
          "allowInsecure": false,
          "serverName": "$DOMAIN"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8080,
      "protocol": "trojan",
      "settings": {
        "clients": $trojan_clients
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "trojan-grpc"
        },
        "tlsSettings": {
          "allowInsecure": false,
          "serverName": "$DOMAIN"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
}

function restart_xray() {
  info "Restart Xray service..."
  systemctl restart xray
}

function add_user_cmd() {
  local username=$1
  local quota=$2
  local days=$3
  local ip_limit=0

  if jq -e --arg u "$username" '.users[] | select(.username == $u)' "$USER_DB" > /dev/null 2>&1; then
    echo "Username '$username' sudah ada!"
    return
  fi

  if [ ! -s "$USER_DB" ]; then
    echo '{"users":[]}' > "$USER_DB"
  fi

  uuid=$(cat /proc/sys/kernel/random/uuid)
  expire_date=$(date -d "+$days days" +"%Y-%m-%d")

  jq --arg u "$username" --arg id "$uuid" --arg q "$quota" --arg ip "$ip_limit" --arg e "$expire_date" \
    '.users += [{"username":$u,"id":$id,"quota":($q|tonumber),"ip_limit":($ip|tonumber),"expire":$e,"used":0}]' "$USER_DB" > tmp.$$.json && mv tmp.$$.json "$USER_DB"

  echo "User $username berhasil ditambahkan dengan UUID $uuid, expired $expire_date"

  generate_xray_config
  restart_xray
}

function remove_user_cmd() {
  local username=$1

  if ! jq -e --arg u "$username" '.users[] | select(.username == $u)' "$USER_DB" > /dev/null 2>&1; then
    echo "User '$username' tidak ditemukan."
    return
  fi

  tmpfile=$(mktemp)
  jq --arg u "$username" 'del(.users[] | select(.username == $u))' "$USER_DB" > "$tmpfile" && mv "$tmpfile" "$USER_DB"

  echo "User '$username' berhasil dihapus."
  
  generate_xray_config
  restart_xray
}

function list_users_cmd() {
  info "Daftar Pengguna:"
  jq '.users[]' "$USER_DB"
}

function remove_expired_users() {
  info "Menghapus user yang sudah expired..."
  today=$(date +"%Y-%m-%d")
  tmpfile=$(mktemp)
  jq --arg today "$today" '.users |= map(select(.expire >= $today))' "$USER_DB" > "$tmpfile" && mv "$tmpfile" "$USER_DB"
}

function create_maintenance_script() {
  cat > "$CONFIG_DIR/maintenance.sh" <<'EOF'
#!/bin/bash
CONFIG_DIR="/etc/xray"
USER_DB="$CONFIG_DIR/users.json"

function remove_expired_users() {
  today=$(date +"%Y-%m-%d")
  tmpfile=$(mktemp)
  jq --arg today "$today" '.users |= map(select(.expire >= $today))' "$USER_DB" > "$tmpfile" && mv "$tmpfile" "$USER_DB"
}

remove_expired_users
systemctl restart xray
EOF
  chmod +x "$CONFIG_DIR/maintenance.sh"
}

function setup_cronjob() {
  create_maintenance_script
  croncmd="/bin/bash $CONFIG_DIR/maintenance.sh"
  cronjob="0 0 * * * $croncmd"

  (crontab -l 2>/dev/null | grep -v -F "$croncmd" ; echo "$cronjob") | crontab -
  info "Cronjob hapus user expired sudah dibuat (jalan tiap jam 00:00)."
}

function generate_sharelink() {
  local username=$1
  if [ -z "$username" ]; then
    echo "Masukkan username sebagai argumen."
    return 1
  fi
  
  user=$(jq -r --arg u "$username" '.users[] | select(.username == $u)' "$USER_DB")
  if [ -z "$user" ]; then
    echo "User tidak ditemukan!"
    return 1
  fi

  id=$(echo "$user" | jq -r '.id')
  domain="$DOMAIN"
  expire=$(echo "$user" | jq -r '.expire')
  
  echo "====================================================="
  echo "        Tautan Berbagi untuk Pengguna: $username     "
  echo "           Masa Aktif hingga: $expire                "
  echo "====================================================="
  echo ""
  
  echo "######### VLESS (WS & gRPC) #########"
  echo "######### WebSocket (WS) #########"
  vless_ws_link="vless://${id}@${domain}:443?type=ws&security=tls&host=${domain}&path=%2Fvless-ws&sni=${domain}#${username}-WS"
  echo "$vless_ws_link"
  echo "######### gRPC #########"
  vless_grpc_link="vless://${id}@${domain}:443/?security=tls&encryption=none&headerType=gun&type=grpc&flow=none&serviceName=vless-grpc&sni=${domain}#${username}-gRPC"
  echo "$vless_grpc_link"
  echo ""
  
  echo "######### VMess (WS & gRPC) #########"
  echo "######### WebSocket (WS) #########"
  vmess_ws_json=$(jq -n --arg id "$id" --arg domain "$domain" --arg username "$username" '{
    v: "2",
    ps: ($username + "-WS"),
    add: $domain,
    port: "443",
    id: $id,
    aid: "0",
    net: "ws",
    type: "none",
    host: $domain,
    path: "/vmess-ws",
    tls: "tls"
  }')
  vmess_ws_link="vmess://$(echo -n "$vmess_ws_json" | base64 -w0)"
  echo "$vmess_ws_link"
  echo "######### gRPC #########"
  vmess_grpc_json=$(jq -n --arg id "$id" --arg domain "$domain" --arg username "$username" '{
    v: "2",
    ps: ($username + "-gRPC"),
    add: $domain,
    port: "443",
    id: $id,
    aid: "0",
    net: "grpc",
    type: "gun",
    host: "",
    path: "vmess-grpc",
    tls: "tls",
    sni: $domain
  }')
  vmess_grpc_link="vmess://$(echo -n "$vmess_grpc_json" | base64 -w0)"
  echo "$vmess_grpc_link"
  echo ""
  
  echo "######### Trojan (WS & gRPC) #########"
  echo "######### WebSocket (WS) #########"
  trojan_ws_link="trojan://${id}@${domain}:443?security=tls&type=ws&host=${domain}&path=%2Ftrojan-ws&sni=${domain}#${username}-WS"
  echo "$trojan_ws_link"
  echo "######### gRPC #########"
  trojan_grpc_link="trojan://${id}@${domain}:443?security=tls&type=grpc&serviceName=trojan-grpc&serverName=${domain}&headerType=gun&flow=none&sni=${domain}#${username}-gRPC"
  echo "$trojan_grpc_link"
  echo ""
}

function setup_telegram_bot() {
    read -p "Masukkan Token Bot Telegram: " BOT_TOKEN
    read -p "Masukkan Chat ID Telegram Anda: " CHAT_ID

    if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then
        info "Token atau Chat ID kosong. Bot Telegram tidak akan diinstal."
        return
    fi

    info "Menginstal library Python untuk bot Telegram..."
    pip3 install python-telegram-bot --upgrade

    info "Membuat file bot.py..."
    cat > "$BOT_SCRIPT" <<EOF
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
import subprocess
import os

TOKEN = "$BOT_TOKEN"
ADMIN_CHAT_ID = int("$CHAT_ID")
SCRIPT_PATH = "$MAIN_SCRIPT_PATH"

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if update.effective_chat.id != ADMIN_CHAT_ID:
        await update.message.reply_text("Maaf, Anda tidak diizinkan menggunakan bot ini.")
        return
    await update.message.reply_markdown_v2(
        f"Halo {user.mention_markdown_v2()}\!\n"
        "Saya adalah bot manajemen VPS\. Berikut adalah perintah yang tersedia:\n"
        "\`/tambah [username] [kuota_MB] [masa_aktif_hari]\`\n"
        "\`/hapus [username]\`\n"
        "\`/list\`\n"
        "\`/sharelink [username]\`"
    )

async def add_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.id != ADMIN_CHAT_ID:
        await update.message.reply_text("Maaf, Anda tidak diizinkan menggunakan bot ini.")
        return
    
    args = context.args
    if len(args) != 3:
        await update.message.reply_text("Format salah. Gunakan: /tambah [username] [kuota_MB] [masa_aktif_hari]")
        return

    username, quota, days = args
    await update.message.reply_text(f"Menambah pengguna {username}...")
    
    try:
        result = subprocess.run(
            ['/bin/bash', SCRIPT_PATH, 'add_user', username, quota, days],
            capture_output=True,
            text=True,
            check=True
        )
        await update.message.reply_text(result.stdout)
    except subprocess.CalledProcessError as e:
        await update.message.reply_text(f"Error: {e.stderr}")

async def remove_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.id != ADMIN_CHAT_ID:
        await update.message.reply_text("Maaf, Anda tidak diizinkan menggunakan bot ini.")
        return
    
    args = context.args
    if len(args) != 1:
        await update.message.reply_text("Format salah. Gunakan: /hapus [username]")
        return
    
    username = args[0]
    await update.message.reply_text(f"Menghapus pengguna {username}...")
    
    try:
        result = subprocess.run(
            ['/bin/bash', SCRIPT_PATH, 'remove_user', username],
            capture_output=True,
            text=True,
            check=True
        )
        await update.message.reply_text(result.stdout)
    except subprocess.CalledProcessError as e:
        await update.message.reply_text(f"Error: {e.stderr}")

async def list_users(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.id != ADMIN_CHAT_ID:
        await update.message.reply_text("Maaf, Anda tidak diizinkan menggunakan bot ini.")
        return

    await update.message.reply_text("Mendapatkan daftar pengguna...")
    
    try:
        result = subprocess.run(
            ['/bin/bash', SCRIPT_PATH, 'list_users'],
            capture_output=True,
            text=True,
            check=True
        )
        await update.message.reply_text(result.stdout)
    except subprocess.CalledProcessError as e:
        await update.message.reply_text(f"Error: {e.stderr}")

async def generate_sharelink(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.id != ADMIN_CHAT_ID:
        await update.message.reply_text("Maaf, Anda tidak diizinkan menggunakan bot ini.")
        return

    args = context.args
    if len(args) != 1:
        await update.message.reply_text("Format salah. Gunakan: /sharelink [username]")
        return
    
    username = args[0]
    await update.message.reply_text(f"Membuat tautan untuk {username}...")
    
    try:
        result = subprocess.run(
            ['/bin/bash', SCRIPT_PATH, 'sharelink', username],
            capture_output=True,
            text=True,
            check=True
        )
        await update.message.reply_text(result.stdout)
    except subprocess.CalledProcessError as e:
        await update.message.reply_text(f"Error: {e.stderr}")

def main() -> None:
    application = Application.builder().token(TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("tambah", add_user))
    application.add_handler(CommandHandler("hapus", remove_user))
    application.add_handler(CommandHandler("list", list_users))
    application.add_handler(CommandHandler("sharelink", generate_sharelink))

    application.run_polling()

if __name__ == "__main__":
    main()
EOF

    info "Bot Telegram telah dikonfigurasi. Untuk menjalankannya, gunakan perintah ini:"
    echo ""
    echo "  screen -S vpn_bot"
    echo "  python3 $BOT_SCRIPT"
    echo ""
    echo "Tekan CTRL+A+D untuk keluar dari screen dan membiarkan bot berjalan di latar belakang."
}

function uninstall_all() {
  echo "PERINGATAN: Tindakan ini akan menghapus semua paket yang diinstal oleh skrip ini!"
  read -p "Apakah Anda yakin ingin melanjutkan? (y/N): " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Uninstalasi dibatalkan."
    return
  fi

  info "Menghentikan dan menonaktifkan layanan..."
  systemctl stop xray nginx 2>/dev/null
  systemctl disable xray nginx 2>/dev/null
  
  # Hentikan proses bot Telegram jika sedang berjalan
  info "Menghentikan proses bot Telegram jika sedang berjalan..."
  pkill -f "$BOT_SCRIPT" 2>/dev/null
  
  # Hapus file skrip bot dan library
  if [ -f "$BOT_SCRIPT" ]; then
    info "Menghapus file bot Telegram..."
    rm -f "$BOT_SCRIPT"
  fi
  if pip3 show python-telegram-bot >/dev/null 2>&1; then
    info "Menghapus library python-telegram-bot..."
    pip3 uninstall -y python-telegram-bot
  fi


  info "Menghapus cronjob..."
  crontab -l | grep -v "$CONFIG_DIR/maintenance.sh" | crontab -

  info "Menghapus paket..."
  apt-get purge -y xray nginx certbot python3-certbot-nginx python3-pip
  apt-get autoremove -y

  info "Menghapus file konfigurasi dan direktori..."
  rm -rf "$CONFIG_DIR"
  rm -rf /etc/letsencrypt/live/$DOMAIN*
  rm -rf /etc/letsencrypt/archive/$DOMAIN*
  rm -f "$NGINX_SITES_AVAILABLE/$DOMAIN"
  rm -f "$NGINX_SITES_ENABLED/$DOMAIN"
  rm -f "$CONFIG_FILE"
  rm -f "$USER_DB"
  rm -f "$BOT_SCRIPT"
  rm -f /usr/local/etc/xray/config.json
  rm -f /etc/systemd/system/xray.service.d/10-donot_touch_single_conf.conf

  echo "Semua paket dan file konfigurasi telah dihapus."
  echo "Sistem Anda sekarang bersih dari instalasi skrip ini."
}

function install_all() {
    echo "=== Memulai Instalasi Xray dan Nginx ==="
    read -p "Masukkan domain Anda (contoh: example.com): " DOMAIN
    read -p "Masukkan email untuk sertifikat TLS (Let's Encrypt): " EMAIL

    if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
        error "Domain dan Email tidak boleh kosong. Instalasi dibatalkan."
    fi

    mkdir -p "$CONFIG_DIR"
    save_config
    
    install_dependencies
    install_xray
    check_dns
    setup_certbot_standalone
    setup_nginx
    generate_xray_config
    
    set_xray_config_path
    
    restart_xray
    
    echo "Instalasi Xray dan Nginx selesai."
    echo ""
    read -p "Apakah Anda ingin mengatur bot Telegram? (y/N): " setup_bot_choice
    if [[ "$setup_bot_choice" == "y" || "$setup_bot_choice" == "Y" ]]; then
        setup_telegram_bot
    fi
    pause
}

function menu() {
  load_config
  clear
  echo "=== Menu Manajemen Xray VPS ==="
  is_installed
  is_running
  echo "-----------------------------"
  echo "1) Install Xray dan Nginx"
  echo "2) Tambah User"
  echo "3) List User"
  echo "4) Hapus User"
  echo "5) Setup Cronjob Hapus User Expired"
  echo "6) Generate Share Link User (Format URL)"
  echo "7) Uninstall Semua Paket"
  echo "8) Keluar"
  read -p "Pilih menu [1-8]: " choice

  case $choice in
    1) install_all ;;
    2) read -p "Masukkan username: " username; read -p "Masukkan kuota (MB): " quota; read -p "Masukkan masa aktif (hari): " days; add_user_cmd "$username" "$quota" "$days"; pause ;;
    3) list_users_cmd; pause ;;
    4) read -p "Masukkan username yang ingin dihapus: " username; remove_user_cmd "$username"; pause ;;
    5) setup_cronjob; pause ;;
    6) read -p "Masukkan username: " username; generate_sharelink "$username"; pause ;;
    7) uninstall_all; pause ;;
    8) exit 0 ;;
    *) echo "Pilihan tidak valid"; pause ;;
  esac
}

# Periksa argumen baris perintah
if [[ "$1" == "add_user" ]]; then
    add_user_cmd "$2" "$3" "$4"
elif [[ "$1" == "remove_user" ]]; then
    remove_user_cmd "$2"
elif [[ "$1" == "list_users" ]]; then
    list_users_cmd
elif [[ "$1" == "sharelink" ]]; then
    generate_sharelink "$2"
else
    menu
fi
