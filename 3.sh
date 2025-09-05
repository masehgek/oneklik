#!/bin/bash
set -e

# =================================================================================
# Script Name   : VPN Tunnel Premium Installer (OpenVPN, SSH, Stunnel Removed)
# Description   : Setup VPN server with XRAY, squid, badvpn, firewall, menu.
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
    apt-get update >/dev/null 2>&1

    info "Installing base dependencies..."
    apt-get install -y \
        wget curl socat htop cron \
        build-essential libnss3-dev \
        zlib1g-dev libssl-dev libgmp-dev \
        ufw fail2ban \
        unzip zip \
        python3 python3-pip \
        squid haveged certbot acl jq dnsutils

    info "Installing Python WebSocket proxy..."
    pip3 install proxy.py >/dev/null 2>&1
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

    info "Performing DNS pre-flight check for $DOMAIN..."
    local_ip=$(curl -s ifconfig.me)
    resolved_ip=$(dig +short "$DOMAIN" @8.8.8.8)

    if [[ "$local_ip" != "$resolved_ip" ]]; then
        error "DNS validation failed. Domain '$DOMAIN' points to '$resolved_ip', VPS IP is '$local_ip'."
    fi
    info "DNS check passed."

    info "Obtaining SSL certificate for $DOMAIN..."
    ufw allow 80/tcp
    systemctl stop xray >/dev/null 2>&1
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
        "statsUser Uplink": true,
        "statsUser Downlink": true
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
    if ! command -v git &> /dev/null; then
        info "Installing git..."
        apt-get install -y git >/dev/null 2>&1
    fi
    if ! command -v cmake &> /dev/null; then
        info "Installing cmake..."
        apt-get install -y cmake >/dev/null 2>&1
    fi
    cd /root
    git clone https://github.com/ambrop72/badvpn.git >/dev/null 2>&1
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
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable badvpn@7100 >/dev/null 2>&1
    systemctl start badvpn@7100
    systemctl enable badvpn@7200 >/dev/null 2>&1
    systemctl start badvpn@7200
    systemctl enable badvpn@7300 >/dev/null 2>&1
    systemctl start badvpn@7300

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
    # ... (sama seperti skrip asli, tapi hapus opsi terkait SSH dan OpenVPN) ...
    # Anda bisa menggunakan menu yang sudah ada dan hapus opsi 5 (OpenVPN) dan 6 (SSH)
    # Pastikan menu hanya mengelola XRAY dan layanan terkait
}

finalize_installation() {
    # ... (sama seperti skrip asli) ...
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
    finalize_installation
    info "Instalasi Selesai! Server akan di-reboot."
    # reboot
}

main
