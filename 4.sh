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

# --- Pre-flight Checks ---
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run as root. Please use 'sudo -i' or 'sudo su'."
    fi
}

# --- Installation Functions ---
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
        dropbear stunnel4 squid haveged certbot acl git cmake dnsutils jq >/dev/null 2>&1

    # Install websocket proxy
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

    # Store domain for later use by other scripts
    echo "$DOMAIN" > /root/domain.txt
}

setup_ssh_tunneling() {
    info "Setting up SSH, Dropbear, and Stunnel..."

    info "Stopping existing SSH services to prevent conflicts..."
    systemctl stop sshd || true
    systemctl stop dropbear || true

    # --- Configure OpenSSH ---
    info "Configuring OpenSSH..."
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    echo "===================================" > /etc/ssh/banner
    echo "       REGAR STORE VPN TUNNEL" >> /etc/ssh/banner
    echo "===================================" >> /etc/ssh/banner
    sed -i -e 's/^[ \t]*Banner/#&/g' /etc/ssh/sshd_config
    echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config

    # --- Configure Dropbear ---
    info "Configuring Dropbear on ports 109 & 143..."
    cat > /etc/default/dropbear << EOF
NO_START=0
DROPBEAR_PORT=109
DROPBEAR_EXTRA_ARGS="-p 143"
DROPBEAR_BANNER="/etc/ssh/banner"
DROPBEAR_RECEIVE_WINDOW=65536
EOF
    systemctl enable dropbear >/dev/null 2>&1

    # --- Configure Stunnel ---
    # We create a self-signed cert first. It will be replaced with the real Certbot cert later.
    info "Configuring Stunnel for SSL Tunneling..."
    openssl req -new -x509 -days 3650 -nodes \
        -out /etc/stunnel/stunnel.pem \
        -keyout /etc/stunnel/stunnel.pem \
        -subj "/C=ID/ST=Jawa/L=Jakarta/O=RegarStore/OU=VPN/CN=localhost" >/dev/null 2>&1
    cat > /etc/stunnel/stunnel.conf << EOF
pid = /var/run/stunnel4/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
retry = yes
[dropbear_ssl]
accept = 445
connect = 127.0.0.1:109
[ssh_ssl]
accept = 777
connect = 127.0.0.1:22
[openvpn_ssl]
accept = 8443
connect = 127.0.0.1:1194
EOF
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
    systemctl enable stunnel4 >/dev/null 2>&1

    # --- Configure SSH over WebSocket ---
    info "Configuring SSH over WebSocket on ports 80 & 8080..."
    cat > /etc/systemd/system/ssh-ws-http.service << EOF
[Unit]
Description=SSH Over WebSocket HTTP
After=network.target nss-lookup.target
[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/proxy --hostname 0.0.0.0 --port 80 --log-level info --plugins "proxy.plugin.SshProxyPlugin"
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/ssh-ws-alt.service << EOF
[Unit]
Description=SSH Over WebSocket ALT
After=network.target nss-lookup.target
[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/proxy --hostname 0.0.0.0 --port 8080 --log-level info --plugins "proxy.plugin.SshProxyPlugin"
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ssh-ws-http.service >/dev/null 2>&1
    systemctl enable ssh-ws-alt.service >/dev/null 2>&1

    # --- Start all services in the correct order ---
    info "Starting SSH and Tunneling services..."
    systemctl start sshd
    if ! systemctl is-active --quiet sshd; then
        error "sshd service failed to start. Check /etc/ssh/sshd_config for errors."
    fi
    systemctl start dropbear
    systemctl start stunnel4
    systemctl start ssh-ws-http.service
    systemctl start ssh-ws-alt.service

    info "SSH & Tunneling components configured successfully."
}

setup_openvpn() {
    info "Setting up OpenVPN server using an interactive, standard installer..."
    if [ ! -f /root/openvpn-install.sh ]; then
        info "Downloading standard OpenVPN installer..."
        curl -o /root/openvpn-install.sh https://raw.githubusercontent.com/Nyr/openvpn-install/master/openvpn-install.sh
        chmod +x /root/openvpn-install.sh
    fi
    info "The standard OpenVPN installer will now run. Please answer the questions it asks. It is recommended to use UDP on port 2200 for the first run."
    /root/openvpn-install.sh
    echo ""
    read -p "Did the OpenVPN installation above complete WITHOUT any fatal errors? [y/n]: " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error "OpenVPN setup aborted by user. Please re-run the main script when ready."
    fi
    info "Verifying OpenVPN installation..."
    if [ ! -f /etc/openvpn/server/server.conf ]; then
        error "OpenVPN installation verification FAILED. The file /etc/openvpn/server/server.conf was not found. The installation likely failed."
    fi
    if ! systemctl is-active --quiet openvpn-server@server.service; then
        error "OpenVPN service 'openvpn-server@server.service' is not running. Please check the logs."
    fi
    info "OpenVPN setup completed successfully."
    info "To add/remove more OpenVPN users, run '/root/openvpn-install.sh' again."
}

setup_xray() {
    info "Setting up XRAY (Vmess/Vless/Trojan)..."
    DOMAIN=$(cat /root/domain.txt)

    # --- Install XRAY Core ---
    info "Installing XRAY core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata >/dev/null 2>&1

    # --- FIX: Download required geodata files from a reliable source ---
    info "FIX: Downloading geodata files (geoip.dat and geosite.dat)..."
    wget -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
    info "Geodata files downloaded."

    # --- DNS Pre-flight Check ---
    info "Performing DNS pre-flight check for $DOMAIN..."
    local_ip=$(curl -s ifconfig.me)
    resolved_ip=$(dig +short "$DOMAIN" @8.8.8.8)

    if [[ "$local_ip" != "$resolved_ip" ]]; then
        error "DNS validation failed. Domain '$DOMAIN' points to '$resolved_ip', but this VPS IP is '$local_ip'. Please wait for DNS propagation or check your DNS records."
    fi
    info "DNS check passed. Domain points to this VPS."

    # --- Obtain SSL Certificate using Certbot ---
    info "Obtaining SSL certificate for $DOMAIN..."
    systemctl stop ssh-ws-http.service
    ufw allow 80/tcp

    if ! certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" --preferred-challenges http; then
        error "Gagal mendapatkan sertifikat SSL dari Let's Encrypt. Pastikan domain Anda sudah di-pointing ke IP VPS ini."
    fi

    ufw deny 80/tcp
    systemctl start ssh-ws-http.service
    info "SSL certificate obtained successfully."

    # --- Create XRAY Config ---
    info "Creating XRAY configuration..."
    VLESS_UUID=$(xray uuid)
    VMESS_UUID=$(xray uuid)
    TROJAN_PASSWORD=$(openssl rand -base64 16)

    echo "VLESS_UUID=${VLESS_UUID}" > /root/xray_credentials.txt
    echo "VMESS_UUID=${VMESS_UUID}" >> /root/xray_credentials.txt
    echo "TROJAN_PASSWORD=${TROJAN_PASSWORD}" >> /root/xray_credentials.txt

    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "error": "/var/log/xray/error.log",
    "access": "/var/log/xray/access.log"
  },
  "api": {
    "tag": "api",
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ]
  },
  "stats": {},
  "policy": {
    "levels": {
      "0": {
        "handshake": 2,
        "connIdle": 128,
        "statsUserUplink": true,
        "statsUserDownlink": true
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
      "port": 10000,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      }
    },
    {
      "port": 443,
      "protocol": "vless",
      "tag": "vless-in",
      "settings": {
        "decryption": "none",
        "fallbacks": [
          {
            "path": "/vmess",
            "dest": 10002,
            "xver": 1
          },
          {
            "path": "/trojan-ws",
            "dest": 10003,
            "xver": 1
          },
          {
            "path": "/ss-ws",
            "dest": 10004,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "alpn": [
            "http/1.1"
          ],
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
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "vmess",
      "tag": "vmess-in",
      "settings": {
        "clients": [
          {
            "id": "$VMESS_UUID",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/vmess"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": 10003,
      "protocol": "trojan",
      "tag": "trojan-in",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "password": "$TROJAN_PASSWORD"
          }
        ],
        "udp": true
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/trojan-ws"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": 10004,
      "protocol": "shadowsocks",
      "tag": "ss-in",
      "settings": {
        "clients": [
          {
            "method": "aes-128-gcm",
            "password": "$TROJAN_PASSWORD"
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/ss-ws"
        }
      }
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
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      },
      {
        "type": "field",
        "outboundTag": "reject",
        "domain": [
          "geosite:category-ads-all"
        ]
      },
      {
        "type": "field",
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      }
    ]
  }
}
EOF

    # --- Final Permissions Fix ---
    info "Applying final permissions fix for XRAY..."
    chmod 644 /usr/local/etc/xray/config.json
    setfacl -R -m u:nobody:r-x /etc/letsencrypt/live/
    setfacl -R -m u:nobody:r-x /etc/letsencrypt/archive/

    systemctl daemon-reload
    info "Restarting XRAY service..."
    systemctl enable xray >/dev/null 2>&1
    systemctl restart xray

    if ! systemctl is-active --quiet xray; then
        error "XRAY service failed to start. Please check 'journalctl -u xray'."
    fi

    info "FIX: Updating Stunnel to use the new Let's Encrypt cert."
    sed -i "s|cert = /etc/stunnel/stunnel.pem|cert = /etc/letsencrypt/live/${DOMAIN}/fullchain.pem\nkey = /etc/letsencrypt/live/${DOMAIN}/privkey.pem|" /etc/stunnel/stunnel.conf
    systemctl restart stunnel4

    info "XRAY setup completed."
}

setup_support_services() {
    info "Setting up Squid Proxy and Badvpn..."
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

    info "Compiling and installing Badvpn UDP Gateway..."
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

    info "Creating Badvpn service for ports 7100, 7200, 7300..."
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
    info "Configuring UFW to open all necessary ports..."
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 109/tcp
    ufw allow 143/tcp
    ufw allow 445/tcp
    ufw allow 777/tcp
    ufw allow 8443/tcp
    ufw allow 1194/tcp
    ufw allow 2200/udp
    ufw allow 3128/tcp
    ufw allow 8080/tcp
    ufw allow 7100/tcp
    ufw allow 7200/tcp
    ufw allow 7300/tcp
    yes | ufw enable >/dev/null 2>&1
    info "Ensuring Fail2Ban is active..."
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban
    info "Enabling TCP BBR for performance optimization..."
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
    mkdir -p /etc/regarstore/usage
    cat > /etc/regarstore/users.db << EOF
# This file stores user data for monitoring.
# Format: username;protocol;uuid_or_pass;quota_gb;ip_limit;exp_date
EOF

    cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash
# Advanced User Management Menu for Regar Store VPN

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Paths and Constants ---
USER_DB="/etc/regarstore/users.db"
XRAY_API_ADDR="127.0.0.1:10000"
XRAY_BIN="/usr/local/bin/xray"
OPENVPN_INSTALLER="/root/openvpn-install.sh"
USAGE_DIR="/etc/regarstore/usage"

# --- Helper Functions ---
function press_enter_to_continue() {
    echo ""
    read -p "Press Enter to continue..."
}

# --- Menu Display ---
show_menu() {
    clear
    echo "========================================"
    echo -e "     ${YELLOW}REGAR STORE - VPN SERVER MENU${NC}"
    echo "========================================"
    echo " 1. Add XRAY User (VLESS/VMess/Trojan)"
    echo " 2. Delete XRAY User"
    echo " 3. List XRAY Users (Basic)"
    echo " 4. List XRAY Users (with Usage)"
    echo " 5. Show XRAY Share Links"
    echo " 6. Manage OpenVPN Users (run installer)"
    echo " 7. Manage SSH Users"
    echo " 8. Check Service Status"
    echo " 9. Renew SSL Certificate"
    echo " 10. Reboot Server"
    echo " 11. Exit"
    echo "----------------------------------------"
}

# --- XRAY User Management (jq method) ---
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
        echo -e "${GREEN}User '$email' for $protocol_name added. Restarting XRAY...${NC}"
        systemctl restart xray
        chmod 644 /usr/local/etc/xray/config.json
        echo "UUID/Password: $creds_for_db"
    else
        echo -e "${RED}Failed to modify xray config file.${NC}"
    fi
}

delete_xray_user() {
    read -p "Enter username (email) to delete: " email
    user_line=$(grep "^$email;" "$USER_DB")
    if [[ -z "$user_line" ]]; then
        echo -e "${RED}User '$email' not found in database.${NC}"; return
    fi

    protocol_name=$(echo "$user_line" | cut -d';' -f2)
    inbound_tag="${protocol_name}-in"
    config_file="/usr/local/etc/xray/config.json"
    temp_config=$(mktemp)

    jq "del(.inbounds[] | select(.tag == \"$inbound_tag\").settings.clients[] | select(.email == \"$email\"))" "$config_file" > "$temp_config" && mv "$temp_config" "$config_file"

    if [[ $? -eq 0 ]]; then
        sed -i "/^$email;/d" "$USER_DB"
        echo -e "${GREEN}User '$email' removed. Restarting XRAY...${NC}"
        systemctl restart xray
        chmod 644 /usr/local/etc/xray/config.json
    else
        echo -e "${RED}Failed to modify xray config file.${NC}"
    fi
}

# --- Existing function, now for basic list ---
list_xray_users() {
    echo "--- XRAY User List (Basic) ---"
    printf "%-25s | %-8s | %-10s | %-10s | %-12s\n" "Email" "Protocol" "Quota(GB)" "IP Limit" "Expires"
    echo "-----------------------------------------------------------------------------"
    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        [[ "$email" == \#* ]] && continue
        printf "%-25s | %-8s | %-10s | %-10s | %-12s\n" "$email" "$protocol" "$quota_gb" "$ip_limit" "$exp_date"
    done < "$USER_DB"
    echo "-----------------------------------------------------------------------------"
}

# --- NEW Function with Usage Check ---
list_xray_users_with_usage() {
    echo "--- XRAY User List (with Quota Usage) ---"
    printf "%-25s | %-8s | %-10s | %-10s | %-10s | %-12s\n" "Email" "Protocol" "Quota(GB)" "Used(GB)" "IP Limit" "Expires"
    echo "---------------------------------------------------------------------------------------"
    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        [[ "$email" == \#* ]] && continue

        local used_bytes=$(cat "$USAGE_DIR/${email}.usage" 2>/dev/null || echo 0)
        local used_gb="0.00"
        
        if [[ "$used_bytes" -gt 0 ]]; then
            used_gb=$(echo "scale=2; $used_bytes / 1024 / 1024 / 1024" | bc)
        fi

        printf "%-25s | %-8s | %-10s | %-10s | %-10s | %-12s\n" "$email" "$protocol" "$quota_gb" "$used_gb" "$ip_limit" "$exp_date"
    done < "$USER_DB"
    echo "---------------------------------------------------------------------------------------"
    echo -e "${YELLOW}Note: Quota usage diperbarui setiap 5 menit oleh vpn-monitor.${NC}"
}

show_xray_share_links() {
    DOMAIN=$(cat /root/domain.txt)
    echo "--- XRAY Shareable Links ---"
    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        if [[ "$email" == \#* || -z "$email" ]]; then continue; fi

        echo -e "\n${YELLOW}User: ${email}${NC}"
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
                link="trojan://${creds}@${DOMAIN}:443?type=ws&path=%2Ftrojan-ws&security=tls#${email}"
                echo -e "${GREEN}$link${NC}"
                ;;
        esac
    done < "$USER_DB"
    echo "----------------------------"
}

# --- Other User Management ---
manage_ssh_users() {
    echo "Simple SSH User Management"
    read -p "Action [1=Add, 2=Delete]: " action
    case $action in
        1) read -p "Enter username: " username
           read -p "Enter password: " password
           read -p "Enter expiration days (e.g., 30): " days
           expiry_date=$(date -d "+$days days" +"%Y-%m-%d")
           useradd -m -s /bin/bash -e "$expiry_date" "$username"
           echo "$username:$password" | chpasswd
           echo -e "${GREEN}SSH User '$username' added. Expires: $expiry_date${NC}"
           ;;
        2) read -p "Enter username to delete: " username
           if id "$username" &>/dev/null; then
               userdel -r "$username"
               echo -e "${GREEN}User '$username' deleted.${NC}"
           else
               echo -e "${RED}User '$username' does not exist.${NC}"
           fi
           ;;
        *) echo "Invalid action." ;;
    esac
}

# --- System Functions ---
check_services() {
    echo "--- Service Status ---"
    SERVICES=("sshd" "dropbear" "stunnel4" "xray" "squid" "badvpn@7100" "openvpn-server@server")
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "$service: ${GREEN}Running\033[0m"
        else
            echo -e "$service: ${RED}Stopped\033[0m"
        fi
    done
    echo "----------------------"
}

renew_ssl() {
    echo "Stopping services on port 80/443 for renewal..."
    systemctl stop ssh-ws-http.service; systemctl stop xray
    echo "Renewing SSL Certificate..."
    certbot renew --quiet
    echo "Restarting services..."
    systemctl start xray; systemctl start ssh-ws-http.service
    echo "Done."
}

# --- Main Loop ---
while true; do
    show_menu
    read -p "Enter your choice [1-11]: " choice
    case $choice in
        1) add_xray_user; press_enter_to_continue ;;
        2) delete_xray_user; press_enter_to_continue ;;
        3) list_xray_users; press_enter_to_continue ;;
        4) list_xray_users_with_usage; press_enter_to_continue ;;
        5) show_xray_share_links; press_enter_to_continue ;;
        6) $OPENVPN_INSTALLER; press_enter_to_continue ;;
        7) manage_ssh_users; press_enter_to_continue ;;
        8) check_services; press_enter_to_continue ;;
        9) renew_ssl; press_enter_to_continue ;;
        10) reboot ;;
        11) exit 0 ;;
        *) echo -e "${RED}Invalid option. Please try again.${NC}"; sleep 1 ;;
    esac
done
EOF

    chmod +x /usr/local/bin/menu
    info "Management menu created. Type 'menu' to use it."

    # --- Create the VPN Monitor Script (FIXED VERSION) ---
    info "Creating vpn-monitor script..."
    cat > /usr/local/bin/vpn-monitor << 'EOF'
#!/bin/bash
# VPN User Monitor for Quota, Expiration, and IP Limit

USER_DB="/etc/regarstore/users.db"
XRAY_API_ADDR="127.0.0.1:10000"
XRAY_BIN="/usr/local/bin/xray"
LOG_FILE="/var/log/vpn-monitor.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

remove_user_and_sync() {
    local email="$1"
    local protocol="$2"
    local reason="$3"

    log "Removing user $email (protocol: $protocol) due to $reason."
    
    # 1. Remove user from local database
    sed -i "/^$email;/d" "$USER_DB"
    
    # 2. Clean up user's usage file (if it exists)
    rm -f "/etc/regarstore/usage/${email}.usage"

    log "User $email has been removed from database."
}

check_users() {
    if [ ! -f "$USER_DB" ]; then
        log "User database not found. Skipping check."
        exit 1
    fi

    local current_date_s=$(date +%s)
    local users_to_remove=()
    local user_removed=0

    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        if [[ "$email" == \#* || -z "$email" ]]; then
            continue
        fi

        local should_remove=0
        local reason=""

        # --- Check Expiration ---
        local exp_date_s=$(date -d "$exp_date" +%s)
        if [[ "$current_date_s" -gt "$exp_date_s" ]]; then
            should_remove=1
            reason="expiration"
        fi

        # --- Check Quota ---
        if [[ "$quota_gb" -gt 0 && "$should_remove" -eq 0 ]]; then
            stats_json=$($XRAY_BIN api stats --server=$XRAY_API_ADDR --query "user>>>$email>>>traffic" --reset)
            
            if [[ -n "$stats_json" ]]; then
                uplink=$(echo "$stats_json" | jq -r 'if has("uplink") then .uplink else 0 end')
                downlink=$(echo "$stats_json" | jq -r 'if has("downlink") then .downlink else 0 end')

                local usage_file="/etc/regarstore/usage/${email}.usage"
                mkdir -p /etc/regarstore/usage

                local total_usage_bytes=$(( $(cat "$usage_file" 2>/dev/null || echo 0) + uplink + downlink ))
                echo "$total_usage_bytes" > "$usage_file"

                local quota_bytes=$(( quota_gb * 1024 * 1024 * 1024 ))

                if [[ "$total_usage_bytes" -gt "$quota_bytes" ]]; then
                    should_remove=1
                    reason="quota exceeded"
                fi
            fi
        fi

        # --- Check IP Limit ---
        if [[ "$ip_limit" -gt 0 && "$should_remove" -eq 0 ]]; then
            local current_ips=$($XRAY_BIN api stats --server=$XRAY_API_ADDR --query "user>>>$email>>>inbound>>>${protocol}-in>>>active_connections" 2>/dev/null | cut -d: -f2 | awk '{print $1}')
            
            if [[ -n "$current_ips" ]]; then
                if [[ "$current_ips" -gt "$ip_limit" ]]; then
                    should_remove=1
                    reason="IP limit exceeded"
                fi
            fi
        fi

        if [[ "$should_remove" -eq 1 ]]; then
            users_to_remove+=("$email;$protocol;$reason")
            user_removed=1
        fi

    done < "$USER_DB"

    if [[ "$user_removed" -eq 1 ]]; then
        log "Processing removal of $((${#users_to_remove[@]})) users."
        for user_data in "${users_to_remove[@]}"; do
            IFS=';' read -r email protocol reason <<< "$user_data"
            remove_user_and_sync "$email" "$protocol" "$reason"
        done
        
        config_file="/usr/local/etc/xray/config.json"
        temp_config=$(mktemp)
        local config_json
        if [ -f "$config_file" ]; then
             config_json=$(cat "$config_file")
        fi

        while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
            if [[ "$email" == \#* || -z "$email" ]]; then
                continue
            fi
            
            local inbound_tag="${protocol}-in"
            if echo "$config_json" | grep -q "$email"; then
                 config_json=$(echo "$config_json" | jq "del(.inbounds[] | select(.tag == \"$inbound_tag\").settings.clients[] | select(.email == \"$email\"))")
            fi
        done < <(grep "" "$USER_DB") # Use process substitution to avoid issues with sed/grep
        
        echo "$config_json" > "$config_file"
        
        systemctl restart xray
        log "Xray service restarted to apply all changes and terminate connections."
    fi
}

log "VPN monitor script started."
check_users
log "VPN monitor script finished."
EOF

    chmod +x /usr/local/bin/vpn-monitor
    info "VPN monitor script created at /usr/local/bin/vpn-monitor"
}

setup_cron() {
    info "FIX: Setting up cronjob to run vpn-monitor every 5 minutes."
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/vpn-monitor >/dev/null 2>&1") | crontab -
    info "Cronjob for vpn-monitor added successfully."
}

finalize_installation() {
    info "Finalizing installation..."
    info "Setting up dynamic MOTD..."
    cat > /usr/local/bin/motd_generator << 'EOF'
#!/bin/bash
# MOTD Generator for Regar Store VPN

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Fetch Data ---
os_info=$(lsb_release -ds)
ram_info=$(free -h | awk '/^Mem:/ {print $2}')
cpu_info=$(lscpu | awk -F: '/^Model name/ {print $2}' | sed 's/^[ \t]*//')
ip_info=$(curl -s ipinfo.io)
city=$(echo "$ip_info" | jq -r .city)
isp=$(echo "$ip_info" | jq -r .org)
ip_vps=$(echo "$ip_info" | jq -r .ip)
domain=$(cat /root/domain.txt)
current_time=$(date +"%Y-%m-%d %H:%M:%S")
version="1.1 (Advanced)"

# --- Display Banner ---
echo -e "====================================================================="
echo -e "     ${GREEN}SELAMAT DATANG DI VPS ANDA!${NC}"
echo -e "====================================================================="
echo -e "${CYAN}Informasi Sistem:${NC}"
echo -e "OS               : ${os_info}"
echo -e "CPU              : ${cpu_info}"
echo -e "RAM              : ${ram_info}"
echo -e "Domain           : ${domain}"
echo -e "IP VPS           : ${ip_vps}"
echo -e "Lokasi           : ${city}, ${isp}"
echo -e "Waktu Server     : ${current_time}"
echo -e "Skrip Versi      : ${version}"
echo "---------------------------------------------------------------------"
echo "Untuk mengelola server, ketik 'menu' lalu Enter."
echo "Untuk melihat status layanan, ketik 'menu' dan pilih Opsi 8."
echo "---------------------------------------------------------------------"
EOF

    chmod +x /usr/local/bin/motd_generator
    echo -e '\n/usr/local/bin/motd_generator' >> /etc/bash.bashrc
    info "Installation script finished successfully."
    info "Anda sekarang bisa mengetik 'menu' untuk mengelola server Anda."
}

# --- Main Script Execution Flow ---
main() {
    check_root
    
    # --- Installation Steps ---
    install_dependencies
    ask_domain
    setup_ssh_tunneling
    setup_openvpn
    setup_xray
    setup_support_services
    setup_security
    setup_management_menu
    setup_cron
    
    # Finalize and show summary
    finalize_installation
}

# Run the main function
main
