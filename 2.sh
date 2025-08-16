#!/bin/bash
set -e

# =================================================================================
# Script Name   : VPN Tunnel Premium Installer
# Description   : Automates the setup of a complete VPN server.
# Author        : Jules for Regar Store
# OS            : Ubuntu 20.04 & 22.04
# =================================================================================

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

check_os() {
    source /etc/os-release
    if [[ "${ID}" != "ubuntu" || ( "${VERSION_ID}" != "20.04" && "${VERSION_ID}" != "22.04" ) ]]; then
        error "This script is designed for Ubuntu 20.04 or 22.04 only."
    fi
    info "Operating system check passed."
}

# --- Feature Installation Functions ---
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
        dropbear stunnel4 squid haveged

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
    echo "      REGAR STORE VPN TUNNEL" >> /etc/ssh/banner
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
accept = 443
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
User =root
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
User =root
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
    info "Setting up OpenVPN server using a robust, industry-standard installer..."

    curl -o /root/openvpn-install.sh https://raw.githubusercontent.com/Nyr/openvpn-install/master/openvpn-install.sh
    chmod +x /root/openvpn-install.sh

    info "Running the OpenVPN installer. If it fails, the error will be shown below."
    warn "This installer will create one OpenVPN instance (UDP on Port 2200)."

    AUTO_INSTALL=y \
    APPROVE_INSTALL=y \
    APPROVE_IP=y \
    PORT_CHOICE=2 \
    PORT=2200 \
    PROTOCOL_CHOICE=1 \
    DNS=1 \
    CLIENT=initial-client \
    PASS=1 \
    /root/openvpn-install.sh

    info "Verifying OpenVPN installation..."
    if [ ! -f /etc/openvpn/server/server.conf ]; then
        error "OpenVPN installation FAILED. The installer script did not create /etc/openvpn/server/server.conf. Please review the output."
    fi
    if ! systemctl is-active --quiet openvpn-server@server.service; then
        error "OpenVPN service 'openvpn-server@server.service' is not running. Please check the logs."
    fi

    info "Adapting management menu for OpenVPN..."
    sed -i '/add_ssh_user/d' /usr/local/bin/menu
    sed -i '/delete_ssh_user/d' /usr/local/bin/menu
    sed -i '/Add SSH\/OpenVPN User/d' /usr/local/bin/menu
    sed -i '/Delete SSH\/OpenVPN User/d' /usr/local/bin/menu
    sed -i '/List XRAY Users/ a \ 4. Manage OpenVPN Users (run installer)' /usr/local/bin/menu
    sed -i '/list_xray_users/ a \        4) /root/openvpn-install.sh; press_enter_to_continue ;;' /usr/local/bin/menu

    info "OpenVPN setup completed successfully."
    info "To add/remove OpenVPN users, run 'menu' and select the OpenVPN option, or run '/root/openvpn-install.sh' directly."
}

setup_xray() {
    info "Setting up XRAY (Vmess/Vless/Trojan)..."
    DOMAIN=$(cat /root/domain.txt)

    info "Installing XRAY core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata >/dev/null 2>&1

    info "Obtaining SSL certificate for $DOMAIN..."
    systemctl stop ssh-ws-http.service
    ufw allow 80/tcp
    if ! certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" --preferred-challenges http; then
        error "Gagal mendapatkan sertifikat SSL dari Let's Encrypt. Pastikan domain Anda sudah di-pointing ke IP VPS ini."
    fi

    ufw deny 80/tcp
    systemctl start ssh-ws-http.service
    info "SSL certificate obtained successfully."

    info "Creating XRAY configuration..."
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
      "port": 8082, "listen": "127.0.0.1", "protocol": "vmess", "tag": "vmess-in",
      "settings": { "clients": [{"id": "${VMESS_UUID}", "alterId": 0, "email": "user@${DOMAIN}"}] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } }
    },
    {
      "port": 8083, "listen": "127.0.0.1", "protocol": "trojan", "tag": "trojan-in",
      "settings": { "clients": [{"password": "${TROJAN_PASSWORD}", "email": "user@${DOMAIN}"}] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } }
    },
    {
      "port": 80, "protocol": "vmess", "tag": "vmess-http-in",
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

    info "Restarting XRAY service..."
    systemctl enable xray >/dev/null 2>&1
    systemctl restart xray

    info "Updating Stunnel to free up port 443 for XRAY..."
    sed -i '/\$openvpn_ssl\$/,+2d' /etc/stunnel/stunnel.conf
    cat >> /etc/stunnel/stunnel.conf << EOF

[openvpn_ssl_alt]
accept = 8443
connect = 127.0.0.1:1194
EOF
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

    info "Creating Badvpn service for ports 7100, 7200, 7300..."
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

    # Allow standard and custom ports
    ufw allow 22/tcp      # SSH
    ufw allow 80/tcp      # XRAY Non-TLS, SSH-WS
    ufw allow 443/tcp     # XRAY TLS
    ufw allow 109/tcp     # Dropbear
    ufw allow 143/tcp     # Dropbear
    ufw allow 445/tcp     # Stunnel for Dropbear
    ufw allow 777/tcp     # Stunnel for SSH
    ufw allow 8443/tcp    # Stunnel for OpenVPN (new port)
    ufw allow 1194/tcp    # OpenVPN TCP
    ufw allow 2200/udp    # OpenVPN UDP
    ufw allow 3128/tcp    # Squid
    ufw allow 8080/tcp    # SSH-WS, Squid

    # Enable UFW non-interactively
    yes | ufw enable

    # --- Configure Fail2Ban ---
    info "Ensuring Fail2Ban is active..."
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban

    # --- Enable TCP BBR ---
    info "Enabling TCP BBR for performance optimization..."
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi

    # Apply changes
    sysctl -p >/dev/null 2>&1

    # Verify BBR is enabled
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        info "TCP BBR enabled successfully."
    else
        warn "TCP BBR could not be enabled."
    fi

    info "Security and performance enhancements completed."
}

setup_management_menu() {
    info "Setting up user management menu..."

    # --- Create User Database File ---
    info "Creating user database directory and file..."
    mkdir -p /etc/regarstore
    cat > /etc/regarstore/users.db << EOF
# This file stores user data for monitoring.
# Format: username;protocol;uuid_or_pass;quota_gb;ip_limit;exp_date
EOF

    # Install jq for potential JSON manipulation
    apt-get install -y jq >/dev/null 2>&1

    cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash
# Advanced User Management Menu for Regar Store VPN

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Paths and Constants ---
USER_DB="/etc/regarstore/users.db"
XRAY_API_ADDR="127.0.0.1:10085"
XRAY_BIN="/usr/local/bin/xray"

# --- Helper Functions ---
function press_enter_to_continue() {
    echo ""
    read -p "Press Enter to continue..."
}

# --- Menu Display ---
show_menu() {
    clear
    echo "========================================"
    echo -e "    ${YELLOW}REGAR STORE - VPN SERVER MENU${NC}"
    echo "========================================"
    echo " 1. Add XRAY User (VLESS/VMess/Trojan)"
    echo " 2. Delete XRAY User"
    echo " 3. List XRAY Users"
    echo " 4. Add SSH/OpenVPN User"
    echo " 5. Delete SSH/OpenVPN User"
    echo " 6. Check Service Status"
    echo " 7. Renew SSL Certificate"
    echo " 8. Reboot Server"
    echo " 9. Exit"
    echo "----------------------------------------"
}

# --- XRAY User Management ---
add_xray_user() {
    echo "--- Add XRAY User ---"
    read -p "Enter username (email format, e.g., user@regar.store): " email
    read -p "Select Protocol [1=VLESS, 2=VMess, 3=Trojan]: " proto_choice
    read -p "Enter Quota (GB, 0 for unlimited): " quota_gb
    read -p "Enter IP Limit (0 for unlimited): " ip_limit
    read -p "Enter expiration days (e.g., 30): " days

    exp_date=$(date -d "+$days days" +"%Y-%m-%d")

    local protocol_name inbound_tag creds_id creds_pass settings

        case $proto_choice in
        1) protocol_name="vless"; inbound_tag="vless-in"; creds_id=$(xray uuid) ;;
        2) protocol_name="vmess"; inbound_tag="vmess-in"; creds_id=$(xray uuid) ;;
        3) protocol_name="trojan"; inbound_tag="trojan-in"; creds_pass=$(openssl rand -base64 12) ;;
        *) echo -e "${RED}Invalid protocol choice.${NC}"; return ;;
    esac

    # Construct settings JSON for API call
    if [[ -n "$creds_pass" ]]; then # Trojan
        settings="{\"clients\": [{\"password\": \"$creds_pass\", \"email\": \"$email\", \"level\": 0}]}"
        creds_for_db=$creds_pass
    else # VLESS/VMess
        settings="{\"clients\": [{\"id\": \"$creds_id\", \"email\": \"$email\", \"level\": 0}]}"
        creds_for_db=$creds_id
    fi

    # Add user to XRAY service via API
    result=$($XRAY_BIN api inbound add --server=$XRAY_API_ADDR --tag=$inbound_tag --protocol=$protocol_name --settings="$settings")

    if [[ $? -eq 0 ]]; then
        echo "$email;$protocol_name;$creds_for_db;$quota_gb;$ip_limit;$exp_date" >> "$USER_DB"
        echo -e "${GREEN}User  '$email' for $protocol_name added successfully.${NC}"
        echo "UUID/Password: $creds_for_db"
    else
        echo -e "${RED}Failed to add user to XRAY service. Error: $result${NC}"
    fi
}

delete_xray_user() {
    read -p "Enter username (email) to delete: " email

    user_line=$(grep "^$email;" "$USER_DB")
    if [[ -z "$user_line" ]]; then
        echo -e "${RED}User  '$email' not found in database.${NC}"
        return
    fi

    protocol_name=$(echo "$user_line" | cut -d';' -f2)
    inbound_tag="${protocol_name}-in"

    # Remove user from XRAY service via API
    result=$($XRAY_BIN api inbound remove --server=$XRAY_API_ADDR --tag="$inbound_tag" --email="$email")

    if [[ $? -eq 0 ]]; then
        sed -i "/^$email;/d" "$USER_DB"
        echo -e "${GREEN}User  '$email' removed from $protocol_name.${NC}"
    else
        echo -e "${RED}Failed to remove user from XRAY service. Error: $result${NC}"
    fi
}

list_xray_users() {
    echo "--- XRAY User List ---"
    printf "%-25s | %-8s | %-10s | %-10s | %-12s\n" "Email" "Protocol" "Quota (GB)" "IP Limit" "Expires"
    echo "-----------------------------------------------------------------------------"
    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        [[ "$email" == \#* ]] && continue
        printf "%-25s | %-8s | %-10s | %-10s | %-12s\n" "$email" "$protocol" "$quota_gb" "$ip_limit" "$exp_date"
    done < "$USER_DB"
    echo "-----------------------------------------------------------------------------"
}

# --- SSH/OpenVPN User Management (Legacy) ---
add_ssh_user() {
    read -p "Enter username: " username
    read -p "Enter password: " password
    read -p "Enter expiration days (e.g., 30): " days

    expiry_date=$(date -d "+$days days" +"%Y-%m-%d")
    useradd -m -s /bin/bash -e "$expiry_date" "$username"
    echo "$username:$password" | chpasswd

    echo -e "${GREEN}SSH User '$username' added. Expires: $expiry_date${NC}"

    # Create OpenVPN client config
    cd /etc/openvpn/easy-rsa
    ./easyrsa build-client-full "$username" nopass >/dev/null 2>&1

    cat /etc/openvpn/client-template.ovpn > "/root/${username}.ovpn"
    echo "<ca>" >> "/root/${username}.ovpn"; cat /etc/openvpn/easy-rsa/pki/ca.crt >> "/root/${username}.ovpn"; echo "</ca>" >> "/root/${username}.ovpn"
    echo "<cert>" >> "/root/${username}.ovpn"; cat /etc/openvpn/easy-rsa/pki/issued/${username}.crt >> "/root/${username}.ovpn"; echo "</cert>" >> "/root/${username}.ovpn"
    echo "<key>" >> "/root/${username}.ovpn"; cat /etc/openvpn/easy-rsa/pki/private/${username}.key >> "/root/${username}.ovpn"; echo "</key>" >> "/root/${username}.ovpn"
    echo -e "${YELLOW}OpenVPN config for '$username' created at /root/${username}.ovpn${NC}"
}

delete_ssh_user() {
    read -p "Enter username to delete: " username
    if id "$username" &>/dev/null; then
        userdel -r "$username"
        cd /etc/openvpn/easy-rsa
        ./easyrsa revoke "$username" >/dev/null 2>&1
        ./easyrsa gen-crl >/dev/null 2>&1
        cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
        echo -e "${GREEN}User  '$username' deleted.${NC}"
    else
        echo -e "${RED}User  '$username' does not exist.${NC}"
    fi
}

# --- System Functions ---
check_services() {
    echo "--- Service Status ---"
    SERVICES=("sshd" "dropbear" "stunnel4" "xray" "squid" "badvpn@7100" "openvpn-server@server_tcp" "openvpn-server@server_udp")
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "$service: ${GREEN}Running${NC}"
        else
            echo -e "$service: ${RED}Stopped${NC}"
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

# --- Finalize Installation ---
finalize_installation() {
    info "Finalizing installation..."

    # --- Add Branding ---
    info "Adding Regar Store branding to login banner..."
    echo "========================================" > /etc/motd
    echo "" >> /etc/motd
    echo "   Welcome to REGAR STORE VPN Server    " >> /etc/motd
    echo "" >> /etc/motd
    echo "   Type 'menu' to manage users/services " >> /etc/motd
    echo "" >> /etc/motd
    echo "========================================" >> /etc/motd

    # --- Setup SSL Auto-Renewal ---
    info "Setting up automatic SSL renewal..."
    (crontab -l 2>/dev/null; echo "0 5 * * * /usr/bin/certbot renew --quiet --pre-hook 'systemctl stop xray' --post-hook 'systemctl start xray'") | crontab -

    # --- Setup User Monitor Cron Job ---
    info "Setting up user monitor cron job (every 5 minutes)..."
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/vpn-monitor >> /var/log/vpn-monitor.log 2>&1") | crontab -

    # --- Display Credentials ---
    clear
    info "Installation complete! Please save the following information:"
    IP_ADDRESS=$(curl -s ifconfig.me)
    DOMAIN=$(cat /root/domain.txt)
    source /root/xray_credentials.txt

    echo -e "\n${YELLOW}--- Server Information ---${NC}"
    echo -e "IP Address: ${GREEN}$IP_ADDRESS${NC}"
    echo -e "Domain:     ${GREEN}$DOMAIN${NC}"

    echo -e "\n${YELLOW}--- SSH / Dropbear / Stunnel --- ${NC}"
    echo -e "Use any username/password created via the 'menu' command."
    echo -e "SSH Port:                 ${GREEN}22${NC}"
    echo -e "Dropbear Ports:           ${GREEN}109, 143${NC}"
    echo -e "Stunnel (SSL->SSH):       ${GREEN}777${NC}"
    echo -e "Stunnel (SSL->Dropbear):  ${GREEN}445${NC}"

    echo -e "\n${YELLOW}--- SSH over WebSocket --- ${NC}"
    echo -e "HTTP Port:                ${GREEN}80, 8080${NC}"

    echo -e "\n${YELLOW}--- OpenVPN --- ${NC}"
    echo -e "TCP Port:                 ${GREEN}1194${NC}"
    echo -e "UDP Port:                 ${GREEN}2200${NC}"
    echo -e "Stunnel (SSL->OpenVPN):   ${GREEN}8443${NC}"
    echo -e "Config files generated via 'menu' are in /root/"

    echo -e "\n${YELLOW}--- XRAY (VLESS/VMess/Trojan) --- ${NC}"
    echo -e "TLS Port:                 ${GREEN}443${NC}"
    echo -e "Non-TLS Port (VMess):     ${GREEN}80${NC}"
    echo -e "--- VLESS over WS (TLS) ---"
    echo -e "UUID:     ${GREEN}$VLESS_UUID${NC}"
    echo -e "Path:     ${GREEN}/vless${NC}"
    echo -e "--- VMess over WS (TLS) ---"
    echo -e "UUID:     ${GREEN}$VMESS_UUID${NC}"
    echo -e "Path:     ${GREEN}/vmess${NC}"
    echo -e "--- Trojan over WS (TLS) ---"
    echo -e "Password: ${GREEN}$TROJAN_PASSWORD${NC}"
    echo -e "Path:     ${GREEN}/trojan${NC}"
    echo -e "--- VMess over WS (HTTP) ---"
    echo -e "UUID:     ${GREEN}$VMESS_UUID${NC}"
    echo -e "Path:     ${GREEN}/vmess-http${NC}"

    echo -e "\n${YELLOW}--- Squid Proxy --- ${NC}"
    echo -e "Ports:                    ${GREEN}3128, 8080${NC}"
}

# --- Main Execution Logic ---
main() {
    check_root
    check_os

    warn "Pastikan domain Anda sudah di-pointing ke IP Address VPS ini."
    ask_domain

    install_dependencies
    setup_management_menu
    setup_ssh_tunneling
    setup_openvpn
    setup_xray
    setup_support_services
    setup_security

    finalize_installation

    info "Instalasi Selesai! Server akan di-reboot."
    # reboot
}

# --- Run the script ---
main
EOF
