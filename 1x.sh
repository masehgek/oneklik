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

# --- Feature Installation Functions (to be implemented) ---
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
        dropbear stunnel4 squid haveged certbot acl

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
    info "Setting up OpenVPN server using an interactive, standard installer..."

    # Download the well-tested openvpn-install.sh script if it doesn't exist.
    if [ ! -f /root/openvpn-install.sh ]; then
        info "Downloading standard OpenVPN installer..."
        curl -o /root/openvpn-install.sh https://raw.githubusercontent.com/Nyr/openvpn-install/master/openvpn-install.sh
        chmod +x /root/openvpn-install.sh
    fi

    # --- Run the installer INTERACTIVELY ---
    info "The standard OpenVPN installer will now run."
    warn "Please answer the questions it asks. If you see any errors, please note them."
    warn "It is recommended to use UDP on port 2200 for the first run."

    # Run the script interactively, allowing the user to see everything.
    /root/openvpn-install.sh

    # --- Ask for user confirmation ---
    echo ""
    read -p "Did the OpenVPN installation above complete WITHOUT any fatal errors? [y/n]: " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error "OpenVPN setup aborted by user. Please re-run the main script when ready."
    fi

    # --- Verification ---
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

    # --- DNS Pre-flight Check ---
    info "Performing DNS pre-flight check for $DOMAIN..."
    if ! command -v dig &> /dev/null; then
        apt-get install -y dnsutils >/dev/null 2>&1
    fi

    local_ip=$(curl -s ifconfig.me)
    resolved_ip=$(dig +short "$DOMAIN" @8.8.8.8)

    if [[ "$local_ip" != "$resolved_ip" ]]; then
        error "DNS validation failed. Domain '$DOMAIN' points to '$resolved_ip', but this VPS IP is '$local_ip'. Please wait for DNS propagation or check your DNS records."
    fi
    info "DNS check passed. Domain points to this VPS."

    # --- Obtain SSL Certificate using Certbot ---
    info "Obtaining SSL certificate for $DOMAIN..."
    # Stop services on port 80 to allow certbot to bind
    systemctl stop ssh-ws-http.service
    # Temporarily allow port 80 through firewall for challenge
    ufw allow 80/tcp

    if ! certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" --preferred-challenges http; then
        error "Gagal mendapatkan sertifikat SSL dari Let's Encrypt. Pastikan domain Anda sudah di-pointing ke IP VPS ini."
    fi

    # Close port 80 again and restart service
    ufw deny 80/tcp
    systemctl start ssh-ws-http.service
    info "SSL certificate obtained successfully."

    # --- Create XRAY Config ---
    info "Creating XRAY configuration..."
    # Generate necessary UUIDs and password
    VLESS_UUID=$(xray uuid)
    VMESS_UUID=$(xray uuid)
    TROJAN_PASSWORD=$(openssl rand -base64 16)

    # Save credentials for later display
    echo "VLESS_UUID=${VLESS_UUID}" > /root/xray_credentials.txt
    echo "VMESS_UUID=${VMESS_UUID}" >> /root/xray_credentials.txt
    echo "TROJAN_PASSWORD=${TROJAN_PASSWORD}" >> /root/xray_credentials.txt

    # Create the config file with API and Stats enabled
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
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess-http" } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
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

    # --- Final Permissions Fix ---
    info "Applying final permissions fix for XRAY..."
    chmod 644 /usr/local/etc/xray/config.json
    setfacl -R -m u:nobody:r-x /etc/letsencrypt/live/
    setfacl -R -m u:nobody:r-x /etc/letsencrypt/archive/

    systemctl daemon-reload

    # --- Restart XRAY ---
    info "Restarting XRAY service with correct permissions..."
    systemctl enable xray >/dev/null 2>&1
    systemctl restart xray

    # --- Verify XRAY Service ---
    if ! systemctl is-active --quiet xray; then
        error "XRAY service failed to start even after permission fix. Please check 'journalctl -u xray'."
    fi

    # --- Update Stunnel to not use port 443 ---
    info "Updating Stunnel to free up port 443 for XRAY..."
    # Remove the old openvpn_ssl section on port 443
    sed -i '/\$openvpn_ssl\$/,+2d' /etc/stunnel/stunnel.conf
    # Add a new one on a non-conflicting port
    cat >> /etc/stunnel/stunnel.conf << EOF

[openvpn_ssl_alt]
accept = 8443
connect = 127.0.0.1:1194
EOF
    # Also, update the main stunnel cert to use the new Let's Encrypt cert
    sed -i "s|cert = /etc/stunnel/stunnel.pem|cert = /etc/letsencrypt/live/${DOMAIN}/fullchain.pem\nkey = /etc/letsencrypt/live/${DOMAIN}/privkey.pem|" /etc/stunnel/stunnel.conf
    systemctl restart stunnel4

    info "XRAY setup completed."
}

setup_support_services() {
    info "Setting up Squid Proxy and Badvpn..."

    # --- Configure Squid Proxy ---
    info "Configuring Squid Proxy on ports 3128 & 8080..."
    if [ -f /etc/squid/squid.conf ]; then
        # Allow all connections by replacing "http_access deny all"
        sed -i 's/http_access deny all/http_access allow all/' /etc/squid/squid.conf
        # Ensure default http_access allow localhost is not the only allow rule
        sed -i 's/http_access allow localhost/#http_access allow localhost/' /etc/squid/squid.conf
        # Add additional ports if they don't exist
        grep -q -F "http_port 8080" /etc/squid/squid.conf || echo "http_port 8080" >> /etc/squid/squid.conf
        grep -q -F "http_port 3128" /etc/squid/squid.conf || echo "http_port 3128" >> /etc/squid/squid.conf
        # Set visible hostname
        DOMAIN=$(cat /root/domain.txt)
        sed -i "s/# visible_hostname .*/visible_hostname $DOMAIN/" /etc/squid/squid.conf

        systemctl enable squid >/dev/null 2>&1
        systemctl restart squid
    else
        warn "Squid configuration file not found. Skipping."
    fi

    # --- Compile and Install Badvpn UDP Gateway ---
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

    # --- Create Badvpn Systemd Service Template ---
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
    # Enable and start services for specified ports
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

    # --- Configure Firewall (UFW) ---
    info "Configuring UFW to open all necessary ports..."
    # Deny all incoming by default and allow outgoing
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
OPENVPN_INSTALLER="/root/openvpn-install.sh"

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
    echo " 4. Show XRAY Share Links"
    echo " 5. Manage OpenVPN Users (run installer)"
    echo " 6. Manage SSH Users"
    echo " 7. Check Service Status"
    echo " 8. Renew SSL Certificate"
    echo " 9. Reboot Server"
    echo " 10. Exit"
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

    # Modify the config file
    config_file="/usr/local/etc/xray/config.json"
    temp_config=$(mktemp)

    jq "(.inbounds[] | select(.tag == \"$inbound_tag\").settings.clients) += [$new_client]" "$config_file" > "$temp_config" && mv "$temp_config" "$config_file"

    if [[ $? -eq 0 ]]; then
        echo "$email;$protocol_name;$creds_for_db;$quota_gb;$ip_limit;$exp_date" >> "$USER_DB"
        echo -e "${GREEN}User  '$email' for $protocol_name added. Restarting XRAY...${NC}"
        systemctl restart xray
        echo "UUID/Password: $creds_for_db"
    else
        echo -e "${RED}Failed to modify xray config file.${NC}"
    fi
}

delete_xray_user() {
    read -p "Enter username (email) to delete: " email
    user_line=$(grep "^$email;" "$USER_DB")
    if [[ -z "$user_line" ]]; then
        echo -e "${RED}User  '$email' not found in database.${NC}"; return
    fi

    protocol_name=$(echo "$user_line" | cut -d';' -f2)
    inbound_tag="${protocol_name}-in"
    config_file="/usr/local/etc/xray/config.json"
    temp_config=$(mktemp)

    # Modify the config file
    jq "del(.inbounds[] | select(.tag == \"$inbound_tag\").settings.clients[] | select(.email == \"$email\"))" "$config_file" > "$temp_config" && mv "$temp_config" "$config_file"

    if [[ $? -eq 0 ]]; then
        sed -i "/^$email;/d" "$USER_DB"
        echo -e "${GREEN}User  '$email' removed. Restarting XRAY...${NC}"
        systemctl restart xray
    else
        echo -e "${RED}Failed to modify xray config file.${NC}"
    fi
}

list_xray_users() {
    echo "--- XRAY User List ---"
    printf "%-25s | %-8s | %-10s | %-10s | %-12s\n" "Email" "Protocol" "Quota(GB)" "IP Limit" "Expires"
    echo "-----------------------------------------------------------------------------"
    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        [[ "$email" == \#* ]] && continue
        printf "%-25s | %-8s | %-10s | %-10s | %-12s\n" "$email" "$protocol" "$quota_gb" "$ip_limit" "$exp_date"
    done < "$USER_DB"
    echo "-----------------------------------------------------------------------------"
}

show_xray_share_links() {
    DOMAIN=$(cat /root/domain.txt)
    echo "--- XRAY Shareable Links ---"
    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        if [[ "$email" == \#* || -z "$email" ]]; then continue; fi

        echo -e "\n${YELLOW}:User  ${email}${NC}"
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
                link="trojan://${creds}@${DOMAIN}:443?type=ws&path=%2Ftrojan&security=tls#${email}"
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
               echo -e "${GREEN}User  '$username' deleted.${NC}"
           else
               echo -e "${RED}User  '$username' does not exist.${NC}"
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
    read -p "Enter your choice [1-10]: " choice
    case $choice in
        1) add_xray_user; press_enter_to_continue ;;
        2) delete_xray_user; press_enter_to_continue ;;
        3) list_xray_users; press_enter_to_continue ;;
        4) show_xray_share_links; press_enter_to_continue ;;
        5) $OPENVPN_INSTALLER; press_enter_to_continue ;;
        6) manage_ssh_users; press_enter_to_continue ;;
        7) check_services; press_enter_to_continue ;;
        8) renew_ssl; press_enter_to_continue ;;
        9) reboot ;;
        10) exit 0 ;;
        *) echo -e "${RED}Invalid option. Please try again.${NC}"; sleep 1 ;;
    esac
done
EOF

    chmod +x /usr/local/bin/menu
    info "Management menu created. Type 'menu' to use it."

    # --- Create the VPN Monitor Script ---
    info "Creating vpn-monitor script..."
    cat > /usr/local/bin/vpn-monitor << 'EOF'
#!/bin/bash
# VPN User Monitor for Quota and Expiration

USER_DB="/etc/regarstore/users.db"
XRAY_API_ADDR="127.0.0.1:10085"
XRAY_BIN="/usr/local/bin/xray"
LOG_FILE="/var/log/vpn-monitor.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

remove_user() {
    local email="$1"
    local protocol="$2"
    local reason="$3"

    local inbound_tag="${protocol}-in"

    log "Removing user $email from $protocol due to $reason."

    # Remove from XRAY service
    $XRAY_BIN api inbound remove --server=$XRAY_API_ADDR --tag="$inbound_tag" --email="$email"

    # Remove from local database
    sed -i "/^$email;/d" "$USER_DB"
}

check_users() {
    if [ ! -f "$USER_DB" ]; then
        log "User  database not found."
        exit 1
    fi

    local current_date_s=$(date +%s)

    while IFS=';' read -r email protocol creds quota_gb ip_limit exp_date; do
        if [[ "$email" == \#* || -z "$email" ]]; then
            continue
        fi

        # --- Check Expiration ---
        local exp_date_s=$(date -d "$exp_date" +%s)
        if [[ "$current_date_s" -gt "$exp_date_s" ]]; then
            remove_user "$email" "$protocol" "expiration"
            continue
        fi

        # --- Check Quota ---
        if [[ "$quota_gb" -gt 0 ]]; then
            # Query stats for user
            uplink=$($XRAY_BIN api stats --server=$XRAY_API_ADDR --query "user>>>$email>>>traffic>>>uplink" --reset)
            downlink=$($XRAY_BIN api stats --server=$XRAY_API_ADDR --query "user>>>$email>>>traffic>>>downlink" --reset)

            # If stats exist, add to a running total
            if [[ -n "$uplink" && "$downlink" ]]; then
                # Store usage in a simple file per user
                usage_file="/etc/regarstore/usage/${email}.usage"
                mkdir -p /etc/regarstore/usage

                total_usage_bytes=$(($(cat "$usage_file" 2>/dev/null || echo 0) + uplink + downlink))
                echo "$total_usage_bytes" > "$usage_file"

                quota_bytes=$((quota_gb * 1024 * 1024 * 1024))

                if [[ "$total_usage_bytes" -gt "$quota_bytes" ]]; then
                    remove_user "$email" "$protocol" "quota exceeded"
                    rm -f "$usage_file" # Clean up usage file
                fi
            fi
        fi
    done < "$USER_DB"
}

log "VPN monitor script started."
check_users
log "VPN monitor script finished."
EOF

    chmod +x /usr/local/bin/vpn-monitor
    info "VPN monitor script created at /usr/local/bin/vpn-monitor"
}

finalize_installation() {
    info "Finalizing installation..."

    # --- Add Dynamic MOTD ---
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
echo -e "=========================================================================="
echo -e "         Welcome to ${YELLOW}Regar Store VPN Server${NC}"
echo -e "=========================================================================="
echo -e "  • ${CYAN}OS${NC}          : $os_info"
echo -e "  • ${CYAN}CPU${NC}         : $cpu_info"
echo -e "  • ${CYAN}RAM${NC}         : $ram_info"
echo -e "  • ${CYAN}ISP${NC}         : $isp"
echo -e "  • ${CYAN}CITY${NC}        : $city"
echo -e "  • ${CYAN}IP VPS${NC}      : $ip_vps"
echo -e "  • ${CYAN}DOMAIN${NC}      : $domain"
echo -e "  • ${CYAN}DATE & TIME${NC} : $current_time"
echo -e "  • ${CYAN}VERSI AUTOSC${NC} : $version"
echo -e "=========================================================================="
echo -e "  Type ${YELLOW}'menu'${NC} to manage users and services."
echo -e "=========================================================================="
EOF
    chmod +x /usr/local/bin/motd_generator

    # Create profile script to run motd generator on login
    echo "/usr/local/bin/motd_generator" > /etc/profile.d/99-regarstore-motd.sh

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
    # check_os dihapus agar tidak melakukan pengecekan OS

    warn "Pastikan domain Anda sudah di-pointing ke IP Address VPS ini."
    ask_domain

    install_dependencies
    setup_ssh_tunneling
    setup_openvpn
    setup_xray
    setup_support_services
    setup_security
    setup_management_menu

    finalize_installation

    info "Instalasi Selesai! Server akan di-reboot."
    # reboot
}

# --- Run the script ---
main
