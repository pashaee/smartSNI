#!/bin/bash

# Smart SNI Proxy Installer
# Author: Peyman | Github: @pashaee
# Repo: https://github.com/pashaee/smartSNI

set -euo pipefail  # Fail on error, undefined vars, and pipe failures

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[*] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[!] $1${NC}"
}

error() {
    echo -e "${RED}[X] $1${NC}" >&2
}

# Detect OS and package manager
detect_distribution() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian)
                PM="apt"
                UPDATE="$PM update -y"
                INSTALL="$PM install -y"
                ;;
            centos|rhel|almalinux|rocky)
                PM="yum"
                UPDATE="$PM makecache"
                INSTALL="$PM install -y"
                ;;
            fedora)
                PM="dnf"
                UPDATE="$PM makecache"
                INSTALL="$PM install -y"
                ;;
            *)
                error "Unsupported distribution: $ID"
                exit 1
                ;;
        esac
    else
        error "Cannot detect OS: /etc/os-release not found"
        exit 1
    fi
}

# Install required packages
install_dependencies() {
    log "Updating package list..."
    $UPDATE

    local packages=("nginx" "git" "jq" "snapd")
    local missing_packages=()

    for pkg in "${packages[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null || ! rpm -q "$pkg" &>/dev/null; then
            missing_packages+=("$pkg")
        fi
    done

    if [ ${#missing_packages[@]} -gt 0 ]; then
        log "Installing missing packages: ${missing_packages[*]}"
        $INSTALL "${missing_packages[@]}"
    else
        log "All required packages are already installed."
    fi

    # Install Go via snap
    if ! snap list go &>/dev/null; then
        log "Installing Go..."
        snap install go --classic
    else
        log "Go is already installed."
    fi
}

# Install Certbot if not available
install_certbot() {
    if ! command -v certbot &>/dev/null; then
        log "Installing Certbot..."
        $INSTALL certbot python3-certbot-nginx || true
    fi
}

# Main install function
install() {
    if systemctl is-active --quiet sni.service 2>/dev/null; then
        warn "The SNI service is already installed and active."
        return
    fi

    install_dependencies
    install_certbot

    local myip=$(hostname -I | awk '{print $1}')
    local domain=""
    local site_list=""
    local sites=()
    local new_domains=""

    log "Configuring Smart SNI Proxy..."

    while [[ -z "$domain" ]]; do
        read -rp "Enter your domain (e.g., f111.com): " domain
        domain=$(echo "$domain" | xargs)  # Trim
    done

    while [[ -z "$site_list" ]]; do
        read -rp "Enter domains to bypass (comma-separated, e.g., google.com,youtube.com): " site_list
        site_list=$(echo "$site_list" | xargs)
    done

    IFS=',' read -ra sites <<< "$site_list"

    # Build JSON domains
    new_domains="{"
    for i in "${!sites[@]}"; do
        new_domains+="\"${sites[i]}\": \"bypass\""
        if [ $i -lt $((${#sites[@]} - 1)) ]; then
            new_domains+=", "
        fi
    done
    new_domains+="}"

    json_content="{ \"host\": \"$domain\", \"domains\": $new_domains }"

    # Clone from YOUR repo
    local repo="https://github.com/pashaee/smartSNI.git"
    local target_dir="/opt/smartSNI"

    if [ -d "$target_dir" ]; then
        rm -rf "$target_dir"
    fi

    log "Cloning from $repo..."
    git clone "$repo" "$target_dir"

    # Save config
    echo "$json_content" | jq '.' > "$target_dir/config.json"
    log "Config saved to $target_dir/config.json"

    # Configure Nginx
    local nginx_conf="/etc/nginx/sites-enabled/default"
    if [ ! -f "$nginx_conf" ]; then
        error "Nginx config not found: $nginx_conf"
        exit 1
    fi

    sed -i "s/server_name _;/server_name $domain;/g" "$nginx_conf"

    # Copy custom nginx.conf from repo
    if [ -f "$target_dir/nginx.conf" ]; then
        sed "s/<YOUR_HOST>/$domain/g" "$target_dir/nginx.conf" > /tmp/sni-nginx.conf
        sudo cp /tmp/sni-nginx.conf "$nginx_conf"
    else
        error "nginx.conf not found in repo!"
        exit 1
    fi

    systemctl stop nginx
    log "Obtaining SSL certificate with Certbot..."
    certbot --nginx -d "$domain" --register-unsafely-without-email --non-interactive --agree-tos --redirect || {
        error "Failed to obtain SSL certificate. Is port 80 accessible?"
        exit 1
    }

    systemctl restart nginx

    # Create systemd service
    cat > /etc/systemd/system/sni.service <<EOL
[Unit]
Description=Smart SNI Proxy
After=network.target nginx.service

[Service]
Type=simple
User=root
WorkingDirectory=$target_dir
ExecStart=/opt/smartSNI/smartSNI
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

    # Build binary (instead of go run)
    log "Building smartSNI binary..."
    cd "$target_dir"
    if [ -f "main.go" ]; then
        /snap/bin/go build -o smartSNI main.go
    else
        error "main.go not found in $target_dir"
        exit 1
    fi

    chmod +x smartSNI

    # Enable service
    systemctl daemon-reload
    systemctl enable sni.service
    systemctl start sni.service

    if systemctl is-active --quiet sni.service; then
        log "Installation completed successfully!"
        echo
        echo "✅ Service is running."
        echo "📌 Use DoH: https://$domain/dns-query"
        echo "🔧 Config: /opt/smartSNI/config.json"
        echo "🔄 Restart: sudo systemctl restart sni.service"
    else
        error "Service failed to start. Check logs: journalctl -u sni.service -n 50"
        exit 1
    fi
}

# Uninstall function
uninstall() {
    if [ ! -f "/etc/systemd/system/sni.service" ]; then
        warn "The service is not installed."
        return
    fi

    log "Stopping and disabling sni.service..."
    systemctl stop sni.service
    systemctl disable sni.service
    rm -f /etc/systemd/system/sni.service

    log "Removing /opt/smartSNI..."
    rm -rf /opt/smartSNI

    log "Uninstallation completed."
}

# Display current sites
display_sites() {
    local config="/opt/smartSNI/config.json"
    if [ ! -f "$config" ]; then
        error "Config file not found: $config"
        return
    fi

    echo "🎯 Current bypass domains:"
    echo "-------------------------"
    jq -r '.domains | keys[]' "$config"
    echo "-------------------------"
}

# Check service status
check_status() {
    if systemctl is-active --quiet sni.service 2>/dev/null; then
        echo -e "${GREEN}[Service Is Active]${NC}"
    else
        echo -e "${RED}[Service Is Not Active]${NC}"
    fi
}

# Main menu
main_menu() {
    clear
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "     Smart SNI Proxy Installer"
    echo "     By --> Peyman | @pashaee"
    echo "     Github: github.com/pashaee/smartSNI"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    check_status
    echo
    echo "   1) Install Smart SNI"
    echo "   2) Uninstall"
    echo "   3) Show Bypass Domains"
    echo "   0) Exit"
    echo
}

# Run menu
while true; do
    main_menu
    read -rp "Select an option [0-3]: " choice

    case "$choice" in
        1) install ;;
        2) uninstall ;;
        3) display_sites ;;
        0) echo "Goodbye!"; exit 0 ;;
        *)
            warn "Invalid option. Please choose 0 to 3."
            sleep 1
            ;;
    esac

    echo
    read -n1 -r -s -p "Press any key to continue..."
done
