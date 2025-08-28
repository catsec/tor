#!/bin/bash
# Step 11: Display complete system configuration info
# Purpose: Show all service details, configs, and connection information
# Usage: Can be run standalone or as part of setup completion

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

info() {
    # Check if previous step requires reboot before proceeding
    check_reboot_required "info" "11"
    
    echo "Step 11: System configuration information..."

    set -euo pipefail

    # Helper: get saved username (created in step 4)
    local USERNAME="$(get_saved_username || true)"
    if [[ -z "${USERNAME:-}" ]]; then
        USERNAME=$(awk -F: '$1!="root" && $7 ~ /bash|zsh|sh/ && $3>=1000 {print $1;exit}' /etc/passwd || true)
    fi

    # Note: External IP detection removed - SSH only accessible via WireGuard/Tor

    echo ""
    echo "==============================================================================="
    echo "                    DEBIAN 13 SECURITY SETUP - CONFIGURATION INFO"
    echo "==============================================================================="
    echo ""

    # ---------------------------------------------------------------------
    # System Information
    # ---------------------------------------------------------------------
    echo "SYSTEM INFORMATION:"
    echo "  Hostname: $(hostname -f 2>/dev/null || hostname)"
    echo "  User Account: ${USERNAME:-'NONE CREATED'}"
    echo "  Setup Date: $(date)"
    echo "  Access: WireGuard VPN + Tor Hidden Service Only"
    echo ""

    # ---------------------------------------------------------------------
    # Service Status
    # ---------------------------------------------------------------------
    echo "SERVICE STATUS:"
    
    # SSH
    SSH_SERVICE=$(detect_ssh_service)
    SSH_STATUS=$(systemctl is-active "$SSH_SERVICE" 2>/dev/null || echo "inactive")
    echo "  SSH Server: $SSH_STATUS ($SSH_SERVICE)"
    if [[ "$SSH_STATUS" == "active" ]]; then
        SSH_PORTS=$(ss -tlnp | grep -E ':22\s' | awk '{print $4}' | sed 's/.*://' | sort -u | tr '\n' ',' | sed 's/,$//')
        echo "    Listening on: ${SSH_PORTS:-'port 22'}"
    fi

    # WireGuard
    WG_STATUS=$(systemctl is-active wg-quick@wg0 2>/dev/null || echo "inactive")
    echo "  WireGuard VPN: $WG_STATUS"
    if [[ "$WG_STATUS" == "active" ]]; then
        WG_INFO=$(wg show wg0 2>/dev/null || true)
        if [[ -n "$WG_INFO" ]]; then
            echo "    Interface: wg0"
            echo "    Server IP: 10.11.12.1"
            PEER_COUNT=$(echo "$WG_INFO" | grep -c "^peer:" || echo "0")
            echo "    Active Peers: $PEER_COUNT"
        fi
    fi

    # Tor
    TOR_STATUS=$(systemctl is-active tor 2>/dev/null || echo "inactive")
    echo "  Tor Proxy: $TOR_STATUS"
    if [[ "$TOR_STATUS" == "active" ]]; then
        echo "    SOCKS Proxy: 127.0.0.1:9050"
        echo "    VPN Access: 10.11.12.1:9050"
    fi

    # Nginx
    NGINX_STATUS=$(systemctl is-active nginx 2>/dev/null || echo "inactive")
    echo "  Nginx Web Server: $NGINX_STATUS"
    if [[ "$NGINX_STATUS" == "active" ]]; then
        echo "    Local Access: http://127.0.0.1"
    fi

    # UFW Firewall
    UFW_STATUS=$(ufw status | head -1 | awk '{print $2}' 2>/dev/null || echo "inactive")
    echo "  UFW Firewall: $UFW_STATUS"

    echo ""

    # ---------------------------------------------------------------------
    # Tor Hidden Service Information
    # ---------------------------------------------------------------------
    echo "TOR HIDDEN SERVICES:"
    
    # Nginx Hidden Service
    NGINX_HS_DIR="/var/lib/tor/nginx_hidden_service"
    if [[ -f "$NGINX_HS_DIR/hostname" ]]; then
        NGINX_TOR_HOSTNAME=$(cat "$NGINX_HS_DIR/hostname" 2>/dev/null | tr -d '\n\r')
        echo "  Nginx Web Service: $NGINX_TOR_HOSTNAME"
        echo "    Access via Tor Browser: http://$NGINX_TOR_HOSTNAME"
        echo "    Command line test: curl --socks5-hostname 127.0.0.1:9050 http://$NGINX_TOR_HOSTNAME"
    else
        echo "  Nginx Hidden Service: NOT CONFIGURED"
    fi
    
    # SSH Hidden Service  
    SSH_HS_DIR="/var/lib/tor/ssh_hidden_service"
    if [[ -f "$SSH_HS_DIR/hostname" ]]; then
        SSH_TOR_HOSTNAME=$(cat "$SSH_HS_DIR/hostname" 2>/dev/null | tr -d '\n\r')
        echo "  SSH Service: $SSH_TOR_HOSTNAME"
        if [[ -n "${USERNAME:-}" ]]; then
            echo "    SSH command: ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:9050 %h %p' $USERNAME@$SSH_TOR_HOSTNAME"
        fi
    else
        echo "  SSH Hidden Service: NOT CONFIGURED"
    fi
    
    if [[ ! -f "$NGINX_HS_DIR/hostname" && ! -f "$SSH_HS_DIR/hostname" ]]; then
        echo "  (Run step 8 - tor configuration to enable hidden services)"
    fi
    echo ""

    # ---------------------------------------------------------------------
    # WireGuard Configuration
    # ---------------------------------------------------------------------
    echo "WIREGUARD VPN CONFIGURATION:"
    
    WG_SERVER_CONF="/etc/wireguard/wg0.conf"
    WG_CLIENT_CONF="/etc/wireguard/client.conf"
    
    if [[ -f "$WG_SERVER_CONF" ]]; then
        echo "  Server Config: $WG_SERVER_CONF"
        echo "  Network: 10.11.12.0/24"
        echo "  Server: 10.11.12.1"
        echo "  Client: 10.11.12.2"
        echo ""
        
        if [[ -f "$WG_CLIENT_CONF" ]]; then
            echo "  CLIENT CONFIGURATION (save as .conf file):"
            echo "  ----------------------------------------"
            cat "$WG_CLIENT_CONF" 2>/dev/null || echo "  ERROR: Cannot read client config"
            echo "  ----------------------------------------"
            echo ""
            
            # Generate QR code if qrencode is available
            if command -v qrencode >/dev/null 2>&1; then
                echo "  QR CODE FOR MOBILE (scan with WireGuard app):"
                echo ""
                qrencode -t ansiutf8 -l L < "$WG_CLIENT_CONF" 2>/dev/null || echo "  ERROR: Cannot generate QR code"
                echo ""
            else
                echo "  Install 'qrencode' package to display QR code for mobile setup"
                echo ""
            fi
        else
            echo "  Client Config: NOT FOUND"
            echo "  (Run step 7 - WireGuard setup to generate client config)"
            echo ""
        fi
    else
        echo "  WireGuard: NOT CONFIGURED"
        echo "  (Run step 7 - WireGuard setup to enable VPN)"
        echo ""
    fi

    # ---------------------------------------------------------------------
    # SSH Connection Information
    # ---------------------------------------------------------------------
    echo "SSH CONNECTION:"
    
    if [[ -n "${USERNAME:-}" ]]; then
        echo "  Via WireGuard VPN: ssh $USERNAME@10.11.12.1"
        
        # Check for SSH Tor hidden service
        SSH_HS_DIR="/var/lib/tor/ssh_hidden_service"
        if [[ -f "$SSH_HS_DIR/hostname" ]]; then
            SSH_TOR_HOSTNAME=$(cat "$SSH_HS_DIR/hostname" 2>/dev/null | tr -d '\n\r')
            echo "  Via Tor Hidden Service: ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:9050 %h %p' $USERNAME@$SSH_TOR_HOSTNAME"
        else
            echo "  Via Tor: Configure Tor hidden service first (step 8)"
        fi
        echo ""
        
        SSH_KEY_FILE="/home/$USERNAME/.ssh/authorized_keys"
        if [[ -f "$SSH_KEY_FILE" ]]; then
            KEY_COUNT=$(wc -l < "$SSH_KEY_FILE" 2>/dev/null || echo "0")
            echo "  Authorized Keys: $KEY_COUNT key(s) configured"
            echo "  Key File: $SSH_KEY_FILE"
        else
            echo "  Authorized Keys: NOT CONFIGURED"
        fi
        echo ""
        echo "  Note: SSH is restricted to loopback (127.0.0.1) and WireGuard (10.11.12.1) only"
        echo "        No direct internet access to SSH for security"
    else
        echo "  SSH User: NOT CONFIGURED"
        echo "  (Run step 4 - user creation to set up SSH access)"
    fi
    echo ""

    # ---------------------------------------------------------------------
    # Security Status
    # ---------------------------------------------------------------------
    echo "SECURITY STATUS:"
    
    # AppArmor
    if command -v aa-status >/dev/null 2>&1; then
        APPARMOR_PROFILES=$(aa-status --enabled 2>/dev/null | wc -l || echo "0")
        echo "  AppArmor: $APPARMOR_PROFILES profile(s) active"
    else
        echo "  AppArmor: Not available"
    fi

    # Logging
    if mountpoint -q /var/log 2>/dev/null; then
        echo "  Persistent Logs: DISABLED (tmpfs)"
    else
        echo "  Persistent Logs: ENABLED (not recommended)"
    fi

    # IPv6
    IPV6_STATUS=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown")
    if [[ "$IPV6_STATUS" == "1" ]]; then
        echo "  IPv6: DISABLED"
    else
        echo "  IPv6: ENABLED (consider disabling)"
    fi

    # Safe Updates
    if [[ -f /usr/local/bin/safe-update ]]; then
        echo "  Safe Updates: CONFIGURED (use 'safe-update' command)"
    else
        echo "  Safe Updates: NOT CONFIGURED"
    fi

    echo ""

    # ---------------------------------------------------------------------
    # Usage Instructions
    # ---------------------------------------------------------------------
    echo "USAGE INSTRUCTIONS:"
    echo ""
    echo "1. Connect via SSH (WireGuard VPN required):"
    if [[ -n "${USERNAME:-}" ]]; then
        echo "   ssh $USERNAME@10.11.12.1"
    else
        echo "   (Set up user account first)"
    fi
    echo ""
    
    echo "2. Connect via WireGuard VPN:"
    echo "   - Import client.conf to WireGuard client"
    echo "   - Connect to VPN, then access:"
    if [[ -n "${USERNAME:-}" ]]; then
        echo "   - SSH: ssh $USERNAME@10.11.12.1"
    fi
    echo "   - Tor Proxy: 10.11.12.1:9050"
    echo ""
    
    echo "3. Test Tor proxy:"
    echo "   curl --socks5 127.0.0.1:9050 https://check.torproject.org"
    echo ""
    
    echo "4. Access via Tor hidden services:"
    if [[ -f "/var/lib/tor/nginx_hidden_service/hostname" ]]; then
        NGINX_TOR_HOSTNAME=$(cat "/var/lib/tor/nginx_hidden_service/hostname" 2>/dev/null | tr -d '\n\r')
        echo "   Web: curl --socks5-hostname 127.0.0.1:9050 http://$NGINX_TOR_HOSTNAME"
    fi
    if [[ -f "/var/lib/tor/ssh_hidden_service/hostname" && -n "${USERNAME:-}" ]]; then
        SSH_TOR_HOSTNAME=$(cat "/var/lib/tor/ssh_hidden_service/hostname" 2>/dev/null | tr -d '\n\r')
        echo "   SSH: ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:9050 %h %p' $USERNAME@$SSH_TOR_HOSTNAME"
    fi
    echo ""
    
    echo "5. Update system safely:"
    echo "   sudo safe-update"
    echo ""
    
    echo "6. View this info again:"
    echo "   sudo setup.sh --info"
    echo ""
    echo "IMPORTANT: This server has no direct SSH access from the internet."
    echo "You must connect via WireGuard VPN or use Tor hidden service."
    echo ""

    echo "==============================================================================="
    echo "                              SETUP COMPLETE"
    echo "==============================================================================="
    
    mark_step_completed 11
}

# Execute function if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    info
fi