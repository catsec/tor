#!/bin/bash
# Step 7: WireGuard VPN Setup
# Purpose: Configure WireGuard VPN with selective routing (not full tunnel)
# Routing: Only SOCKS proxy port 9050 and SSH port 22 go through VPN
# Network: Uses 10.11.12.x range for VPN clients
# Security: Generates unique server and client keys for secure communication

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

wireguard() {
    # Check if previous step requires reboot before proceeding
    check_reboot_required "wireguard" "7"
    
    echo "Step 7: Setting up WireGuard VPN..."
    
    # WireGuard tools were installed and verified in steps 2-3
    
    # CONFIGURATION PATHS: Define all WireGuard-related file locations
    local wg_dir="/etc/wireguard"
    local server_conf="$wg_dir/wg0.conf"
    local server_key="$wg_dir/server_private.key"
    local server_pub="$wg_dir/server_public.key"
    local client_key="$wg_dir/client_private.key"
    local client_pub="$wg_dir/client_public.key"
    
    # DIRECTORY SETUP: Create secure WireGuard configuration directory
    # 700 permissions ensure only root can access VPN configuration
    mkdir -p "$wg_dir"
    chmod 700 "$wg_dir"
    
    # KEY SAFETY CHECK: Prevent overwriting existing keys without user consent
    local keys_exist=false
    local existing_files=()
    
    for keyfile in "$server_key" "$server_pub" "$client_key" "$client_pub" "$server_conf"; do
        if [[ -f "$keyfile" ]]; then
            keys_exist=true
            existing_files+=("$keyfile")
        fi
    done
    
    if $keys_exist; then
        echo "WARNING: Existing WireGuard configuration detected!"
        echo "The following files already exist:"
        for file in "${existing_files[@]}"; do
            echo "  - $file"
        done
        echo ""
        echo "Continuing will overwrite these files and invalidate existing client configurations."
        local overwrite_confirm=""
        read -p "Do you want to continue and overwrite existing WireGuard setup? (yes/no): " overwrite_confirm
        
        if [[ "$overwrite_confirm" != "yes" ]]; then
            echo "WireGuard setup cancelled to preserve existing configuration."
            echo "To force overwrite, run: sudo setup.sh -s wireguard"
            exit 0
        fi
        
        echo "Backing up existing files..."
        for file in "${existing_files[@]}"; do
            cp "$file" "${file}.backup.$(date +%Y%m%d_%H%M%S)"
            echo "Backed up: $file"
        done
    fi
    
    echo "Generating WireGuard keys..."
    
    # KEY GENERATION: Create cryptographic keys for server-client authentication
    # WireGuard uses Curve25519 for key exchange and ChaCha20Poly1305 for encryption
    
    # Server key pair generation
    wg genkey > "$server_key"
    chmod 600 "$server_key"  # Secure private key permissions
    wg pubkey < "$server_key" > "$server_pub"
    
    # Client key pair generation  
    wg genkey > "$client_key"
    chmod 600 "$client_key"  # Secure private key permissions
    wg pubkey < "$client_key" > "$client_pub"
    
    # Load keys into variables for configuration generation
    local server_private=$(cat "$server_key")
    local server_public=$(cat "$server_pub")
    local client_private=$(cat "$client_key")
    local client_public=$(cat "$client_pub")
    
    echo "Keys generated successfully!"
    
    # PUBLIC IP DETECTION: Get server's real public IP for WireGuard endpoint
    # Important: WireGuard needs public IP, not local IP (unlike SSH setup)
    echo "Detecting server's public IP address..."
    local server_ip=""
    
    # curl was installed and verified in steps 2-3
    
    # MULTI-SERVICE APPROACH: Try multiple IP detection services for reliability
    # Using multiple services ensures we get accurate public IP even if one fails
    local ip_services=(
        "https://ipv4.icanhazip.com"    # Clean IPv4-only service
        "https://api.ipify.org"         # Simple IP API
        "https://ifconfig.me/ip"        # Traditional service
        "https://checkip.amazonaws.com" # AWS-backed service
    )
    
    # Try each service until we get a valid IP address
    for service in "${ip_services[@]}"; do
        # Timeout settings prevent hanging on unresponsive services
        server_ip=$(curl -s --connect-timeout 5 --max-time 10 "$service" 2>/dev/null | tr -d '\n\r' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
        
        if [[ -n "$server_ip" ]]; then
            echo "Public IP detected: $server_ip (via external service)"
            break
        fi
    done
    
    # FALLBACK: Use local detection if all external services fail
    # Note: This may not give the correct public IP if behind NAT
    if [[ -z "$server_ip" ]]; then
        echo "Warning: Could not detect public IP from external services"
        echo "Trying local IP detection as fallback..."
        
        if command -v ip >/dev/null 2>&1; then
            server_ip=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}')
        fi
        if [[ -z "$server_ip" ]]; then
            server_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
        fi
        if [[ -z "$server_ip" ]]; then
            server_ip=$(hostname -i 2>/dev/null | awk '{print $1}')
        fi
        
        if [[ -n "$server_ip" ]]; then
            echo "Warning: Using local IP ($server_ip) - this may not work for external clients"
        fi
    fi
    
    # MANUAL FALLBACK: If all automatic detection methods fail
    if [[ -z "$server_ip" ]]; then
        echo "============================================================"
        echo "MANUAL IP CONFIGURATION REQUIRED"
        echo "============================================================"
        echo "Could not automatically detect server's public IP address."
        echo ""
        echo "To find your public IP, try one of these methods:"
        echo "1. Visit whatismyipaddress.com in a browser"
        echo "2. Ask your VPS provider"
        echo "3. Check your router/firewall configuration"
        echo ""
        echo "IMPORTANT: This must be your PUBLIC IP address that clients"
        echo "           can reach from the internet, not a local IP."
        echo "============================================================"
        
        while true; do
            read -p "Please enter the server's PUBLIC IP address: " server_ip
            
            # Enhanced IP validation with better error messages
            if [[ "$server_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                local valid=true
                IFS='.' read -ra OCTETS <<< "$server_ip"
                for octet in "${OCTETS[@]}"; do
                    if [[ "$octet" -gt 255 || "$octet" -lt 0 ]]; then
                        valid=false
                        break
                    fi
                done
                
                # Additional check for obviously invalid ranges
                local first_octet="${OCTETS[0]}"
                if [[ "$first_octet" -eq 0 || "$first_octet" -eq 127 ]]; then
                    echo -e "\033[31mError: IP address $server_ip appears to be invalid\033[0m"
                    echo "First octet cannot be 0 or 127"
                    continue
                fi
                
                # Warn about private IP ranges
                if [[ ("$first_octet" -eq 10) || \
                      ("$first_octet" -eq 172 && "${OCTETS[1]}" -ge 16 && "${OCTETS[1]}" -le 31) || \
                      ("$first_octet" -eq 192 && "${OCTETS[1]}" -eq 168) ]]; then
                    echo "Warning: $server_ip appears to be a private IP address."
                    read -p "Are you sure this is your PUBLIC IP? (yes/no): " confirm
                    if [[ "$confirm" != "yes" ]]; then
                        continue
                    fi
                fi
                
                if $valid; then
                    break
                fi
            fi
            echo -e "\033[31mError: Please enter a valid IPv4 address (e.g., 203.0.113.1)\033[0m"
        done
    fi
    
    echo "Creating WireGuard server configuration..."
    
    # Create server configuration (firewall rules will be handled by UFW in hardening step)
    cat > "$server_conf" << EOF
[Interface]
PrivateKey = $server_private
Address = 10.11.12.1/24
ListenPort = 51820

[Peer]
PublicKey = $client_public
AllowedIPs = 10.11.12.2/32
EOF
    
    chmod 600 "$server_conf"
    
    echo "Enabling IP forwarding..."
    # Only add if not already present to avoid duplicates
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        echo "Added IP forwarding to sysctl.conf"
    else
        echo "IP forwarding already configured in sysctl.conf"
    fi
    sysctl -p
    
    echo "Starting WireGuard service..."
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    # Verify WireGuard is running
    if systemctl is-active wg-quick@wg0 &>/dev/null; then
        echo "WireGuard service started successfully!"
        echo ""
        echo "IMPORTANT: WireGuard is running but NOT yet secured by firewall."
        echo "Continue to step 10 (hardening) to configure UFW firewall rules."
        echo "Until then, WireGuard port 51820 is open to all traffic!"
    else
        echo -e "\033[31mError: Failed to start WireGuard service\033[0m"
        exit 1
    fi
    
    echo ""
    echo "========================================"
    echo "       WIREGUARD SETUP COMPLETE"
    echo "========================================"
    echo ""
    echo "Server Configuration:"
    echo "- Interface: wg0"
    echo "- Server IP: 10.11.12.1/24"
    echo "- Listen Port: 51820"
    echo "- Public IP: $server_ip (detected from external service)"
    echo ""
    echo "========================================"
    echo "        CLIENT CONFIGURATION"
    echo "========================================"
    echo ""
    echo "This is a SELECTIVE routing VPN - only specific traffic goes through the tunnel."
    echo "Save this configuration to a file (e.g., client.conf):"
    echo ""
    echo "[Interface]"
    echo "PrivateKey = $client_private"
    echo "Address = 10.11.12.2/32"
    echo ""
    echo "[Peer]"
    echo "PublicKey = $server_public"
    echo "Endpoint = $server_ip:51820"
    echo "AllowedIPs = 10.11.12.1/32"
    echo "PersistentKeepalive = 25"
    echo ""
    
    # Save client configuration to file
    local client_config_file="$wg_dir/client.conf"
    cat > "$client_config_file" << EOF
[Interface]
PrivateKey = $client_private
Address = 10.11.12.2/32

[Peer]
PublicKey = $server_public
Endpoint = $server_ip:51820
AllowedIPs = 10.11.12.1/32
PersistentKeepalive = 25
EOF
    
    chmod 600 "$client_config_file"
    echo "Client configuration saved to: $client_config_file"
    echo ""
    
    # Ask user if they want to see QR code
    local show_qr=""
    read -p "Do you want to display a QR code for mobile setup? (yes/no): " show_qr
    
    if [[ "$show_qr" == "yes" || "$show_qr" == "y" ]]; then
        # Generate QR code for mobile devices
        echo ""
        echo "========================================"
        echo "           QR CODE FOR MOBILE"
        echo "========================================"
        echo ""
        echo "Scan this QR code with your mobile WireGuard app:"
        echo ""
        
        # Use the saved client config file for QR code generation
        
        # Generate QR code using qrencode
        if command -v qrencode >/dev/null 2>&1; then
            qrencode -t ANSIUTF8 < "$client_config_file"
            echo ""
        else
            echo "QR code generation not available (qrencode not installed)"
        fi
        echo "========================================"
    fi
    echo "     CLIENT SETUP INSTRUCTIONS"
    echo "========================================"
    echo ""
    echo "1. Install WireGuard on your client device:"
    echo "   - Windows/macOS: Download from https://www.wireguard.com/install/"
    echo "   - Linux: apt install wireguard (or equivalent)"
    echo "   - Mobile: Install WireGuard app from app store"
    echo ""
    echo "2. Import the configuration above or create a file with it"
    echo ""
    echo "3. Connect to the VPN using your WireGuard client"
    echo ""
    echo "4. Configure your applications to use the WireGuard tunnel:"
    echo "   - SOCKS Proxy: Use 10.11.12.1:9050 for Tor traffic"
    echo "   - SSH: Connect to 10.11.12.1:22 for secure shell access"
    echo "   - Only these specific services route through the VPN tunnel"
    echo ""
    
    echo -e "\033[92mWireGuard VPN setup completed successfully!\033[0m"
    
    mark_step_completed 7
}

# Execute function if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    wireguard
fi