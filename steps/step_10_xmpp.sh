#!/bin/bash
# Step 10: XMPP Server Setup
# Purpose: Install and configure XMPP server for secure messaging

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

xmpp() {
    echo "Step 10: XMPP server setup..."

    set -euo pipefail
    
    # Check if previous step requires reboot before proceeding
    check_reboot_required "xmpp" "10"
    
    echo "Configuring Prosody XMPP server for maximum security..."
    
    # Create secure Prosody configuration
    cat > /etc/prosody/prosody.cfg.lua << 'EOF'
-- Prosody XMPP Server Configuration - Maximum Security Setup
-- Listen only locally; Tor publishes the ports
interfaces = { "127.0.0.1"}  -- global

-- HTTPS listener (no plain HTTP)
https_ports = { 5281 }
https_interfaces = { "127.0.0.1"}
http_ports = {}  -- disable HTTP

-- Make Prosody build correct onion URLs for HTTP modules
http_external_url = "https://YOUR_ONION.onion/"

-- Security defaults
authentication = "internal_hashed"
c2s_require_encryption = true
s2s_require_encryption = true
tls_profile = "modern"

-- Additional security settings
consider_bosh_secure = true
consider_websocket_secure = true
allow_registration = false  -- disable public registration

-- Logging configuration (minimal for privacy)
log = {
    warn = "/var/log/prosody/prosody.log";
    error = "/var/log/prosody/prosody.err";
}

-- Module configuration
modules_enabled = {
    -- Generally required
    "roster"; -- Allow users to have a roster
    "saslauth"; -- Authentication for clients and servers
    "tls"; -- Add support for secure TLS on c2s/s2s connections
    "disco"; -- Service discovery
    "carbons"; -- Keep multiple clients in sync
    "pep"; -- Enables users to publish their avatar, status, etc.
    "private"; -- Private XML storage (for room bookmarks, etc.)
    "blocklist"; -- Allow users to block communications
    "vcard4"; -- User profiles (for client compatibility)
    "vcard_legacy"; -- Legacy vCard compatibility
    "limits"; -- Enable bandwidth limiting for XMPP connections
    "version"; -- Replies to server version requests
    "uptime"; -- Report how long server has been running
    "time"; -- Let others know the time here
    "ping"; -- Replies to XMPP pings with pongs
    "admin_adhoc"; -- Allows administration via an XMPP client
    "admin_shell"; -- Allow secure administration via 'prosodyctl shell'

    -- Nice to have
    "compression"; -- Stream compression

    -- Admin interfaces
    "bosh"; -- Enable BOSH clients
    "websocket"; -- XMPP over WebSockets
    "http_files"; -- Serve static files from a directory over HTTP
    
    -- Security modules
    "smacks"; -- Stream management and resumption
    "csi_simple"; -- Simple Mobile optimizations
}

-- Disable modules that could reduce security
modules_disabled = {
    "s2s"; -- Disable server-to-server communication for maximum isolation
}

-- Virtual host configuration
VirtualHost "localhost"
    enabled = true
    ssl = {
        key = "/etc/prosody/certs/localhost.key";
        certificate = "/etc/prosody/certs/localhost.crt";
    }

-- Configure admin users (will be set up during installation)
admins = { }

-- Rate limiting
limits = {
    c2s = {
        rate = "10kb/s";
    };
    s2sin = {
        rate = "30kb/s";
    };
}

-- Security: Disable unnecessary features
allow_unencrypted_plain_auth = false
c2s_timeout = 300
s2s_timeout = 300
EOF

    # Set proper permissions
    chown root:prosody /etc/prosody/prosody.cfg.lua
    chmod 640 /etc/prosody/prosody.cfg.lua
    
    # Create certificate directory
    mkdir -p /etc/prosody/certs
    chown prosody:prosody /etc/prosody/certs
    chmod 750 /etc/prosody/certs
    
    # Generate self-signed certificate for localhost
    openssl req -new -x509 -days 365 -nodes -out "/etc/prosody/certs/localhost.crt" -keyout "/etc/prosody/certs/localhost.key" -subj "/CN=localhost"
    chown prosody:prosody /etc/prosody/certs/localhost.*
    chmod 644 /etc/prosody/certs/localhost.crt
    chmod 600 /etc/prosody/certs/localhost.key
    
    # Create log directory
    mkdir -p /var/log/prosody
    chown prosody:prosody /var/log/prosody
    chmod 750 /var/log/prosody
    
    # Start and enable Prosody
    systemctl enable prosody
    systemctl restart prosody
    
    # Wait for service to start
    sleep 2
    
    if systemctl is-active prosody &>/dev/null; then
        echo "Prosody XMPP server started successfully"
    else
        echo -e "\033[31mError: Failed to start Prosody service\033[0m"
        systemctl status prosody --no-pager -l | head -10
        exit 1
    fi
    
    # Update configuration with actual onion address if available
    XMPP_HS_DIR="/var/lib/tor/xmpp_hidden_service"
    if [[ -f "$XMPP_HS_DIR/hostname" ]]; then
        XMPP_ONION=$(cat "$XMPP_HS_DIR/hostname" 2>/dev/null | tr -d '\n\r')
        if [[ -n "$XMPP_ONION" ]]; then
            echo "Updating Prosody configuration with onion address: $XMPP_ONION"
            sed -i "s|https://YOUR_ONION.onion/|https://$XMPP_ONION:5281/|g" /etc/prosody/prosody.cfg.lua
            systemctl reload prosody
        fi
    else
        echo "Note: XMPP onion address will be available after Tor restart"
        echo "Run 'sudo systemctl reload prosody' after step 8 (Tor) completes"
    fi
    
    echo "XMPP server configured with maximum security:"
    echo "- HTTPS only (port 5281) - no plain HTTP"
    echo "- TLS required for all client connections"
    echo "- Server-to-server disabled for isolation"
    echo "- Public registration disabled"
    echo "- Listening only on localhost (Tor provides access)"
    echo "- Modern TLS profile enabled"
    
    echo -e "\033[92mXMPP server setup completed successfully!\033[0m"
    
    mark_step_completed 10
}

# Execute function if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    xmpp
fi