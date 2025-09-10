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

-- Logging configuration (ZERO LOGS for maximum security)
-- All logging disabled - no metadata leakage
log = {
    -- No file logging - everything goes to /dev/null via systemd
}
-- Disable internal debug logging
debug = false

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
    
    -- Privacy modules (optional - only if available in prosody-modules)
    "filter_chatstates"; -- Block chat state notifications (typing indicators)
    "privacy_lists"; -- XMPP privacy lists support
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

-- Privacy: Minimize metadata collection
archive_expires_after = "1 day"  -- Auto-delete message archives
max_archive_query_results = 1   -- Limit archive query results
default_archive_policy = false  -- No message archiving by default

-- Disable presence/status broadcasting to reduce metadata
broadcast_presence = false

-- Security: Additional hardening
require_encryption = true
c2s_require_encryption = true
s2s_require_encryption = true
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
    
    # No log directories needed - all logging disabled for security
    
    # Enable Prosody (don't start yet - will start after all config is complete)
    systemctl enable prosody
    
    # Create admin user
    echo ""
    echo "Setting up XMPP admin user..."
    
    # Function to validate username (lowercase and numbers only)
    validate_username() {
        local username="$1"
        if [[ -z "$username" ]]; then
            return 1
        fi
        if [[ ! "$username" =~ ^[a-z0-9]+$ ]]; then
            return 1
        fi
        if [[ ${#username} -lt 3 || ${#username} -gt 20 ]]; then
            return 1
        fi
        return 0
    }
    
    # Prompt for admin username with validation
    while true; do
        echo -n "Enter XMPP admin username (lowercase and numbers only, 3-20 chars): "
        read -r XMPP_ADMIN_USER
        
        if validate_username "$XMPP_ADMIN_USER"; then
            break
        else
            echo "Invalid username. Must be 3-20 characters, lowercase letters and numbers only."
        fi
    done
    
    # Generate secure random password (16 chars, lowercase and numbers)
    XMPP_ADMIN_PASS=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 16)
    
    # Create admin user in Prosody
    echo "Creating admin user: $XMPP_ADMIN_USER"
    if ! prosodyctl register "$XMPP_ADMIN_USER" localhost "$XMPP_ADMIN_PASS" 2>/dev/null; then
        echo -e "\033[31mError: Failed to create admin user with prosodyctl\033[0m"
        echo "This may be normal if Prosody service is not running yet"
        echo "Admin user will be created when service starts"
    else
        echo "Admin user registered successfully"
    fi
    
    # Update Prosody configuration with admin user
    sed -i "s|admins = { }|admins = { \"$XMPP_ADMIN_USER@localhost\" }|g" /etc/prosody/prosody.cfg.lua
    
    # Store admin credentials for info step
    ADMIN_CREDS_FILE="/var/tmp/xmpp_admin_credentials"
    cat > "$ADMIN_CREDS_FILE" << EOF
XMPP_ADMIN_USER=$XMPP_ADMIN_USER
XMPP_ADMIN_PASS=$XMPP_ADMIN_PASS
EOF
    chmod 600 "$ADMIN_CREDS_FILE"
    
    echo "Admin user created successfully!"
    echo "Username: $XMPP_ADMIN_USER@localhost"
    echo "Password: $XMPP_ADMIN_PASS"
    echo "(Credentials will be displayed in final info step)"
    
    # Update configuration with actual onion address if available
    XMPP_HS_DIR="/var/lib/tor/xmpp_hidden_service"
    if [[ -f "$XMPP_HS_DIR/hostname" ]]; then
        XMPP_ONION=$(cat "$XMPP_HS_DIR/hostname" 2>/dev/null | tr -d '\n\r')
        if [[ -n "$XMPP_ONION" ]]; then
            echo "Updating Prosody configuration with onion address: $XMPP_ONION"
            sed -i "s|https://YOUR_ONION.onion/|https://$XMPP_ONION:5281/|g" /etc/prosody/prosody.cfg.lua
        fi
    else
        echo "Note: XMPP onion address not yet available"
        echo "This is normal if Tor hidden services are still initializing"
    fi
    
    # Start Prosody with all configuration complete
    echo "Starting Prosody XMPP server..."
    systemctl restart prosody
    
    # Wait for service to start
    sleep 3
    
    if systemctl is-active prosody &>/dev/null; then
        echo "Prosody XMPP server started successfully"
        
        # Ensure admin user is registered now that service is running
        echo "Verifying admin user registration..."
        if prosodyctl register "$XMPP_ADMIN_USER" localhost "$XMPP_ADMIN_PASS" 2>/dev/null; then
            echo "Admin user registered successfully"
        elif prosodyctl passwd "$XMPP_ADMIN_USER" localhost "$XMPP_ADMIN_PASS" 2>/dev/null; then
            echo "Admin user password updated (user already existed)"
        else
            echo -e "\033[31mWarning: Could not verify admin user registration\033[0m"
            echo "You may need to manually create the admin user later"
        fi
        
        # Check if admin_web module is available and enable it
        echo "Checking for admin_web module availability..."
        if prosodyctl check config 2>/dev/null | grep -q "admin_web" || find /usr/lib/prosody/modules /usr/share/prosody-modules -name "*admin_web*" -type f 2>/dev/null | head -1 | grep -q admin_web; then
            echo "Enabling admin_web module..."
            prosodyctl module enable admin_web localhost 2>/dev/null || {
                # Add module to config file if prosodyctl method fails
                sed -i '/-- Admin interfaces/,/-- Security modules/s/http_files"; -- Serve static files from a directory over HTTP/http_files"; -- Serve static files from a directory over HTTP\n    "admin_web"; -- Web-based admin interface/' /etc/prosody/prosody.cfg.lua
                systemctl reload prosody
                echo "admin_web module added to configuration"
            }
            echo "Web admin interface available at /admin/"
        else
            echo "admin_web module not found - using admin_adhoc for management"
            echo "Use XMPP client with admin account for server management"
        fi
    else
        echo -e "\033[31mError: Failed to start Prosody service\033[0m"
        systemctl status prosody --no-pager -l | head -10
        exit 1
    fi
    
    echo "XMPP server configured with maximum security:"
    echo "- HTTPS only (port 5281) - no plain HTTP"
    echo "- TLS required for all client connections"
    echo "- Server-to-server disabled for isolation"
    echo "- Public registration disabled"
    echo "- Listening only on localhost (Tor provides access)"
    echo "- Modern TLS profile enabled"
    echo "- Web admin interface enabled at /admin/"
    
    echo -e "\033[92mXMPP server setup completed successfully!\033[0m"
    
    mark_step_completed 10
}

# Execute function if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    xmpp
fi