#!/usr/bin/env bash
# Idempotent Tor-only XMPP server bootstrap (Ubuntu 24.04.3 LTS)
# Safe reruns: uses stamp files in /var/lib/torstack-setup

set -e
set -u
set -o pipefail

# ---------- args ----------
FORCE_ALL=0
REDO_TARGET=""
while [ $# -gt 0 ]; do
  case "${1:-}" in
    --force) FORCE_ALL=1 ;;
    --redo)  REDO_TARGET="${2:-}"; shift ;;
    *) echo "Unknown arg: $1"; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash setup.sh [--force|--redo <step>]"; exit 1
fi
export DEBIAN_FRONTEND=noninteractive

STAMPDIR="/var/lib/torstack-setup"
LOGFILE="$STAMPDIR/setup.log"
mkdir -p "$STAMPDIR"

# Logging functions
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }
log_error() { echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: $*" | tee -a "$LOGFILE" >&2; }
log_warn() { echo "$(date '+%Y-%m-%d %H:%M:%S') WARN: $*" | tee -a "$LOGFILE"; }

stamp() { [ "$FORCE_ALL" -eq 1 ] && return 1; [ -f "$STAMPDIR/$1.ok" ] && [ "$REDO_TARGET" != "$1" ]; }
mark()  { touch "$STAMPDIR/$1.ok"; log "Completed step: $1"; }

need_cmds() {
  local missing=0
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || { echo "Missing: $c"; missing=1; }; done
  [ $missing -eq 0 ] || exit 1
}

# Initialize logging
log "Starting Tor-only Ubuntu Server Bootstrap"
log "Running as: $(whoami), Args: $*"

# ---------- prompts (only once unless forced/redo) ----------
if ! stamp "prompts"; then
  echo "=== Tor-only Ubuntu Server Bootstrap (existing user) ==="
  read -rp "Existing non-root username for SSH (must already exist): " SSH_USER
  read -rp "GitHub username to pull SSH keys from: " GITHUB_USER

  # Validate user exists
  if ! id -u "$SSH_USER" >/dev/null 2>&1; then
    echo "ERROR: user '$SSH_USER' does not exist."; exit 1
  fi
  USER_HOME="$(getent passwd "$SSH_USER" | cut -d: -f6)"
  [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ] || { echo "ERROR: home dir not found for $SSH_USER"; exit 1; }

  # Validate GitHub user exists before proceeding
  if ! curl -fsSL "https://github.com/${GITHUB_USER}.keys" | grep -q .; then
    echo "WARNING: No SSH keys found for GitHub user '${GITHUB_USER}' or user doesn't exist."
    echo "Please verify the username is correct and has public SSH keys."
    read -rp "Continue anyway? [y/N]: " CONTINUE
    if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
      echo "Exiting. Please check the GitHub username and try again."
      exit 1
    fi
  fi

  echo "This setup will create a Tor-only server with NO LOGGING (maximum privacy)."

  SSH_PORT=22
  WEB_PORT=80

  # Persist prompts for reruns
  cat >"$STAMPDIR/env" <<EOF
SSH_USER="$SSH_USER"
GITHUB_USER="$GITHUB_USER"
USER_HOME="$USER_HOME"
SSH_PORT="$SSH_PORT"
WEB_PORT="$WEB_PORT"
EOF
  mark "prompts"
else
  # shellcheck disable=SC1090
  . "$STAMPDIR/env"
fi

# ---------- 00 packages ----------
if ! stamp "packages"; then
  echo "=== [packages] Updating & installing base packages ==="
  apt update
  apt full-upgrade -y
  apt install -y software-properties-common >/dev/null 2>&1 || true
  add-apt-repository -y universe >/dev/null 2>&1 || true
  apt update
  apt install -y nano ufw unattended-upgrades apt-listchanges curl gpg tor nyx openssh-server nginx cron openssl
  apt autoremove --purge -y
  apt clean
  systemctl enable tor
  systemctl start tor
  mark "packages"
else echo "[packages] skipped"; fi

# ---------- 05 early_ssh ----------
if ! stamp "early_ssh"; then
  echo "=== [early_ssh] Configure SSH for remote access ==="
  mkdir -p /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/05-early-setup.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers ${SSH_USER}
EOF
  
  # Install SSH keys early
  install -d -m 700 -o "$SSH_USER" -g "$SSH_USER" "$USER_HOME/.ssh"
  if curl -fsSL "https://github.com/${GITHUB_USER}.keys" -o "$USER_HOME/.ssh/authorized_keys"; then
    log "SSH keys fetched successfully from GitHub user ${GITHUB_USER}"
  else
    log_warn "Couldn't fetch GitHub keys for ${GITHUB_USER}"
    touch "$USER_HOME/.ssh/authorized_keys"
  fi
  
  if [ ! -s "$USER_HOME/.ssh/authorized_keys" ]; then
    echo "# WARNING: No SSH keys were retrieved from GitHub user ${GITHUB_USER}" > "$USER_HOME/.ssh/authorized_keys"
    echo "# You will need to add SSH keys manually or you may be locked out" >> "$USER_HOME/.ssh/authorized_keys"
  fi
  
  chown -R "$SSH_USER:$SSH_USER" "$USER_HOME/.ssh"
  chmod 700 "$USER_HOME/.ssh"
  chmod 600 "$USER_HOME/.ssh/authorized_keys"
  
  # Create SSH privilege separation directory
  mkdir -p /run/sshd
  chown root:root /run/sshd
  chmod 755 /run/sshd
  
  # Test SSH config and restart
  if sshd -t; then
    systemctl restart ssh
    log "SSH configured and restarted successfully"
  else
    log_error "SSH configuration test failed"
    exit 1
  fi
  
  mark "early_ssh"
  
  # Prompt user to connect via SSH
  PRIMARY_IP="$(ip -o -f inet addr show "$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}')" 2>/dev/null | awk '{print $4}' | head -n1 | cut -d/ -f1 || true)"
  echo
  echo "=============================================="
  echo "SSH is now configured and running!"
  echo "Current server IP: ${PRIMARY_IP:-unknown}"
  echo "You can now connect via SSH using:"
  echo "  ssh ${SSH_USER}@${PRIMARY_IP:-<server-ip>}"
  echo "=============================================="
  echo
  read -rp "Do you want to stop here and continue via SSH? [Y/n]: " CONNECT_SSH
  CONNECT_SSH="${CONNECT_SSH:-Y}"
  
  if [[ "$CONNECT_SSH" =~ ^[Yy]$ ]]; then
    echo
    echo "Setup paused. Connect via SSH and run this script again with the same parameters."
    echo "The script will resume from where it left off."
    echo
    echo "To resume: sudo bash setup.sh"
    exit 0
  else
    echo "Continuing with local setup..."
  fi
else echo "[early_ssh] skipped"; fi

# ---------- 20 sshd ----------
if ! stamp "sshd"; then
  echo "=== [sshd] Final SSH hardening (Tor-only) ==="
  mkdir -p /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/10-tor-only.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers ${SSH_USER}
ListenAddress 127.0.0.1
EOF
  # Ensure SSH privilege separation directory exists
  mkdir -p /run/sshd
  chown root:root /run/sshd
  chmod 755 /run/sshd
  
  # Test SSH config before applying
  if ! sshd -t; then
    log_error "SSH configuration test failed"
    exit 1
  fi
  systemctl restart ssh
  passwd -l root || true
  log "SSH hardened for Tor-only access"
  mark "sshd"
else echo "[sshd] skipped"; fi

# ---------- 30 tor ----------
if ! stamp "tor"; then
  echo "=== [tor] ControlPort + Hidden Services ==="
  install -d -m 700 -o debian-tor -g debian-tor /var/lib/tor/ssh_service
  install -d -m 700 -o debian-tor -g debian-tor /var/lib/tor/web_service
  install -d -m 700 -o debian-tor -g debian-tor /var/lib/tor/xmpp_service

  # Replace our managed blocks
  sed -i '/# BEGIN_CHATG_CONTROL/,/# END_CHATG_CONTROL/d' /etc/tor/torrc
  sed -i '/# BEGIN_CHATG_SERVICES/,/# END_CHATG_SERVICES/d' /etc/tor/torrc
  cat >>/etc/tor/torrc <<'EOF'
# BEGIN_CHATG_CONTROL
ControlPort 127.0.0.1:9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
# END_CHATG_CONTROL

# BEGIN_CHATG_SERVICES
# SSH Hidden Service (separate .onion)
HiddenServiceDir /var/lib/tor/ssh_service/
HiddenServicePort 22 127.0.0.1:22

# Web Demo Page Hidden Service (separate .onion)  
HiddenServiceDir /var/lib/tor/web_service/
HiddenServicePort 80 127.0.0.1:80

# XMPP Client/Server Hidden Service (separate .onion)
HiddenServiceDir /var/lib/tor/xmpp_service/
HiddenServicePort 5222 127.0.0.1:5222
HiddenServicePort 5269 127.0.0.1:5269
# END_CHATG_SERVICES
EOF
  usermod -aG debian-tor "$SSH_USER"
  systemctl restart tor
  sleep 3
  mark "tor"
else echo "[tor] skipped"; fi

SSH_ONION="$(cat /var/lib/tor/ssh_service/hostname 2>/dev/null || true)"
WEB_ONION="$(cat /var/lib/tor/web_service/hostname 2>/dev/null || true)"
XMPP_ONION="$(cat /var/lib/tor/xmpp_service/hostname 2>/dev/null || true)"

# ---------- 40 nginx ----------
if ! stamp "nginx"; then
  echo "=== [nginx] Dark page ==="
  install -d -m 755 /var/www/tor
  cat >/var/www/tor/index.html <<'EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Dark Net</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    html,body { 
      margin: 0; 
      padding: 0; 
      height: 100%; 
      background: #000; 
      color: #fff;
      font-family: 'Courier New', monospace; 
      overflow: hidden;
    }
    .container { 
      height: 100vh; 
      display: flex; 
      align-items: center; 
      justify-content: center; 
      text-align: center; 
    }
    .text { 
      font-size: clamp(2rem, 10vw, 6rem); 
      font-weight: bold; 
      text-transform: uppercase;
      line-height: 1.2;
      letter-spacing: 0.1em;
    }
    .line1 { 
      color: #666; 
      margin-bottom: 0.2em;
    }
    .line2 { 
      color: #fff; 
      text-shadow: 0 0 20px #fff, 0 0 40px #fff;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="text">
      <div class="line1">welcome to the</div>
      <div class="line2">DARK NET</div>
    </div>
  </div>
</body>
</html>
EOF

  # First, completely remove all existing sites
  rm -f /etc/nginx/sites-enabled/*
  rm -f /etc/nginx/sites-available/default
  rm -f /etc/nginx/sites-available/tor-darkpage 2>/dev/null || true

  cat >/etc/nginx/sites-available/tor-darkpage <<EOF
server {
    listen 127.0.0.1:80 default_server;
    listen 80 default_server;
    server_name _ default;

    # Absolutely no logging
    access_log off;
    error_log /dev/null crit;
    log_not_found off;
    
    root /var/www/tor;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
        
        # Additional privacy headers
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
    }

    # Catch-all for any other requests
    location ~* {
        try_files \$uri /index.html;
    }
}
EOF
  
  # Disable nginx access and error logging globally, and remove default server
  cat >/etc/nginx/conf.d/no-logs.conf <<EOF
# Global nginx no-logging configuration
access_log off;
error_log /dev/null crit;
log_not_found off;
server_tokens off;
EOF

  # Also disable the default server in main nginx.conf
  sed -i '/include.*sites-enabled/d' /etc/nginx/nginx.conf
  sed -i '/http {/a\\tinclude /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
  
  # Enable our dark page site
  ln -sf /etc/nginx/sites-available/tor-darkpage /etc/nginx/sites-enabled/tor-darkpage
  
  # Ensure proper permissions on web directory and files
  chown -R www-data:www-data /var/www/tor
  chmod 755 /var/www/tor
  chmod 644 /var/www/tor/index.html
  
  # Verify our site is the only one enabled
  ls -la /etc/nginx/sites-enabled/
  echo "Content of /var/www/tor:"
  ls -la /var/www/tor/
  
  # Test and restart nginx completely
  if nginx -t; then
    systemctl stop nginx
    sleep 2
    systemctl start nginx
    log "Nginx configured with dark page and restarted"
  else
    log_error "Nginx configuration test failed"
    exit 1
  fi
  mark "nginx"
else echo "[nginx] skipped"; fi

# ---------- 50 prosody install ----------
PROSODY_INSTALLED=0
if ! stamp "prosody"; then
  echo "=== [prosody] Install Prosody XMPP server ==="
  if apt install -y prosody lua-sec lua-dbi-sqlite3 lua-zlib; then
    # Install prosody-modules separately (may not be available on all Ubuntu versions)
    apt install -y prosody-modules 2>/dev/null || log_warn "prosody-modules package not available, some modules may not work"
    PROSODY_INSTALLED=1
    # Create prosody data directory
    install -d -m 750 -o prosody -g prosody /var/lib/prosody
    # Hidden services are already configured in the tor step
    # Just ensure the XMPP service directory exists
    install -d -m 700 -o debian-tor -g debian-tor /var/lib/tor/xmpp_service
    systemctl restart tor
    sleep 3
    mark "prosody"
  else
    echo "WARN: Prosody not installed; skipping."
  fi
else
  dpkg -s prosody >/dev/null 2>&1 && PROSODY_INSTALLED=1 || PROSODY_INSTALLED=0
  echo "[prosody] skipped"
fi

# XMPP_ONION is set above from hostname files

# ---------- 51 prosody config ----------
if ! stamp "prosody_config" && [ $PROSODY_INSTALLED -eq 1 ]; then
  echo "=== [prosody_config] Configure Prosody with OMEMO support ==="
  
  # Backup original config
  cp /etc/prosody/prosody.cfg.lua /etc/prosody/prosody.cfg.lua.bak
  
  cat >/etc/prosody/prosody.cfg.lua <<EOF
-- Prosody XMPP Server Configuration for Tor-only deployment with OMEMO

---------- Server-wide settings ----------
-- Enable IPv4
use_ipv4 = true
-- Disable IPv6 for Tor-only setup
use_ipv6 = false

-- Disable s2s encryption requirement for .onion domains
s2s_require_encryption = false
s2s_secure_auth = false

-- This is the list of modules Prosody will load on startup.
modules_enabled = {
    -- Generally required
        "roster"; -- Allow users to have a roster. Recommended ;)
        "saslauth"; -- Authentication for clients and servers. Recommended if you want to log in.
        "tls"; -- Add support for secure TLS on c2s/s2s connections
        "dialback"; -- s2s dialback support
        "disco"; -- Service discovery

    -- Not essential, but recommended
        "carbons"; -- Keep multiple clients in sync
        "pep"; -- Enables users to publish their avatar, mood, activity, playing music and more
        "private"; -- Private XML storage (for room bookmarks, etc.)
        "blocklist"; -- Allow users to block communications with other users
        "vcard4"; -- User profiles (stored in PEP)
        "vcard_legacy"; -- Conversion between legacy vCard and PEP Avatar, vcard-temp

    -- Nice to have
        "version"; -- Replies to server version requests
        "uptime"; -- Report how long server has been running
        "time"; -- Let others know the time here on this server
        "ping"; -- Replies to XMPP pings with pongs
        "register"; -- Allow users to register on this server using a client and change passwords
        "mam"; -- Store messages in an archive and allow users to access it

    -- OMEMO support
        "pubsub"; -- Required for OMEMO

    -- Admin interfaces
        "admin_adhoc"; -- Allows administration via an XMPP client that supports ad-hoc commands
        "admin_telnet"; -- Opens telnet console interface on localhost port 5582


    -- Other specific functionality
        "posix"; -- POSIX functionality, sends server to background, enables syslog, etc.
};

-- Disable account creation by default, for security
allow_registration = false

-- These are the SSL/TLS-related settings.
ssl = {
    key = "/etc/prosody/certs/localhost.key";
    certificate = "/etc/prosody/certs/localhost.crt";
}

-- Force clients to use encrypted connections
c2s_require_encryption = true

-- Server-to-server authentication
authentication = "internal_hashed"

-- Storage configuration
storage = "sql" -- Default is "internal"
sql = { driver = "SQLite3", database = "prosody.sqlite" }

-- Logging configuration (all logs sent to /dev/null for privacy)
log = {
    { levels = { min = "debug", max = "info" }, to = "file", filename = "/dev/null" };
    { levels = { min = "warn", max = "error" }, to = "file", filename = "/dev/null" };
}


-- Pidfile, used by prosodyctl and the init.d script
pidfile = "/var/run/prosody/prosody.pid"

-- Admin interface configuration  
admin_interfaces = { "127.0.0.1" }

---------- Virtual hosts ----------
-- Define your .onion domain here once Tor generates it
-- This will be updated after the onion hostname is available
-- VirtualHost will be configured after .onion hostname is available
-- This is a placeholder that will be replaced

-- Components will be configured after VirtualHost is set up

-- Configure PEP/pubsub for OMEMO
pubsub_max_items = 10000
pep_max_items = 10000

-- OMEMO-specific settings
omemo_default_policy = true
archive_expires_after = "1w" -- Archive expires after 1 week
max_archive_query_results = 20
default_archive_policy = false -- Users opt in to message archiving
EOF

  # SSL certificates will be created after .onion hostname is available
  mkdir -p /etc/prosody/certs
  chown prosody:prosody /etc/prosody/certs
  
  # Override systemd service to disable all logging
  mkdir -p /etc/systemd/system/prosody.service.d
  cat >/etc/systemd/system/prosody.service.d/no-logs.conf <<'EOF'
[Service]
StandardOutput=null
StandardError=null
SyslogIdentifier=
EOF
  systemctl daemon-reload

  # Test configuration and start
  if prosodyctl check config; then
    log "Prosody configuration validated successfully"
  else
    log_warn "Prosody configuration check failed, but continuing..."
  fi
  
  if systemctl restart prosody && systemctl enable prosody; then
    log "Prosody service started and enabled"
  else
    log_error "Failed to start Prosody service"
    exit 1
  fi
  
  mark "prosody_config"
else 
  [ $PROSODY_INSTALLED -eq 0 ] && echo "[prosody_config] skipped (prosody not installed)" || echo "[prosody_config] skipped"
fi

# ---------- 52 prosody_onion ----------
if ! stamp "prosody_onion" && [ $PROSODY_INSTALLED -eq 1 ]; then
  echo "=== [prosody_onion] Configure .onion domain and SSL certificates ==="
  
  # Wait for XMPP .onion hostname to be available
  if [ -z "$XMPP_ONION" ]; then
    log_warn "XMPP .onion hostname not yet available, sleeping 5 seconds..."
    sleep 5
    XMPP_ONION="$(cat /var/lib/tor/xmpp_service/hostname 2>/dev/null || true)"
  fi
  
  if [ -n "$XMPP_ONION" ]; then
    log "Configuring Prosody for XMPP .onion domain: $XMPP_ONION"
    
    # Create SSL certificates for the .onion domain
    if [ ! -f "/etc/prosody/certs/$XMPP_ONION.crt" ]; then
      if openssl req -new -x509 -days 365 -nodes \
        -out "/etc/prosody/certs/$XMPP_ONION.crt" \
        -keyout "/etc/prosody/certs/$XMPP_ONION.key" \
        -subj "/C=XX/ST=XX/L=XX/O=Tor XMPP Server/CN=$XMPP_ONION" 2>/dev/null; then
        log "SSL certificates created for $XMPP_ONION"
        chown prosody:prosody "/etc/prosody/certs/$XMPP_ONION".*
        chmod 640 "/etc/prosody/certs/$XMPP_ONION".*
      else
        log_error "Failed to create SSL certificates for $XMPP_ONION"
        exit 1
      fi
    fi
    
    # Update Prosody configuration with the actual .onion domain
    cat >>/etc/prosody/prosody.cfg.lua <<EOF

---------- .onion Virtual Host ----------
VirtualHost "$XMPP_ONION"
    enabled = true
    ssl = {
        key = "/etc/prosody/certs/$XMPP_ONION.key";
        certificate = "/etc/prosody/certs/$XMPP_ONION.crt";
    }

-- Set up a MUC (multi-user chat) room server
Component "conference.$XMPP_ONION" "muc"
    name = "Chatrooms"

-- Set up a SOCKS5 bytestreams proxy for server-proxied file transfers  
Component "proxy.$XMPP_ONION" "proxy65"
    proxy65_address = "$XMPP_ONION"
EOF
    
    # Restart Prosody to load the new configuration
    if systemctl restart prosody; then
      log "Prosody restarted with .onion configuration"
    else
      log_error "Failed to restart Prosody with .onion configuration"
      exit 1
    fi
    
    # Create admin user with random 22-character password
    ADMIN_PASSWORD="$(openssl rand -base64 33 | tr -d '=+/' | cut -c1-22)"
    # Use printf to provide password non-interactively
    if printf '%s\n%s\n' "$ADMIN_PASSWORD" "$ADMIN_PASSWORD" | prosodyctl adduser "admin@$XMPP_ONION" 2>/dev/null; then
      log "Admin user created: admin@$XMPP_ONION"
      # Store credentials securely
      echo "JID: admin@$XMPP_ONION" > "$STAMPDIR/admin_credentials.txt"
      echo "Password: $ADMIN_PASSWORD" >> "$STAMPDIR/admin_credentials.txt"
      chmod 600 "$STAMPDIR/admin_credentials.txt"
      chown root:root "$STAMPDIR/admin_credentials.txt"
    else
      log_warn "Automatic admin user creation failed, manual creation required"
      # Still store the generated password for manual use
      echo "JID: admin@$XMPP_ONION" > "$STAMPDIR/admin_credentials.txt"
      echo "Password: $ADMIN_PASSWORD" >> "$STAMPDIR/admin_credentials.txt"
      echo "Status: REQUIRES_MANUAL_CREATION" >> "$STAMPDIR/admin_credentials.txt"
      chmod 600 "$STAMPDIR/admin_credentials.txt"
      chown root:root "$STAMPDIR/admin_credentials.txt"
      log "Generated password stored. Create manually: prosodyctl adduser admin@$XMPP_ONION"
    fi
    
    mark "prosody_onion"
  else
    log_error "Could not get XMPP .onion hostname after waiting"
    exit 1
  fi
else 
  [ $PROSODY_INSTALLED -eq 0 ] && echo "[prosody_onion] skipped (prosody not installed)" || echo "[prosody_onion] skipped"
fi

# ---------- 55 help_script ----------
if ! stamp "help_script"; then
  echo "=== [help_script] Create help script with credentials and admin commands ==="
  
  cat >/usr/local/bin/help.sh <<'EOF'
#!/usr/bin/env bash
# Tor Server Help - Credentials and XMPP Management

set -e

echo "====== TOR SERVER HELP ======"
echo

# Read onion addresses and config
SSH_ONION="$(sudo cat /var/lib/tor/ssh_service/hostname 2>/dev/null || echo "pending")"
WEB_ONION="$(sudo cat /var/lib/tor/web_service/hostname 2>/dev/null || echo "pending")"
XMPP_ONION="$(sudo cat /var/lib/tor/xmpp_service/hostname 2>/dev/null || echo "pending")"
SSH_USER="$(sudo cat /var/lib/torstack-setup/env 2>/dev/null | grep SSH_USER | cut -d'"' -f2 2>/dev/null || echo "unknown")"

echo "🔗 SERVER ACCESS:"
if [ "$SSH_ONION" != "pending" ]; then
  echo "  SSH:     torsocks ssh -p 22 ${SSH_USER}@${SSH_ONION}"
else
  echo "  SSH:     <waiting for onion address>"
fi
if [ "$WEB_ONION" != "pending" ]; then
  echo "  Web:     http://${WEB_ONION}/"
else
  echo "  Web:     <waiting for onion address>"
fi
if [ "$XMPP_ONION" != "pending" ]; then
  echo "  XMPP:    ${XMPP_ONION}:5222 (clients), :5269 (server)"
else
  echo "  XMPP:    <waiting for onion address>"
fi
echo

if dpkg -s prosody >/dev/null 2>&1 && [ "$XMPP_ONION" != "pending" ]; then
  echo "👤 ADMIN CREDENTIALS:"
  if [ -f "/var/lib/torstack-setup/admin_credentials.txt" ]; then
    sudo cat /var/lib/torstack-setup/admin_credentials.txt
  else
    echo "  Create manually: prosodyctl adduser admin@${XMPP_ONION}"
  fi
  echo

  echo "👥 USER MANAGEMENT:"
  echo "  prosodyctl adduser user@${XMPP_ONION}    # Create user"
  echo "  prosodyctl passwd user@${XMPP_ONION}     # Change password"
  echo "  prosodyctl deluser user@${XMPP_ONION}    # Delete user"
  echo "  prosodyctl list users                    # List all users"
  echo

  echo "🔧 SERVER ADMIN:"
  echo "  prosodyctl status                        # Server status"
  echo "  prosodyctl restart                       # Restart server"
  echo "  prosodyctl check                         # Check config"
  echo "  telnet 127.0.0.1 5582                   # Admin console"
  echo

  echo "💬 CLIENT SETUP:"
  echo "  Server:   ${XMPP_ONION}"
  echo "  Port:     5222"
  echo "  Security: OMEMO encryption (recommended)"
  echo "  Proxy:    SOCKS5 127.0.0.1:9050 (Tor)"
  echo "  MUC:      conference.${XMPP_ONION}"
  echo

  echo "📝 QUICK EXAMPLES:"
  echo "  # Add a user"
  echo "  prosodyctl adduser alice@${XMPP_ONION}"
  echo
  echo "  # Check online users"
  echo "  prosodyctl shell -c 'print(get_stats().c2s.sessions)'"
  echo
fi

echo "🔐 SECURITY:"
echo "  • All access via Tor only (maximum privacy)"
echo "  • No logs stored anywhere"
echo "  • OMEMO end-to-end encryption"
echo "  • Web admin disabled for security"
echo

echo "======================================"
EOF

  chmod +x /usr/local/bin/help.sh
  ln -sf /usr/local/bin/help.sh /usr/local/bin/help
  
  log "Combined help script created at /usr/local/bin/help.sh"
  mark "help_script"
else echo "[help_script] skipped"; fi

# ---------- 60 ufw ----------
if ! stamp "ufw"; then
  echo "=== [ufw] Firewall rules ==="
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow in on lo
  # No LAN access - Tor-only setup
  ufw --force enable
  mark "ufw"
else echo "[ufw] skipped"; fi

# ---------- 70 nologs ----------
if ! stamp "nologs"; then
  echo "=== [nologs] Apply NO-LOGS policy ==="
  
  # Disable systemd journal storage
  mkdir -p /etc/systemd/journald.conf.d
  cat >/etc/systemd/journald.conf.d/99-nologs.conf <<'EOF'
[Journal]
Storage=none
ForwardToSyslog=no
ForwardToKMsg=no
ForwardToConsole=no
Compress=no
Seal=no
EOF
  systemctl restart systemd-journald || true
  
  # Disable and remove logging services
  systemctl disable --now rsyslog 2>/dev/null || true
  systemctl disable --now fail2ban 2>/dev/null || true
  apt purge -y fail2ban rsyslog 2>/dev/null || true
  
  # Setup automatic log purging
  systemctl enable --now cron || true
  cat >/etc/cron.hourly/nuke-logs <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Clear all log files
find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null || true
find /var/log -mindepth 1 -type f \( -name "*.gz" -o -name "*.1" -o -name "*.old" -o -name "*.xz" \) -delete 2>/dev/null || true

# Clear systemd journal
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true

# Clear any potential Prosody logs
rm -f /var/log/prosody/* 2>/dev/null || true
rm -f /tmp/prosody* 2>/dev/null || true

# Clear nginx logs completely
rm -f /var/log/nginx/* 2>/dev/null || true
truncate -s 0 /var/log/nginx/* 2>/dev/null || true

# Clear any auth logs
truncate -s 0 /var/log/auth* 2>/dev/null || true
truncate -s 0 /var/log/secure* 2>/dev/null || true
EOF
  chmod +x /etc/cron.hourly/nuke-logs
  
  # Run log cleanup immediately
  /etc/cron.hourly/nuke-logs || true
  
  log "No-logs policy applied - maximum privacy mode enabled"
  mark "nologs"
else echo "[nologs] skipped"; fi

# ---------- 80 unattended ----------
if ! stamp "unattended"; then
  echo "=== [unattended] Autoupdates ==="
  dpkg-reconfigure --priority=low unattended-upgrades
  cat >/etc/apt/apt.conf.d/52chatg-unattended <<'EOF'
Unattended-Upgrade::Allowed-Origins {
  "${distro_id}:${distro_codename}";
  "${distro_id}:${distro_codename}-security";
  "${distro_id}:${distro_codename}-updates";
  "${distro_id}:${distro_codename}-backports";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
  mark "unattended"
else echo "[unattended] skipped"; fi

# ---------- 90 cleanup ----------
if ! stamp "cleanup"; then
  echo "=== [cleanup] Remove unneeded services ==="
  systemctl disable --now avahi-daemon 2>/dev/null || true
  systemctl disable --now cups 2>/dev/null || true
  apt purge -y apache2* samba* rpcbind fail2ban* rsyslog* 2>/dev/null || true
  apt autoremove --purge -y
  mark "cleanup"
else echo "[cleanup] skipped"; fi

# ---------- health check (always runs) ----------
echo
echo "===== HEALTH CHECK ====="
echo "[1] Services:"
for s in tor ssh nginx; do
  printf "  %-16s %s\n" "$s:" "$(systemctl is-active "$s" || true)"
done
if dpkg -s prosody >/dev/null 2>&1; then
  printf "  %-16s %s\n" "prosody:" "$(systemctl is-active prosody || true)"
fi

echo
echo "[2] Listening sockets (127.0.0.1 only - Tor-only setup):"
ss -lntp | awk 'NR==1 || $4 ~ /127\.0\.0\.1/ {print}'

echo
echo "[3] Onion hostnames:"
echo "  SSH:     ${SSH_ONION:-pending}"
echo "  Web:     ${WEB_ONION:-pending}"
if dpkg -s prosody >/dev/null 2>&1; then
  echo "  XMPP:    ${XMPP_ONION:-pending}"
fi

echo
echo "[4] UFW status:"
ufw status verbose

echo
echo "[5] Versions:"
( tor --version | head -n1 ) || true
( nginx -v 2>&1 ) || true
( ssh -V 2>&1 ) || true
( nyx --version 2>&1 | head -n1 ) || true
if dpkg -s prosody >/dev/null 2>&1; then
  dpkg -s prosody 2>/dev/null | awk -F': ' '/^Package:|^Version:/{print}'
fi

echo
echo "[6] Nyx cookie readable for $SSH_USER?"
if sudo -u "$SSH_USER" test -r /run/tor/control.authcookie; then
  echo "  OK"
else
  echo "  Not yet (re-login may be required)."
fi

echo
echo "[7] SSH Key Check:"
if [ -s "$USER_HOME/.ssh/authorized_keys" ] && ! grep -q "^#.*WARNING" "$USER_HOME/.ssh/authorized_keys"; then
  echo "  SSH keys present"
else
  echo "  WARNING: No valid SSH keys found! You may be locked out."
  echo "  Add SSH keys manually to: $USER_HOME/.ssh/authorized_keys"
fi

echo "===== HEALTH CHECK END ====="

echo
log "Setup completed successfully"
echo "====== DONE ======"
echo
echo "💡 Quick Access: Run 'help' for credentials and admin commands"
echo
if [ -n "${SSH_ONION:-}" ]; then
  echo "SSH via Tor:  torsocks ssh -p 22 ${SSH_USER}@${SSH_ONION}"
else
  echo "SSH via Tor:  <waiting for onion address>"
fi
if [ -n "${WEB_ONION:-}" ]; then
  echo "Web (Tor):    http://${WEB_ONION}/"
else
  echo "Web (Tor):    <waiting for onion address>"
fi
if [ $PROSODY_INSTALLED -eq 1 ] && [ -n "${XMPP_ONION:-}" ]; then
  echo "XMPP (C2S):   ${XMPP_ONION}:5222"
  echo "XMPP (S2S):   ${XMPP_ONION}:5269"
  echo
  echo "==== XMPP Server Ready ===="
  echo "Admin account created:"
  if [ -f "$STAMPDIR/admin_credentials.txt" ]; then
    cat "$STAMPDIR/admin_credentials.txt"
    echo
    echo "IMPORTANT: Credentials are stored at: $STAMPDIR/admin_credentials.txt"
    echo "To view credentials later: sudo cat $STAMPDIR/admin_credentials.txt"
  else
    echo "ERROR: Admin credentials file not found!"
    echo "Manual admin user creation: prosodyctl adduser admin@$XMPP_ONION"
  fi
  echo
  echo "XMPP Connection (separate .onion):"
  echo "   Server: $XMPP_ONION"
  echo "   Port: 5222"
  echo "   OMEMO encryption: Supported"
  echo "   Use Tor proxy (SOCKS5: 127.0.0.1:9050)"
  echo
  echo "Admin Interface:"
  echo "   Telnet: telnet 127.0.0.1 5582 (from server console)"
  echo "   Command Line: prosodyctl (recommended)"
  echo "   Note: Web admin interface disabled for security"
  echo
  echo "Create additional users: prosodyctl adduser username@$XMPP_ONION"
fi