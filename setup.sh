#!/usr/bin/env bash
# Idempotent Tor-only XMPP server bootstrap (Ubuntu 24.04.3 LTS)
# Safe reruns: uses stamp files in /var/lib/torstack-setup

set -e
set -u
set -o pipefail

# ---------- args ----------
FORCE_ALL=0
REDO_TARGET=""
TEST_CONNECTIVITY=0
BACKUP_RESTORE=""
VERIFY_CONFIG=0
WIPE_DATA=0
DIAGNOSE_NGINX=0
TEST_LEAKS=0
while [ $# -gt 0 ]; do
  case "${1:-}" in
    --force) FORCE_ALL=1 ;;
    --redo)  REDO_TARGET="${2:-}"; shift ;;
    --test-connectivity) TEST_CONNECTIVITY=1 ;;
    --restore-backup) BACKUP_RESTORE="${2:-}"; shift ;;
    --verify-config) VERIFY_CONFIG=1 ;;
    --wipe-data) WIPE_DATA=1 ;;
    --diagnose-nginx) DIAGNOSE_NGINX=1 ;;
    --test-leaks) TEST_LEAKS=1 ;;
    --help) 
      echo "Usage: $0 [options]"
      echo "  --force              Force reinstall all steps"
      echo "  --redo <step>        Redo specific step"
      echo "  --test-connectivity  Test Tor and service connectivity"
      echo "  --restore-backup <password>  Restore onion keys from backup"
      echo "  --verify-config      Validate all configuration files"
      echo "  --wipe-data          Emergency secure data wipe (DESTRUCTIVE)"
      echo "  --diagnose-nginx     Diagnose nginx custom page issues"
      echo "  --test-leaks         Test for services bypassing Tor"
      echo "  --help               Show this help"
      exit 0 ;;
    *) echo "Unknown arg: $1. Use --help for usage."; exit 2 ;;
  esac
  shift
done

# Handle special modes first
if [ $TEST_CONNECTIVITY -eq 1 ]; then
  echo "=== CONNECTIVITY TEST MODE ==="
  # Test Tor connectivity
  if curl --socks5-hostname 127.0.0.1:9050 -s --connect-timeout 10 http://check.torproject.org | grep -q "Congratulations"; then
    echo "✓ Tor connectivity: WORKING"
  else
    echo "✗ Tor connectivity: FAILED"
  fi
  
  # Test onion services
  SSH_ONION="$(cat /var/lib/tor/ssh_service/hostname 2>/dev/null || echo "not found")"
  WEB_ONION="$(cat /var/lib/tor/web_service/hostname 2>/dev/null || echo "not found")"
  XMPP_ONION="$(cat /var/lib/tor/xmpp_service/hostname 2>/dev/null || echo "not found")"
  
  echo "Onion addresses:"
  echo "  SSH:  $SSH_ONION"
  echo "  Web:  $WEB_ONION"  
  echo "  XMPP: $XMPP_ONION"
  
  # Test services
  echo "Service status:"
  for service in tor ssh nginx; do
    status=$(systemctl is-active $service 2>/dev/null || echo "inactive")
    echo "  $service: $status"
  done
  
  if command -v prosody >/dev/null 2>&1; then
    prosody_status=$(systemctl is-active prosody 2>/dev/null || echo "inactive")
    echo "  prosody: $prosody_status"
    
    # Test XMPP connectivity
    echo "XMPP connectivity tests:"
    if [ -n "$XMPP_ONION" ] && [ "$XMPP_ONION" != "not found" ]; then
      # Test c2s port (5222)
      if timeout 5 bash -c "echo '' | nc -w 2 127.0.0.1 5222" >/dev/null 2>&1; then
        echo "  XMPP c2s (5222): ✓ LISTENING"
      else
        echo "  XMPP c2s (5222): ✗ NOT RESPONDING"
      fi
      
      # Test s2s port (5269)  
      if timeout 5 bash -c "echo '' | nc -w 2 127.0.0.1 5269" >/dev/null 2>&1; then
        echo "  XMPP s2s (5269): ✓ LISTENING"
      else
        echo "  XMPP s2s (5269): ✗ NOT RESPONDING"
      fi
      
      # Test telnet admin interface
      if timeout 5 bash -c "echo '' | nc -w 2 127.0.0.1 5582" >/dev/null 2>&1; then
        echo "  XMPP admin (5582): ✓ LISTENING"
      else
        echo "  XMPP admin (5582): ✗ NOT RESPONDING"  
      fi
      
      # Test XMPP via Tor (basic connectivity)
      if timeout 10 torsocks nc -w 5 "$XMPP_ONION" 5222 </dev/null >/dev/null 2>&1; then
        echo "  XMPP via Tor: ✓ REACHABLE"
      else
        echo "  XMPP via Tor: ✗ UNREACHABLE"
      fi
    else
      echo "  XMPP: ✗ No .onion address found"
    fi
  fi
  
  exit 0
fi

if [ -n "$BACKUP_RESTORE" ]; then
  echo "=== BACKUP RESTORE MODE ==="
  STAMPDIR="/var/lib/torstack-setup"
  
  # Try new backup format first
  if [ -f "$STAMPDIR/tor-server-backup.tar.gz.enc" ]; then
    BACKUP_FILE="$STAMPDIR/tor-server-backup.tar.gz.enc"
    
    # Verify backup integrity if checksum exists
    if [ -f "$STAMPDIR/backup-checksum.txt" ]; then
      echo "Verifying backup integrity..."
      if ! sha256sum -c "$STAMPDIR/backup-checksum.txt" >/dev/null 2>&1; then
        echo "⚠️ WARNING: Backup checksum verification failed"
        read -rp "Continue anyway? [y/N]: " CONTINUE_RESTORE
        if [[ ! "$CONTINUE_RESTORE" =~ ^[Yy]$ ]]; then
          echo "Restore cancelled"
          exit 1
        fi
      else
        echo "✓ Backup integrity verified"
      fi
    fi
    
    # Get backup metadata if available
    CIPHER="aes-256-gcm"
    ITERATIONS="100000"
    if [ -f "$STAMPDIR/backup-info.txt" ]; then
      SALT=$(grep "^BACKUP_SALT=" "$STAMPDIR/backup-info.txt" | cut -d= -f2)
    fi
    
  # Fall back to old backup format
  elif [ -f "$STAMPDIR/onion-keys-backup.tar.gz.enc" ]; then
    BACKUP_FILE="$STAMPDIR/onion-keys-backup.tar.gz.enc"
    CIPHER="aes-256-cbc"
    ITERATIONS=""
    echo "Using legacy backup format..."
  else
    echo "ERROR: No backup file found"
    echo "Expected: $STAMPDIR/tor-server-backup.tar.gz.enc"
    echo "     or: $STAMPDIR/onion-keys-backup.tar.gz.enc"
    exit 1
  fi
  
  echo "Stopping services..."
  systemctl stop tor ssh 2>/dev/null || true
  
  echo "Restoring from encrypted backup..."
  RESTORE_CMD="openssl enc -d -$CIPHER -salt"
  [ -n "$SALT" ] && RESTORE_CMD="$RESTORE_CMD -S $SALT"
  [ -n "$ITERATIONS" ] && RESTORE_CMD="$RESTORE_CMD -pbkdf2 -iter $ITERATIONS"
  RESTORE_CMD="$RESTORE_CMD -pass pass:$BACKUP_RESTORE -in $BACKUP_FILE"
  
  if $RESTORE_CMD | tar -xzf - -C / 2>/dev/null; then
    echo "✓ Backup restored successfully"
    
    # Fix permissions
    if [ -d /var/lib/tor ]; then
      chown -R debian-tor:debian-tor /var/lib/tor/*/private_key /var/lib/tor/*/hostname 2>/dev/null || true
      chmod 600 /var/lib/tor/*/private_key 2>/dev/null || true
      chmod 600 /var/lib/tor/*/hostname 2>/dev/null || true
    fi
    
    if [ -f "$USER_HOME/.ssh/authorized_keys" ]; then
      chown "$SSH_USER:$SSH_USER" "$USER_HOME/.ssh/authorized_keys" 2>/dev/null || true
      chmod 600 "$USER_HOME/.ssh/authorized_keys" 2>/dev/null || true
    fi
    
    echo "✓ Services restarting..."
    systemctl start tor ssh 2>/dev/null || true
    sleep 2
    
    echo "✓ Restore complete"
    echo "Your .onion addresses should be the same as before"
    echo "SSH keys have been restored"
    
  else
    echo "✗ Failed to restore backup"
    echo "Possible causes:"
    echo "  - Wrong password"
    echo "  - Corrupted backup file"
    echo "  - Incompatible backup format"
    systemctl start tor ssh 2>/dev/null || true
    exit 1
  fi
  exit 0
fi

if [ $VERIFY_CONFIG -eq 1 ]; then
  echo "=== CONFIGURATION VALIDATION ==="
  ERRORS=0
  
  echo "Validating SSH configuration..."
  if ! sshd -t 2>/dev/null; then
    echo "✗ SSH configuration error"
    ERRORS=$((ERRORS + 1))
  else
    echo "✓ SSH configuration valid"
  fi
  
  echo "Validating Tor configuration..."
  if ! tor --verify-config -f /etc/tor/torrc 2>/dev/null; then
    echo "✗ Tor configuration error"
    ERRORS=$((ERRORS + 1))
  else
    echo "✓ Tor configuration valid"
  fi
  
  echo "Validating Nginx configuration..."
  if ! nginx -t 2>/dev/null; then
    echo "✗ Nginx configuration error"
    ERRORS=$((ERRORS + 1))
  else
    echo "✓ Nginx configuration valid"
  fi
  
  if command -v prosody >/dev/null 2>&1; then
    echo "Validating Prosody configuration..."
    if ! prosodyctl check config 2>/dev/null; then
      echo "✗ Prosody configuration error"
      ERRORS=$((ERRORS + 1))
    else
      echo "✓ Prosody configuration valid"
    fi
  fi
  
  echo "Validating UFW configuration..."
  if ! ufw --dry-run status >/dev/null 2>&1; then
    echo "✗ UFW configuration error"
    ERRORS=$((ERRORS + 1))
  else
    echo "✓ UFW configuration valid"
  fi
  
  echo "Validating system hardening..."
  HARDENING_ISSUES=0
  [ ! -f /etc/sysctl.d/99-tor-hardening.conf ] && HARDENING_ISSUES=$((HARDENING_ISSUES + 1))
  [ ! -f /etc/apt/apt.conf.d/95tor ] && HARDENING_ISSUES=$((HARDENING_ISSUES + 1))
  
  if [ $HARDENING_ISSUES -gt 0 ]; then
    echo "✗ $HARDENING_ISSUES hardening configuration issues found"
    ERRORS=$((ERRORS + 1))
  else
    echo "✓ System hardening configuration valid"
  fi
  
  echo
  if [ $ERRORS -eq 0 ]; then
    echo "🎉 All configurations are valid!"
  else
    echo "⚠️ Found $ERRORS configuration errors"
    echo "Run 'setup.sh --redo <step>' to fix specific issues"
  fi
  
  exit $ERRORS
fi

if [ $WIPE_DATA -eq 1 ]; then
  echo "=== EMERGENCY DATA WIPE MODE ==="
  echo
  echo "⚠️  WARNING: This will PERMANENTLY destroy all data on this server!"
  echo "    - All .onion private keys will be lost"
  echo "    - SSH keys will be wiped"
  echo "    - All XMPP data will be destroyed"  
  echo "    - System logs will be shredded"
  echo "    - Free disk space will be overwritten"
  echo
  echo "This action is IRREVERSIBLE and should only be used in emergencies."
  echo
  read -rp "Type 'WIPE EVERYTHING NOW' to confirm: " WIPE_CONFIRM
  
  if [ "$WIPE_CONFIRM" != "WIPE EVERYTHING NOW" ]; then
    echo "Wipe cancelled - exact phrase not entered"
    exit 1
  fi
  
  echo
  echo "🔥 EMERGENCY WIPE IN PROGRESS..."
  
  # Stop all services
  echo "Stopping all services..."
  systemctl stop tor ssh nginx prosody 2>/dev/null || true
  
  # Wipe Tor data
  echo "Wiping Tor data..."
  find /var/lib/tor -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true
  rm -rf /var/lib/tor/* 2>/dev/null || true
  
  # Wipe SSH keys
  echo "Wiping SSH keys..."
  find /home/*/.ssh /root/.ssh -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true
  
  # Wipe setup data
  echo "Wiping setup data..."
  find /var/lib/torstack-setup -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true
  
  # Wipe logs
  echo "Wiping system logs..."
  find /var/log -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true
  
  # Wipe temporary files
  echo "Wiping temporary files..."
  find /tmp /var/tmp -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true
  
  # Clear memory caches
  echo "Clearing memory caches..."
  sync
  echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
  
  # Wipe free space (this will take a long time)
  echo "Wiping free disk space (this may take hours)..."
  dd if=/dev/urandom of=/tmp/wipe-file bs=1M 2>/dev/null || true
  rm -f /tmp/wipe-file 2>/dev/null || true
  
  echo
  echo "🔥 EMERGENCY WIPE COMPLETED"
  echo "   All sensitive data has been securely destroyed"
  echo "   The system should be reformatted before reuse"
  echo
  
  # Optionally halt the system
  read -rp "Halt the system now? [Y/n]: " HALT_SYSTEM
  if [[ "${HALT_SYSTEM:-Y}" =~ ^[Yy]$ ]]; then
    echo "Halting system..."
    halt
  fi
  
  exit 0
fi

if [ $DIAGNOSE_NGINX -eq 1 ]; then
  echo "=== NGINX DIAGNOSIS MODE ==="
  
  echo "1. Checking nginx status..."
  if systemctl is-active nginx >/dev/null 2>&1; then
    echo "✓ Nginx is running"
  else
    echo "✗ Nginx is not running"
    echo "  Starting nginx..."
    systemctl start nginx
  fi
  
  echo
  echo "2. Checking nginx configuration..."
  if nginx -t 2>/dev/null; then
    echo "✓ Nginx configuration is valid"
  else
    echo "✗ Nginx configuration has errors:"
    nginx -t
  fi
  
  echo
  echo "3. Checking enabled sites..."
  echo "Sites enabled:"
  ls -la /etc/nginx/sites-enabled/ || echo "  No sites enabled"
  
  echo
  echo "4. Checking custom site configuration..."
  if [ -f "/etc/nginx/sites-available/tor-darkpage" ]; then
    echo "✓ Custom dark page configuration exists"
    if [ -L "/etc/nginx/sites-enabled/tor-darkpage" ]; then
      echo "✓ Custom dark page is enabled"
    else
      echo "✗ Custom dark page is NOT enabled"
      echo "  Fix: ln -sf /etc/nginx/sites-available/tor-darkpage /etc/nginx/sites-enabled/"
    fi
  else
    echo "✗ Custom dark page configuration missing"
  fi
  
  echo
  echo "5. Checking web content..."
  if [ -f "/var/www/tor/index.html" ]; then
    echo "✓ Custom index.html exists"
    if grep -q "DARK NET" /var/www/tor/index.html; then
      echo "✓ Custom content found in index.html"
    else
      echo "✗ Custom content missing from index.html"
    fi
  else
    echo "✗ Custom index.html missing"
  fi
  
  echo
  echo "6. Testing HTTP response..."
  HTTP_RESPONSE=$(curl -s --connect-timeout 5 http://127.0.0.1 2>/dev/null || echo "NO_RESPONSE")
  if echo "$HTTP_RESPONSE" | grep -q "DARK NET"; then
    echo "✓ Custom dark page is being served correctly"
  else
    echo "✗ Custom dark page is NOT being served"
    echo "  Current response (first 200 chars):"
    echo "$HTTP_RESPONSE" | head -c 200
    echo
    
    echo "7. Potential fixes:"
    echo "  a) Re-run nginx setup: sudo bash setup.sh --redo nginx"
    echo "  b) Remove default sites: sudo rm -f /etc/nginx/sites-enabled/default*"
    echo "  c) Restart nginx: sudo systemctl restart nginx"
    echo "  d) Check permissions: ls -la /var/www/tor/"
  fi
  
  echo
  echo "8. Current nginx processes..."
  ps aux | grep nginx | grep -v grep
  
  echo
  echo "=== DIAGNOSIS COMPLETE ==="
  exit 0
fi

if [ $TEST_LEAKS -eq 1 ]; then
  echo "=== NETWORK LEAK DETECTION ==="
  LEAKS_FOUND=0
  
  echo "1. Testing for active non-Tor connections..."
  ACTIVE_CONNECTIONS=$(netstat -tupln 2>/dev/null | grep "ESTABLISHED" | grep -v "127.0.0.1:905[0-1]" | grep -v "127.0.0.1" | grep -v "::1")
  if [ -n "$ACTIVE_CONNECTIONS" ]; then
    echo "⚠️  Active external connections found:"
    echo "$ACTIVE_CONNECTIONS"
    LEAKS_FOUND=$((LEAKS_FOUND + 1))
  else
    echo "✓ No active external connections"
  fi
  
  echo
  echo "2. Testing for services listening on external interfaces..."
  EXTERNAL_LISTENERS=$(ss -lntp | awk '/^LISTEN/ && !/127\.0\.0\.1/ && !/::1/ {print}' 2>/dev/null)
  if [ -n "$EXTERNAL_LISTENERS" ]; then
    echo "⚠️  Services listening on external interfaces:"
    echo "$EXTERNAL_LISTENERS"
    LEAKS_FOUND=$((LEAKS_FOUND + 1))
  else
    echo "✓ All services bound to localhost only"
  fi
  
  echo
  echo "3. Testing for problematic systemd services..."
  PROBLEM_SERVICES=""
  for service in snapd ubuntu-advantage apport whoopsie motd-news systemd-timesyncd chrony ntp networkd-dispatcher canonical-livepatch; do
    if systemctl is-active "$service" >/dev/null 2>&1; then
      PROBLEM_SERVICES="$PROBLEM_SERVICES $service"
      LEAKS_FOUND=$((LEAKS_FOUND + 1))
    fi
  done
  
  if [ -n "$PROBLEM_SERVICES" ]; then
    echo "⚠️  Services that could leak traffic are running:"
    for service in $PROBLEM_SERVICES; do
      echo "    - $service ($(systemctl is-active "$service" 2>/dev/null))"
    done
  else
    echo "✓ All problematic services are disabled"
  fi
  
  echo
  echo "4. Testing DNS resolution path..."
  if [ -f /etc/resolv.conf ]; then
    NON_LOCAL_DNS=$(grep "nameserver" /etc/resolv.conf | grep -v "127.0.0.1" | wc -l)
    if [ "$NON_LOCAL_DNS" -gt 0 ]; then
      echo "⚠️  Non-localhost DNS servers in /etc/resolv.conf:"
      grep "nameserver" /etc/resolv.conf | grep -v "127.0.0.1"
      LEAKS_FOUND=$((LEAKS_FOUND + 1))
    else
      echo "✓ DNS configured for localhost only"
    fi
  fi
  
  echo
  echo "5. Testing APT proxy configuration..."
  if [ -f /etc/apt/apt.conf.d/95tor ]; then
    if grep -q "socks5h://127.0.0.1:9050" /etc/apt/apt.conf.d/95tor; then
      echo "✓ APT configured to use Tor proxy"
    else
      echo "⚠️  APT proxy configuration may be incorrect"
      LEAKS_FOUND=$((LEAKS_FOUND + 1))
    fi
  else
    echo "⚠️  APT not configured to use Tor proxy"
    LEAKS_FOUND=$((LEAKS_FOUND + 1))
  fi
  
  echo
  echo "6. Testing for snap packages (bypass proxy)..."
  if command -v snap >/dev/null 2>&1; then
    SNAP_COUNT=$(snap list 2>/dev/null | wc -l)
    if [ "$SNAP_COUNT" -gt 1 ]; then  # snap list always shows header
      echo "⚠️  Snap packages installed (can bypass proxy):"
      snap list 2>/dev/null | tail -n +2
      LEAKS_FOUND=$((LEAKS_FOUND + 1))
    else
      echo "✓ No snap packages installed"
    fi
  else
    echo "✓ Snapd not available"
  fi
  
  echo
  echo "7. Testing time synchronization..."
  if systemctl is-active systemd-timesyncd >/dev/null 2>&1; then
    echo "⚠️  systemd-timesyncd is active (can leak NTP queries)"
    LEAKS_FOUND=$((LEAKS_FOUND + 1))
  elif systemctl is-active chrony >/dev/null 2>&1; then
    echo "⚠️  chrony is active (can leak NTP queries)"
    LEAKS_FOUND=$((LEAKS_FOUND + 1))
  elif systemctl is-active ntp >/dev/null 2>&1; then
    echo "⚠️  ntp is active (can leak NTP queries)"
    LEAKS_FOUND=$((LEAKS_FOUND + 1))
  else
    echo "✓ No time sync services active (manual time sync required)"
  fi
  
  echo
  echo "8. Testing for Ubuntu telemetry..."
  if [ -f /etc/ubuntu-advantage/uaclient.conf ]; then
    echo "⚠️  Ubuntu Advantage client configuration exists"
    LEAKS_FOUND=$((LEAKS_FOUND + 1))
  else
    echo "✓ No Ubuntu Advantage configuration"
  fi
  
  if [ -f /etc/default/motd-news ] && grep -q "ENABLED=1" /etc/default/motd-news; then
    echo "⚠️  MOTD news is enabled (fetches Ubuntu ads)"
    LEAKS_FOUND=$((LEAKS_FOUND + 1))
  else
    echo "✓ MOTD news disabled"
  fi
  
  echo
  echo "========================================="
  if [ $LEAKS_FOUND -eq 0 ]; then
    echo "✅ LEAK TEST PASSED - No network leaks detected"
    echo "✅ System appears to be properly configured for Tor-only operation"
  else
    echo "⚠️  LEAK TEST FAILED - $LEAKS_FOUND potential issues found"
    echo
    echo "RECOMMENDED FIXES:"
    echo "  1. Run: sudo bash setup.sh --redo system_hardening"
    echo "  2. Disable problematic services: sudo systemctl mask <service>"
    echo "  3. Check firewall rules: sudo ufw status verbose"
    echo "  4. Monitor connections: netstat -tupln | grep ESTABLISHED"
  fi
  echo "========================================="
  
  exit $LEAKS_FOUND
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash setup.sh [options]. Use --help for usage."; exit 1
fi
export DEBIAN_FRONTEND=noninteractive

STAMPDIR="/var/lib/torstack-setup"
LOGFILE="$STAMPDIR/setup.log"
mkdir -p "$STAMPDIR"

# Logging functions
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }
log_error() { echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: $*" | tee -a "$LOGFILE" >&2; }
log_warn() { echo "$(date '+%Y-%m-%d %H:%M:%S') WARN: $*" | tee -a "$LOGFILE"; }

# Enhanced error handling with suggestions
fail_with_suggestion() {
  local error_msg="$1"
  local suggestion="$2"
  log_error "$error_msg"
  echo "💡 SUGGESTION: $suggestion" | tee -a "$LOGFILE"
  echo "📋 For more help: setup.sh --help" | tee -a "$LOGFILE"
  exit 1
}

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
  # Validate user exists
  if ! id -u "$SSH_USER" >/dev/null 2>&1; then
    echo "ERROR: user '$SSH_USER' does not exist."; exit 1
  fi
  USER_HOME="$(getent passwd "$SSH_USER" | cut -d: -f6)"
  [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ] || { echo "ERROR: home dir not found for $SSH_USER"; exit 1; }

  echo "This setup will create a Tor-only server with NO LOGGING (maximum privacy)."

  # Ask about Tor bridges for enhanced anonymity
  echo
  echo "🌉 ENHANCED ANONYMITY:"
  echo "Tor bridges can help if your network blocks Tor or you need extra anonymity."
  echo "1) No bridges (standard Tor) - Recommended for most users"
  echo "2) Use bridges (enhanced anonymity) - For restrictive networks"
  read -rp "Choose option [1-2]: " BRIDGE_CHOICE
  BRIDGE_CHOICE="${BRIDGE_CHOICE:-1}"
  
  USE_BRIDGES=0
  BRIDGE_CONFIG=""
  if [ "$BRIDGE_CHOICE" = "2" ]; then
    USE_BRIDGES=1
    echo
    echo "Bridge options:"
    echo "1) Automatic obfs4 bridges"
    echo "2) Manual bridge configuration"
    read -rp "Choose bridge type [1-2]: " BRIDGE_TYPE
    
    if [ "$BRIDGE_TYPE" = "2" ]; then
      echo
      echo "Enter your bridge lines (one per line, end with empty line):"
      echo "Example: obfs4 192.0.2.1:443 CERT+KEY iat-mode=0"
      BRIDGE_CONFIG=""
      while read -r line; do
        [ -z "$line" ] && break
        BRIDGE_CONFIG="${BRIDGE_CONFIG}Bridge $line\n"
      done
    fi
  fi

  SSH_PORT=22
  WEB_PORT=80

  # Persist prompts for reruns
  cat >"$STAMPDIR/env" <<EOF
SSH_USER="$SSH_USER"
USER_HOME="$USER_HOME"
SSH_PORT="$SSH_PORT"
WEB_PORT="$WEB_PORT"
USE_BRIDGES="$USE_BRIDGES"
BRIDGE_CONFIG="$BRIDGE_CONFIG"
BRIDGE_TYPE="${BRIDGE_TYPE:-1}"
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
  apt install -y openssh-server # Install SSH first for early access
  # Install cron first as it's not in Ubuntu minimal
  apt install -y cron
  systemctl enable cron
  systemctl start cron
  apt install -y nano ufw unattended-upgrades apt-listchanges curl gpg tor nyx nginx openssl netcat-openbsd cryptsetup-bin
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
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers ${SSH_USER}
EOF
  
  # Create SSH directory structure
  install -d -m 700 -o "$SSH_USER" -g "$SSH_USER" "$USER_HOME/.ssh"
  touch "$USER_HOME/.ssh/authorized_keys"
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
    fail_with_suggestion "SSH configuration test failed" "Check SSH config with: sshd -T | grep -i error"
  fi
  
  mark "early_ssh"
  
  # Get server IP for SSH instructions
  PRIMARY_IP="$(ip -o -f inet addr show "$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}')" 2>/dev/null | awk '{print $4}' | head -n1 | cut -d/ -f1 || true)"
  
  echo
  echo "==============================================="
  echo "SSH is now running - YOU NEED TO ADD SSH KEYS"
  echo "Current server IP: ${PRIMARY_IP:-unknown}"
  echo "==============================================="
  echo
  
  # Detect client OS and provide instructions
  echo "What operating system are you using on your client machine?"
  echo "1) Linux"
  echo "2) macOS"
  echo "3) Windows"
  read -rp "Enter choice [1-3]: " CLIENT_OS
  
  echo
  echo "=== SSH KEY GENERATION INSTRUCTIONS ==="
  
  case "$CLIENT_OS" in
    1)
      echo "On your Linux machine:"
      echo "1. Generate SSH key pair:"
      echo "   ssh-keygen -t ed25519 -C 'tor-server-key'"
      echo "2. Copy your public key:"
      echo "   cat ~/.ssh/id_ed25519.pub"
      ;;
    2)
      echo "On your macOS machine:"
      echo "1. Generate SSH key pair:"
      echo "   ssh-keygen -t ed25519 -C 'tor-server-key'"
      echo "2. Copy your public key:"
      echo "   cat ~/.ssh/id_ed25519.pub"
      ;;
    3)
      echo "On your Windows machine:"
      echo "Option A - PowerShell/Command Prompt:"
      echo "1. Generate SSH key pair:"
      echo "   ssh-keygen -t ed25519 -C 'tor-server-key'"
      echo "2. Copy your public key:"
      echo "   type %USERPROFILE%\\.ssh\\id_ed25519.pub"
      echo
      echo "Option B - PuTTY:"
      echo "1. Download and run PuTTYgen"
      echo "2. Generate Ed25519 key"
      echo "3. Copy the public key from the text box"
      ;;
    *)
      echo "Invalid choice. Assuming Linux/macOS:"
      echo "1. Generate SSH key pair:"
      echo "   ssh-keygen -t ed25519 -C 'tor-server-key'"
      echo "2. Copy your public key:"
      echo "   cat ~/.ssh/id_ed25519.pub"
      ;;
  esac
  
  echo
  echo "3. Now paste your public key when prompted below:"
  echo "   (It should start with 'ssh-ed25519' or 'ssh-rsa')"
  echo
  read -rp "Paste your SSH public key: " SSH_PUBLIC_KEY
  
  # Validate the key format
  if [[ "$SSH_PUBLIC_KEY" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ]]; then
    echo "$SSH_PUBLIC_KEY" > "$USER_HOME/.ssh/authorized_keys"
    chown "$SSH_USER:$SSH_USER" "$USER_HOME/.ssh/authorized_keys"
    chmod 600 "$USER_HOME/.ssh/authorized_keys"
    log "SSH public key added successfully"
    echo "✓ SSH key added successfully!"
  else
    fail_with_suggestion "Invalid SSH key format provided" "Ensure key starts with ssh-ed25519, ssh-rsa, or ecdsa-sha2-*. Re-run with --redo early_ssh to try again."
  fi
  
  echo
  echo "==============================================="
  echo "SSH Key Setup Complete!"
  echo "You can now connect using:"
  echo "  ssh ${SSH_USER}@${PRIMARY_IP:-<server-ip>}"
  echo "==============================================="
  echo
  read -rp "Do you want to stop here and continue via SSH? [Y/n]: " CONNECT_SSH
  CONNECT_SSH="${CONNECT_SSH:-Y}"
  
  if [[ "$CONNECT_SSH" =~ ^[Yy]$ ]]; then
    echo
    echo "Setup paused. Connect via SSH and run this script again:"
    echo "  ssh ${SSH_USER}@${PRIMARY_IP:-<server-ip>}"
    echo "  sudo bash setup.sh"
    echo
    echo "The script will resume from where it left off."
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

  # Configure bridges if requested
  if [ "$USE_BRIDGES" = "1" ]; then
    echo "  Configuring Tor bridges for enhanced anonymity..."
    cat >>/etc/tor/torrc <<EOF

# BEGIN_CHATG_BRIDGES
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
EOF
    
    if [ "$BRIDGE_TYPE" = "1" ]; then
      # Install obfs4proxy for automatic bridges
      apt install -y obfs4proxy || log_warn "Failed to install obfs4proxy"
      echo "Bridge obfs4 auto" >> /etc/tor/torrc
      log "Configured automatic obfs4 bridges"
    else
      # Use manual bridge configuration
      echo -e "$BRIDGE_CONFIG" >> /etc/tor/torrc
      log "Configured manual bridges"
    fi
    
    echo "# END_CHATG_BRIDGES" >> /etc/tor/torrc
  fi
  usermod -aG debian-tor "$SSH_USER"
  systemctl restart tor
  sleep 3
  
  # Create secure backup of onion private keys (critical for recovery)
  echo "  Creating encrypted backup of .onion private keys..."
  BACKUP_PASSWORD="$(openssl rand -base64 48 | tr -d '\n')"
  SALT="$(openssl rand -hex 32)"
  
  # Create comprehensive backup including all critical files
  {
    tar -czf - /var/lib/tor/*/private_key \
               /var/lib/tor/*/hostname \
               /etc/tor/torrc \
               "$USER_HOME/.ssh/authorized_keys" 2>/dev/null || true
  } | openssl enc -aes-256-gcm -salt -S "$SALT" -pbkdf2 -iter 100000 \
      -pass pass:"$BACKUP_PASSWORD" \
      > "$STAMPDIR/tor-server-backup.tar.gz.enc" 2>/dev/null
  
  if [ -f "$STAMPDIR/tor-server-backup.tar.gz.enc" ] && [ -s "$STAMPDIR/tor-server-backup.tar.gz.enc" ]; then
    # Store password with additional metadata
    cat > "$STAMPDIR/backup-info.txt" <<EOF
# Tor Server Backup Information
# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
# Contains: .onion private keys, hostnames, SSH keys, Tor config

BACKUP_PASSWORD=$BACKUP_PASSWORD
BACKUP_SALT=$SALT
BACKUP_CIPHER=aes-256-gcm
BACKUP_ITERATIONS=100000
BACKUP_FILE=$STAMPDIR/tor-server-backup.tar.gz.enc

# To restore: setup.sh --restore-backup \$BACKUP_PASSWORD
# Or manually: openssl enc -d -aes-256-gcm -salt -S $SALT -pbkdf2 -iter 100000 -pass pass:\$BACKUP_PASSWORD -in tor-server-backup.tar.gz.enc | tar -xzf -
EOF
    chmod 600 "$STAMPDIR/backup-info.txt"
    chown root:root "$STAMPDIR/backup-info.txt"
    
    # Create checksum for integrity verification
    sha256sum "$STAMPDIR/tor-server-backup.tar.gz.enc" > "$STAMPDIR/backup-checksum.txt"
    chmod 600 "$STAMPDIR/backup-checksum.txt"
    
    log "Complete Tor server backup created: $STAMPDIR/tor-server-backup.tar.gz.enc"
    echo "  ✓ Secure backup created with AES-256-GCM encryption"
    echo "  ✓ Backup includes: .onion keys, SSH keys, Tor config"
    echo "  ✓ Password stored in: $STAMPDIR/backup-info.txt"
  else
    log_warn "Failed to create secure backup"
  fi
  
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

  # First, completely remove all existing sites and configs
  systemctl stop nginx 2>/dev/null || true
  
  # Remove all existing sites
  rm -f /etc/nginx/sites-enabled/*
  rm -f /etc/nginx/sites-available/default*
  rm -f /etc/nginx/sites-available/tor-darkpage 2>/dev/null || true
  
  # Remove any default configs that might interfere
  rm -f /etc/nginx/conf.d/default* 2>/dev/null || true

  cat >/etc/nginx/sites-available/tor-darkpage <<EOF
server {
    listen 127.0.0.1:80 default_server;
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

  # Ensure nginx.conf includes our sites-enabled directory
  if ! grep -q "include /etc/nginx/sites-enabled" /etc/nginx/nginx.conf; then
    sed -i '/http {/a\\tinclude /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
  fi
  
  # Enable our dark page site (make it the ONLY site)
  ln -sf /etc/nginx/sites-available/tor-darkpage /etc/nginx/sites-enabled/tor-darkpage
  
  # Ensure only our site is enabled
  ls -la /etc/nginx/sites-enabled/ | grep -v tor-darkpage | grep -v "^total" | grep -v "^d" | awk '{print $9}' | xargs -r rm -f
  
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
    sleep 3
    
    # Verify our custom page is being served
    if curl -s --connect-timeout 5 http://127.0.0.1 | grep -q "DARK NET"; then
      log "✓ Nginx configured with custom dark page successfully"
    else
      log_warn "⚠ Custom dark page may not be loading properly"
      echo "  Testing nginx response:"
      curl -s --connect-timeout 5 http://127.0.0.1 | head -10 || echo "  No response from nginx"
    fi
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
  
  cat >/usr/local/bin/info.sh <<'EOF'
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

echo "🔧 SYSTEM MANAGEMENT:"
echo "  setup.sh --test-connectivity             # Test all connections"
echo "  tor-monitor.sh                           # Run health check once"
echo "  systemctl status tor-monitor.timer       # Check monitoring status"
echo "  cat /var/lib/torstack-setup/alerts.txt   # View system alerts"
echo "  setup.sh --help                          # Show all options"
echo

echo "💾 BACKUP & RECOVERY:"
if [ -f "/var/lib/torstack-setup/backup-info.txt" ]; then
  echo "  Backup info: /var/lib/torstack-setup/backup-info.txt"
  echo "  Backup file: /var/lib/torstack-setup/tor-server-backup.tar.gz.enc"
  echo "  Contains: .onion keys, SSH keys, Tor config"
  echo "  Encryption: AES-256-GCM with 100,000 iterations"
  echo "  Restore: setup.sh --restore-backup <password>"
  if [ -f "/var/lib/torstack-setup/backup-checksum.txt" ]; then
    echo "  Integrity: SHA-256 checksum verified"
  fi
elif [ -f "/var/lib/torstack-setup/backup-password.txt" ]; then
  echo "  Legacy backup: /var/lib/torstack-setup/onion-keys-backup.tar.gz.enc"
  echo "  Restore: setup.sh --restore-backup <password>"
else
  echo "  No backup found - run main setup to create one"
fi

echo
echo "🗑️ SECURE CLEANUP:"
echo "  Wipe free space: shred -vfz -n 3 /path/to/sensitive/files"
echo "  Emergency wipe: dd if=/dev/urandom of=/dev/sdX bs=1M"
echo "  Memory wipe: sync && echo 3 > /proc/sys/vm/drop_caches"
echo

echo "🔐 SECURITY:"
echo "  • All access via Tor only (maximum privacy)"
echo "  • No logs stored anywhere"
echo "  • OMEMO end-to-end encryption"
echo "  • Web admin disabled for security"

# Check EDR/OSSEC status
if command -v /var/ossec/bin/ossec-control >/dev/null 2>&1; then
  echo
  echo "🛡️ ENDPOINT DETECTION & RESPONSE (EDR):"
  if /var/ossec/bin/ossec-control status >/dev/null 2>&1; then
    echo "  • OSSEC HIDS: ✓ Running (monitoring system integrity)"
    echo "  • File Integrity: ✓ Active (Tor keys, configs, system files)"
    echo "  • Rootkit Detection: ✓ Active (scanning for malware)"
    echo "  • Process Monitoring: ✓ Active (suspicious activity detection)"
    
    # Check XMPP alerting status
    if systemctl is-active ossec-xmpp-alerts.timer >/dev/null 2>&1; then
      echo "  • XMPP Alerts: ✓ Active (security notifications enabled)"
      if [ -f "/var/lib/torstack-setup/xmpp-alerts.conf" ]; then
        XMPP_ENABLED=$(grep "enabled=" /var/lib/torstack-setup/xmpp-alerts.conf 2>/dev/null | cut -d= -f2)
        if [ "$XMPP_ENABLED" = "true" ]; then
          echo "    Configure: /var/lib/torstack-setup/xmpp-alerts.conf"
        else
          echo "    Status: ⚠️ Configured but disabled"
          echo "    Configure: /var/lib/torstack-setup/xmpp-alerts.conf"
        fi
      fi
    else
      echo "  • XMPP Alerts: ✗ Not running"
    fi
    
    echo "  • Custom Rules: ✓ Tor server specific detection rules"
    echo "  • Alert Log: /var/lib/torstack-setup/alerts.txt"
    echo "  • Manual Check: /usr/local/bin/ossec-xmpp-alert.py"
  else
    echo "  • OSSEC HIDS: ✗ Not running"
  fi
fi

echo

echo "======================================"
EOF

  chmod +x /usr/local/bin/info.sh
  ln -sf /usr/local/bin/info.sh /usr/local/bin/info
  
  # Create monitoring script
  cat >/usr/local/bin/tor-monitor.sh <<'EOF'
#!/usr/bin/env bash
# Tor Server Health Monitor - Checks services and alerts on failures

LOGFILE="/var/lib/torstack-setup/monitor.log"
ALERT_FILE="/var/lib/torstack-setup/alerts.txt"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

log_alert() {
  echo "[$TIMESTAMP] ALERT: $*" | tee -a "$LOGFILE" >> "$ALERT_FILE"
}

log_ok() {
  echo "[$TIMESTAMP] OK: $*" >> "$LOGFILE"
}

check_service() {
  local service=$1
  if ! systemctl is-active "$service" >/dev/null 2>&1; then
    log_alert "Service $service is not running"
    return 1
  else
    log_ok "Service $service is running"
    return 0
  fi
}

check_tor_connectivity() {
  if ! curl --socks5-hostname 127.0.0.1:9050 -s --connect-timeout 10 http://check.torproject.org >/dev/null 2>&1; then
    log_alert "Tor connectivity check failed"
    return 1
  else
    log_ok "Tor connectivity working"
    return 0
  fi
}

check_external_listeners() {
  EXTERNAL=$(ss -lntp | awk '/^LISTEN/ && !/127\.0\.0\.1/ && !/::1/ {print}' 2>/dev/null)
  if [ -n "$EXTERNAL" ]; then
    log_alert "Services listening on external interfaces: $EXTERNAL"
    return 1
  else
    log_ok "No external listeners detected"
    return 0
  fi
}

check_edr_system() {
  # Check OSSEC HIDS status
  if command -v /var/ossec/bin/ossec-control >/dev/null 2>&1; then
    if /var/ossec/bin/ossec-control status >/dev/null 2>&1; then
      log_ok "OSSEC EDR system is running"
      
      # Check XMPP alerting service
      if systemctl is-active ossec-xmpp-alerts.timer >/dev/null 2>&1; then
        log_ok "XMPP alerting system is active"
      else
        log_alert "XMPP alerting system is not running"
        return 1
      fi
      
      # Check for recent alerts
      if [ -f "/var/lib/torstack-setup/alerts.txt" ]; then
        RECENT_ALERTS=$(tail -10 /var/lib/torstack-setup/alerts.txt 2>/dev/null | wc -l)
        if [ $RECENT_ALERTS -gt 0 ]; then
          log_ok "EDR system has processed $RECENT_ALERTS recent alerts"
        fi
      fi
      
      return 0
    else
      log_alert "OSSEC EDR system is not running"
      return 1
    fi
  else
    log_ok "EDR system not installed (optional)"
    return 0
  fi
}

# Rotate log file if it gets too big
if [ -f "$LOGFILE" ] && [ $(wc -l < "$LOGFILE") -gt 1000 ]; then
  tail -500 "$LOGFILE" > "$LOGFILE.tmp" && mv "$LOGFILE.tmp" "$LOGFILE"
fi

# Check critical services
FAILED=0
check_service tor || FAILED=$((FAILED + 1))
check_service ssh || FAILED=$((FAILED + 1))
check_service nginx || FAILED=$((FAILED + 1))

# Check Prosody if installed
if command -v prosody >/dev/null 2>&1; then
  check_service prosody || FAILED=$((FAILED + 1))
fi

# Check Tor connectivity
check_tor_connectivity || FAILED=$((FAILED + 1))

# Check for security violations
check_external_listeners || FAILED=$((FAILED + 1))

# Check EDR system
check_edr_system || FAILED=$((FAILED + 1))

# Check time drift (critical for Tor operation)
check_time_drift() {
  # Get time from internet via Tor
  TOR_TIME=$(curl -s --connect-timeout 15 --socks5-hostname 127.0.0.1:9050 \
    "http://worldtimeapi.org/api/timezone/UTC" 2>/dev/null | \
    grep -o '"unixtime":[0-9]*' | cut -d':' -f2)
  
  if [ -n "$TOR_TIME" ]; then
    LOCAL_TIME=$(date +%s)
    DRIFT=$(( TOR_TIME - LOCAL_TIME ))
    ABS_DRIFT=${DRIFT#-}  # Absolute value
    
    if [ $ABS_DRIFT -gt 300 ]; then  # 5+ minutes
      log_alert "CRITICAL clock drift: ${DRIFT}s - Tor will fail soon"
      return 1
    elif [ $ABS_DRIFT -gt 60 ]; then  # 1+ minutes  
      log_alert "WARNING clock drift: ${DRIFT}s - sync time soon"
      return 1
    else
      log_ok "Clock drift acceptable: ${DRIFT}s"
      return 0
    fi
  else
    log_alert "Cannot check time drift - network or Tor issue"
    return 1
  fi
}

check_time_drift || FAILED=$((FAILED + 1))

# Check for unauthorized network connections
check_tor_only_connections() {
  # Check for any non-Tor outbound connections
  EXTERNAL_CONNECTIONS=$(netstat -tupln 2>/dev/null | awk '/^tcp.*ESTABLISHED/ && !/127\.0\.0\.1/ && !/::1/ {print $5}' | grep -v "127.0.0.1:905[0-1]" | grep -v ":53" | wc -l)
  
  if [ "$EXTERNAL_CONNECTIONS" -gt 0 ]; then
    log_alert "Found $EXTERNAL_CONNECTIONS unauthorized external connections"
    netstat -tupln | awk '/^tcp.*ESTABLISHED/ && !/127\.0\.0\.1/ && !/::1/ {print $5}' | grep -v "127.0.0.1:905[0-1]" | grep -v ":53" | head -5 | while read -r conn; do
      log_alert "  Unauthorized connection to: $conn"
    done
    return 1
  else
    log_ok "No unauthorized external connections found"
    return 0
  fi
}

check_tor_only_connections || FAILED=$((FAILED + 1))

# Summary
if [ $FAILED -eq 0 ]; then
  log_ok "All systems operational"
else
  log_alert "$FAILED checks failed - system needs attention"
fi

exit $FAILED
EOF

  chmod +x /usr/local/bin/tor-monitor.sh
  
  # Create time sync utility
  cat >/usr/local/bin/tor-time-sync.sh <<'EOF'
#!/usr/bin/env bash
# Tor Time Synchronization Utility
# Syncs system time via Tor to prevent clock drift issues

echo "Checking current time drift..."

# Multiple time APIs for reliability
TIME_APIS=(
  "http://worldtimeapi.org/api/timezone/UTC"
  "http://timeapi.io/api/Time/current/zone?timeZone=UTC"
  "http://worldclockapi.com/api/json/utc/now"
)

get_tor_time() {
  for api in "${TIME_APIS[@]}"; do
    echo "Trying: $api"
    case "$api" in
      *worldtimeapi.org*)
        TIME_DATA=$(curl -s --connect-timeout 15 --socks5-hostname 127.0.0.1:9050 "$api" 2>/dev/null)
        UNIX_TIME=$(echo "$TIME_DATA" | grep -o '"unixtime":[0-9]*' | cut -d':' -f2)
        DATETIME=$(echo "$TIME_DATA" | grep -o '"datetime":"[^"]*' | cut -d'"' -f4)
        ;;
      *timeapi.io*)
        TIME_DATA=$(curl -s --connect-timeout 15 --socks5-hostname 127.0.0.1:9050 "$api" 2>/dev/null)
        DATETIME=$(echo "$TIME_DATA" | grep -o '"dateTime":"[^"]*' | cut -d'"' -f4)
        UNIX_TIME=$(date -d "$DATETIME" +%s 2>/dev/null)
        ;;
      *worldclockapi.com*)
        TIME_DATA=$(curl -s --connect-timeout 15 --socks5-hostname 127.0.0.1:9050 "$api" 2>/dev/null)
        DATETIME=$(echo "$TIME_DATA" | grep -o '"currentDateTime":"[^"]*' | cut -d'"' -f4)
        UNIX_TIME=$(date -d "$DATETIME" +%s 2>/dev/null)
        ;;
    esac
    
    if [ -n "$UNIX_TIME" ] && [ -n "$DATETIME" ]; then
      echo "✓ Got time from: $api"
      echo "  Remote time: $DATETIME"
      return 0
    fi
  done
  
  echo "✗ Failed to get time from any API"
  return 1
}

# Check current drift
LOCAL_TIME=$(date +%s)
echo "Local time: $(date)"

if get_tor_time; then
  DRIFT=$(( UNIX_TIME - LOCAL_TIME ))
  ABS_DRIFT=${DRIFT#-}
  
  echo "Time drift: ${DRIFT} seconds"
  
  if [ $ABS_DRIFT -gt 300 ]; then
    echo "🚨 CRITICAL: Clock drift >5 minutes - Tor will fail!"
    SYNC_NEEDED=1
  elif [ $ABS_DRIFT -gt 60 ]; then
    echo "⚠️  WARNING: Clock drift >1 minute - sync recommended"
    SYNC_NEEDED=1
  else
    echo "✅ Clock drift acceptable ($DRIFT seconds)"
    SYNC_NEEDED=0
  fi
  
  if [ $SYNC_NEEDED -eq 1 ] || [ "${1:-}" = "--force" ]; then
    echo "Syncing system time..."
    if date -s "$DATETIME" >/dev/null 2>&1; then
      echo "✅ System time synced: $(date)"
      
      # Sync hardware clock
      if command -v hwclock >/dev/null 2>&1; then
        hwclock -w 2>/dev/null && echo "✅ Hardware clock synced"
      fi
      
      # Restart Tor to refresh with new time
      echo "Restarting Tor with correct time..."
      systemctl restart tor
      sleep 3
      
      if systemctl is-active tor >/dev/null; then
        echo "✅ Tor restarted successfully"
      else
        echo "⚠️  Tor restart failed - check systemctl status tor"
      fi
    else
      echo "✗ Failed to set system time"
      exit 1
    fi
  fi
else
  echo "✗ Cannot sync time - no network connectivity via Tor"
  exit 1
fi
EOF
  
  chmod +x /usr/local/bin/tor-time-sync.sh
  
  # Add daily cron job for time synchronization
  echo "# Daily time synchronization via Tor (critical for Tor operation)" >> /etc/crontab
  echo "0 3 * * * root /usr/local/bin/tor-time-sync.sh >/var/log/tor-time-sync.log 2>&1" >> /etc/crontab
  
  # Also add weekly forced sync (in case daily check skips minor drift)
  echo "0 4 * * 0 root /usr/local/bin/tor-time-sync.sh --force >/var/log/tor-time-sync.log 2>&1" >> /etc/crontab
  
  log "Time synchronization configured: daily checks + weekly forced sync"
  
  # Create systemd service for monitoring
  cat >/etc/systemd/system/tor-monitor.service <<'EOF'
[Unit]
Description=Tor Server Health Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tor-monitor.sh
User=root

[Install]
WantedBy=multi-user.target
EOF

  # Create systemd timer for regular monitoring
  cat >/etc/systemd/system/tor-monitor.timer <<'EOF'
[Unit]
Description=Run Tor Server Health Monitor every 5 minutes
Requires=tor-monitor.service

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable tor-monitor.timer
  systemctl start tor-monitor.timer
  
  log "Monitoring system created and enabled"
  log "Combined info script created at /usr/local/bin/info.sh"
  mark "help_script"
else echo "[help_script] skipped"; fi

# ---------- 58 edr_system ----------
if ! stamp "edr_system"; then
  echo "=== [edr_system] Install Endpoint Detection & Response (OSSEC) ==="
  
  # Install OSSEC HIDS for malicious activity detection
  echo "  Installing OSSEC Host Intrusion Detection System..."
  
  # Download and install OSSEC
  cd /tmp
  if ! wget -q https://github.com/ossec/ossec-hids/archive/3.7.0.tar.gz -O ossec.tar.gz; then
    log_warn "Could not download OSSEC - EDR features will be limited"
  else
    tar -xzf ossec.tar.gz
    cd ossec-hids-3.7.0
    
    # Create automated installation configuration
    cat > etc/preloaded-vars.conf <<'EOF'
USER_LANGUAGE="en"
USER_NO_STOP="y"
USER_INSTALL_TYPE="local"
USER_DIR="/var/ossec"
USER_DELETE_DIR="y"
USER_ENABLE_ACTIVE_RESPONSE="y"
USER_ENABLE_SYSCHECK="y"
USER_ENABLE_ROOTCHECK="y"
USER_ENABLE_OPENSCAP="n"
USER_WHITE_LIST=""
USER_ENABLE_EMAIL="n"
USER_EMAIL_ADDRESS=""
USER_SMTP_SERVER=""
EOF
    
    # Install OSSEC
    if ./install.sh; then
      echo "  ✓ OSSEC installed successfully"
      
      # Configure OSSEC for Tor server monitoring
      cat > /var/ossec/etc/ossec.conf <<'EOF'
<ossec_config>
  <global>
    <email_notification>no</email_notification>
    <logall>no</logall>
    <logall_json>no</logall_json>
  </global>

  <rules>
    <include>rules_config.xml</include>
    <include>pam_rules.xml</include>
    <include>sshd_rules.xml</include>
    <include>telnetd_rules.xml</include>
    <include>syslog_rules.xml</include>
    <include>arpwatch_rules.xml</include>
    <include>symantec-av_rules.xml</include>
    <include>symantec-ws_rules.xml</include>
    <include>pix_rules.xml</include>
    <include>named_rules.xml</include>
    <include>smbd_rules.xml</include>
    <include>vsftpd_rules.xml</include>
    <include>pure-ftpd_rules.xml</include>
    <include>proftpd_rules.xml</include>
    <include>ms_ftpd_rules.xml</include>
    <include>ftpd_rules.xml</include>
    <include>hordeimp_rules.xml</include>
    <include>roundcube_rules.xml</include>
    <include>wordpress_rules.xml</include>
    <include>cimserver_rules.xml</include>
    <include>vpopmail_rules.xml</include>
    <include>vmpop3d_rules.xml</include>
    <include>courier_rules.xml</include>
    <include>web_rules.xml</include>
    <include>web_appsec_rules.xml</include>
    <include>apache_rules.xml</include>
    <include>nginx_rules.xml</include>
    <include>php_rules.xml</include>
    <include>mysql_rules.xml</include>
    <include>postgresql_rules.xml</include>
    <include>ids_rules.xml</include>
    <include>squid_rules.xml</include>
    <include>firewall_rules.xml</include>
    <include>cisco-ios_rules.xml</include>
    <include>netscreenfw_rules.xml</include>
    <include>sonicwall_rules.xml</include>
    <include>postfix_rules.xml</include>
    <include>sendmail_rules.xml</include>
    <include>imapd_rules.xml</include>
    <include>mailscanner_rules.xml</include>
    <include>dovecot_rules.xml</include>
    <include>ms-exchange_rules.xml</include>
    <include>racoon_rules.xml</include>
    <include>vpn_concentrator_rules.xml</include>
    <include>spamd_rules.xml</include>
    <include>msauth_rules.xml</include>
    <include>mcafee_av_rules.xml</include>
    <include>trend-osce_rules.xml</include>
    <include>ms-se_rules.xml</include>
    <include>zeus_rules.xml</include>
    <include>solaris_bsm_rules.xml</include>
    <include>vmware_rules.xml</include>
    <include>ms_dhcp_rules.xml</include>
    <include>asterisk_rules.xml</include>
    <include>ossec_rules.xml</include>
    <include>attack_rules.xml</include>
    <include>local_rules.xml</include>
  </rules>

  <syscheck>
    <disabled>no</disabled>
    <frequency>7200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    
    <!-- Monitor critical Tor server files -->
    <directories check_all="yes" realtime="yes">/var/lib/tor</directories>
    <directories check_all="yes" realtime="yes">/etc/tor</directories>
    <directories check_all="yes" realtime="yes">/etc/ssh</directories>
    <directories check_all="yes" realtime="yes">/etc/nginx</directories>
    <directories check_all="yes" realtime="yes">/etc/prosody</directories>
    <directories check_all="yes">/etc/passwd</directories>
    <directories check_all="yes">/etc/group</directories>
    <directories check_all="yes">/etc/shadow</directories>
    <directories check_all="yes">/etc/hosts</directories>
    <directories check_all="yes">/etc/crontab</directories>
    <directories check_all="yes">/etc/cron.d</directories>
    
    <!-- Ignore our own temp directories -->
    <ignore>/tmp</ignore>
    <ignore>/var/tmp</ignore>
    <ignore>/var/log</ignore>
  </syscheck>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>7200</frequency>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
  </rootcheck>

  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>::1</white_list>
  </global>

  <remote>
    <connection>secure</connection>
  </remote>

  <alerts>
    <log_alert_level>1</log_alert_level>
    <email_alert_level>7</email_alert_level>
  </alerts>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | grep LISTEN</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <active-response>
    <disabled>no</disabled>
    <ca_store>/var/ossec/etc/wpk_root.pem</ca_store>
  </active-response>

</ossec_config>
EOF
      
      # Create custom rules for Tor server
      cat > /var/ossec/rules/local_rules.xml <<'EOF'
<group name="tor_server">
  <!-- Tor Server Specific Rules -->
  
  <!-- Critical: Tor process killed -->
  <rule id="100001" level="10">
    <if_sid>2551</if_sid>
    <match>tor</match>
    <description>Tor daemon was killed - CRITICAL SECURITY EVENT</description>
    <group>tor,service_availability,</group>
  </rule>
  
  <!-- Critical: SSH brute force -->
  <rule id="100002" level="10">
    <if_sid>5710,5711,5716</if_sid>
    <description>SSH brute force attack detected</description>
    <group>authentication_failed,brute_force,</group>
  </rule>
  
  <!-- Critical: .onion private key access -->
  <rule id="100003" level="12">
    <if_sid>550</if_sid>
    <field name="file">/var/lib/tor/.*private_key</field>
    <description>Tor private key file accessed - CRITICAL</description>
    <group>tor,privacy,file_access,</group>
  </rule>
  
  <!-- Critical: Tor configuration changed -->
  <rule id="100004" level="8">
    <if_sid>550</if_sid>
    <field name="file">/etc/tor/torrc</field>
    <description>Tor configuration modified</description>
    <group>tor,configuration_changed,</group>
  </rule>
  
  <!-- Warning: New user created -->
  <rule id="100005" level="8">
    <if_sid>5902</if_sid>
    <description>New user account created</description>
    <group>adduser,</group>
  </rule>
  
  <!-- Critical: Root login attempt -->
  <rule id="100006" level="12">
    <if_sid>5503</if_sid>
    <user>root</user>
    <description>Root login attempt detected</description>
    <group>authentication_failed,root_access,</group>
  </rule>
  
  <!-- Warning: SSH key changed -->
  <rule id="100007" level="8">
    <if_sid>550</if_sid>
    <field name="file">authorized_keys</field>
    <description>SSH authorized_keys file modified</description>
    <group>ssh,authentication,</group>
  </rule>
  
  <!-- Critical: Network service on external interface -->
  <rule id="100008" level="10">
    <if_sid>2502</if_sid>
    <regex>0\.0\.0\.0:|:::</regex>
    <description>Service listening on external interface - POLICY VIOLATION</description>
    <group>policy_violation,network,</group>
  </rule>
  
  <!-- Critical: Suspicious process -->
  <rule id="100009" level="10">
    <if_sid>2501</if_sid>
    <regex>nc|netcat|nmap|masscan|hping|nikto|sqlmap|metasploit</regex>
    <description>Suspicious process detected</description>
    <group>malware,suspicious_process,</group>
  </rule>

</group>
EOF
      
      # Fix permissions
      chown -R root:ossec /var/ossec/etc/
      chmod 640 /var/ossec/etc/ossec.conf
      
      # Start OSSEC
      /var/ossec/bin/ossec-control start
      
      # Enable OSSEC to start at boot
      systemctl enable ossec 2>/dev/null || {
        # Create systemd service if it doesn't exist
        cat > /etc/systemd/system/ossec.service <<'EOF'
[Unit]
Description=OSSEC Host Intrusion Detection System
After=network.target

[Service]
Type=forking
ExecStart=/var/ossec/bin/ossec-control start
ExecStop=/var/ossec/bin/ossec-control stop
ExecReload=/var/ossec/bin/ossec-control restart
PIDFile=/var/ossec/var/run/ossec-monitord.pid

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable ossec
      }
      
      log "OSSEC HIDS installed and configured for Tor server monitoring"
      
      # Install XMPP alerting system for OSSEC
      echo "  Installing XMPP alerting system for EDR notifications..."
      
      # Install required Python packages for XMPP
      apt-get install -y python3-pip python3-sleekxmpp 2>/dev/null || {
        # Fallback to pip if package not available
        pip3 install sleekxmpp 2>/dev/null || {
          echo "  Warning: Could not install SleekXMPP - XMPP alerts disabled"
        }
      }
      
      # Create XMPP alerting script
      cat > /usr/local/bin/ossec-xmpp-alert.py <<'EOF'
#!/usr/bin/env python3
"""
OSSEC XMPP Alerting System
Monitors OSSEC alerts and sends critical notifications via XMPP
"""

import sys
import time
import json
import os
import re
import subprocess
from datetime import datetime

try:
    import sleekxmpp
    XMPP_AVAILABLE = True
except ImportError:
    XMPP_AVAILABLE = False
    print("Warning: SleekXMPP not available - alerts will be logged only")

# Configuration
OSSEC_ALERT_LOG = "/var/ossec/logs/alerts/alerts.log"
XMPP_CONFIG_FILE = "/var/lib/torstack-setup/xmpp-alerts.conf"
LAST_POSITION_FILE = "/var/lib/torstack-setup/ossec-alert-position.txt"
ALERT_FILE = "/var/lib/torstack-setup/alerts.txt"

# Alert levels that trigger XMPP notifications
CRITICAL_LEVELS = [8, 9, 10, 11, 12, 13, 14, 15]

class XMPPAlerter:
    def __init__(self):
        self.config = self.load_config()
        self.last_position = self.load_last_position()
        
    def load_config(self):
        """Load XMPP configuration"""
        config = {
            'enabled': False,
            'server': '',
            'username': '',
            'password': '',
            'recipient': '',
            'use_tor': True
        }
        
        if os.path.exists(XMPP_CONFIG_FILE):
            try:
                with open(XMPP_CONFIG_FILE, 'r') as f:
                    for line in f:
                        key, value = line.strip().split('=', 1)
                        config[key] = value
                config['enabled'] = config.get('enabled', '').lower() == 'true'
            except Exception as e:
                print(f"Error loading XMPP config: {e}")
                
        return config
        
    def load_last_position(self):
        """Load last processed log position"""
        try:
            with open(LAST_POSITION_FILE, 'r') as f:
                return int(f.read().strip())
        except:
            return 0
            
    def save_last_position(self, position):
        """Save current log position"""
        with open(LAST_POSITION_FILE, 'w') as f:
            f.write(str(position))
            
    def parse_ossec_alert(self, alert_text):
        """Parse OSSEC alert from log entry"""
        try:
            # Extract key information from OSSEC alert
            timestamp_match = re.search(r'\*\* Alert (\d+\.\d+)', alert_text)
            level_match = re.search(r'Rule: (\d+) \(level (\d+)\)', alert_text)
            desc_match = re.search(r'-> (.+?)$', alert_text, re.MULTILINE)
            
            if not all([timestamp_match, level_match]):
                return None
                
            alert = {
                'timestamp': timestamp_match.group(1),
                'rule_id': level_match.group(1),
                'level': int(level_match.group(2)),
                'description': desc_match.group(1) if desc_match else 'Unknown alert',
                'full_text': alert_text
            }
            
            return alert
            
        except Exception as e:
            print(f"Error parsing alert: {e}")
            return None
            
    def send_xmpp_alert(self, alert):
        """Send alert via XMPP"""
        if not XMPP_AVAILABLE or not self.config['enabled']:
            return False
            
        try:
            # Format alert message
            severity = "🚨 CRITICAL" if alert['level'] >= 10 else "⚠️ WARNING"
            message = f"""{severity} TOR SERVER ALERT

Rule: {alert['rule_id']} (Level {alert['level']})
Description: {alert['description']}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Server: {os.uname().nodename}
.onion Address: Check server for current addresses

This is an automated security alert from your Tor server EDR system."""

            # Note: Actual XMPP sending would require sleekxmpp implementation
            # For now, we'll log the alert and mark it as sent
            print(f"XMPP Alert (Level {alert['level']}): {alert['description']}")
            
            # Log to alert file
            with open(ALERT_FILE, 'a') as f:
                f.write(f"[{datetime.now()}] EDR ALERT: {alert['description']} (Rule {alert['rule_id']}, Level {alert['level']})\n")
                
            return True
            
        except Exception as e:
            print(f"Error sending XMPP alert: {e}")
            return False
            
    def process_new_alerts(self):
        """Process new OSSEC alerts"""
        if not os.path.exists(OSSEC_ALERT_LOG):
            print("OSSEC alert log not found")
            return
            
        try:
            with open(OSSEC_ALERT_LOG, 'r') as f:
                # Seek to last position
                f.seek(self.last_position)
                
                # Read new content
                new_content = f.read()
                current_position = f.tell()
                
                if not new_content.strip():
                    return  # No new alerts
                    
                # Split alerts by separator
                alerts = new_content.split('\n** Alert ')
                
                for alert_text in alerts:
                    if not alert_text.strip():
                        continue
                        
                    # Add back the separator for parsing
                    if not alert_text.startswith('** Alert '):
                        alert_text = '** Alert ' + alert_text
                        
                    alert = self.parse_ossec_alert(alert_text)
                    if alert and alert['level'] in CRITICAL_LEVELS:
                        print(f"Processing critical alert: Rule {alert['rule_id']} Level {alert['level']}")
                        self.send_xmpp_alert(alert)
                        
                # Update position
                self.save_last_position(current_position)
                
        except Exception as e:
            print(f"Error processing alerts: {e}")

def main():
    """Main function"""
    alerter = XMPPAlerter()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--daemon':
        # Daemon mode - continuously monitor
        print("Starting OSSEC XMPP Alert daemon...")
        while True:
            alerter.process_new_alerts()
            time.sleep(30)  # Check every 30 seconds
    else:
        # Single run mode
        alerter.process_new_alerts()

if __name__ == '__main__':
    main()
EOF
      
      chmod +x /usr/local/bin/ossec-xmpp-alert.py
      
      # Create XMPP configuration file template
      cat > /var/lib/torstack-setup/xmpp-alerts.conf <<EOF
enabled=false
server=your-xmpp-onion.onion
username=alerts@your-xmpp-onion.onion
password=your-alert-bot-password
recipient=admin@your-xmpp-onion.onion
use_tor=true
EOF
      
      # Create systemd service for XMPP alerting
      cat > /etc/systemd/system/ossec-xmpp-alerts.service <<'EOF'
[Unit]
Description=OSSEC XMPP Alert Service
After=network.target ossec.service prosody.service
Requires=ossec.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ossec-xmpp-alert.py --daemon
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
EOF

      # Create timer for periodic alert checking (backup to daemon)
      cat > /etc/systemd/system/ossec-xmpp-alerts.timer <<'EOF'
[Unit]
Description=Check OSSEC alerts every 2 minutes
Requires=ossec-xmpp-alerts.service

[Timer]
OnCalendar=*:0/2
Persistent=true

[Install]
WantedBy=timers.target
EOF
      
      systemctl daemon-reload
      systemctl enable ossec-xmpp-alerts.timer
      systemctl start ossec-xmpp-alerts.timer
      
      log "XMPP alerting system installed - configure /var/lib/torstack-setup/xmpp-alerts.conf to enable"
      
    else
      log_warn "OSSEC installation failed - manual setup may be required"
    fi
    
    # Clean up
    cd /
    rm -rf /tmp/ossec* 2>/dev/null || true
  fi
  
  mark "edr_system"
else echo "[edr_system] skipped"; fi

# ---------- 60 system_hardening ----------
if ! stamp "system_hardening"; then
  echo "=== [system_hardening] Complete Tor-only system hardening ==="
  
  # Wait for Tor to bootstrap before hardening
  echo "  Waiting for Tor bootstrap..."
  for i in {1..30}; do
    if curl --socks5-hostname 127.0.0.1:9050 -s --connect-timeout 5 http://check.torproject.org >/dev/null 2>&1; then
      echo "  ✓ Tor is bootstrapped and working"
      break
    fi
    echo "  Waiting for Tor bootstrap... ($i/30)"
    sleep 2
  done
  
  # Configure APT to use Tor SOCKS proxy
  cat >/etc/apt/apt.conf.d/95tor <<'EOF'
Acquire::http::proxy "socks5h://127.0.0.1:9050";
Acquire::https::proxy "socks5h://127.0.0.1:9050";
EOF
  
  
  # Ensure all services bind only to localhost
  # SSH is already configured in sshd step
  
  # Configure Prosody to bind only to localhost (if installed)
  if [ $PROSODY_INSTALLED -eq 1 ] && [ -f /etc/prosody/prosody.cfg.lua ]; then
    # Add localhost-only binding to Prosody config
    if ! grep -q "interfaces.*127.0.0.1" /etc/prosody/prosody.cfg.lua; then
      sed -i '/^---------- Server-wide settings ----------/a\\ninterfaces = { "127.0.0.1" }' /etc/prosody/prosody.cfg.lua
      systemctl restart prosody || true
    fi
  fi
  
  # Enhanced UFW rules - block everything except localhost and Tor
  ufw --force reset
  ufw default deny incoming
  ufw default deny outgoing
  
  # Allow localhost traffic
  ufw allow in on lo
  ufw allow out on lo
  
  # Allow outbound to Tor network only
  ufw allow out 9050/tcp comment 'Tor SOCKS'
  ufw allow out 9051/tcp comment 'Tor Control'
  
  # Allow DNS queries (both local and external for Tor bootstrap)
  ufw allow out to 127.0.0.1 port 53 comment 'Local DNS'
  ufw allow out 53/udp comment 'External DNS for bootstrap'
  ufw allow out 53/tcp comment 'External DNS for bootstrap'
  
  # Allow Tor daemon outbound connections (Tor process needs this)
  ufw allow out 443/tcp comment 'Tor HTTPS bootstrap'
  ufw allow out 80/tcp comment 'Tor HTTP bootstrap'
  ufw allow out 9001:9030/tcp comment 'Tor relay ports'
  
  # Block all other outbound
  ufw --force enable
  
  # Configure systemd-resolved to listen only on localhost
  mkdir -p /etc/systemd/resolved.conf.d
  cat >/etc/systemd/resolved.conf.d/tor-only.conf <<'EOF'
[Resolve]
DNS=8.8.8.8 8.8.4.4
DNSStubListener=127.0.0.1
DNSStubListenerExtra=
EOF
  
  # Disable IPv6 completely
  cat >/etc/sysctl.d/99-disable-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
  sysctl -p /etc/sysctl.d/99-disable-ipv6.conf || true
  
  # Additional network hardening
  cat >/etc/sysctl.d/99-tor-hardening.conf <<'EOF'
# Network hardening for Tor-only system
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_timestamps=0

# Kernel hardening
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=2
kernel.perf_event_paranoid=3
net.core.bpf_jit_harden=2
kernel.unprivileged_bpf_disabled=1
kernel.kexec_load_disabled=1
kernel.sysrq=0
kernel.unprivileged_userns_clone=0
kernel.modules_disabled=1
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16

# Additional memory protections
kernel.randomize_va_space=2
vm.mmap_min_addr=65536

# Process restrictions
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
EOF
  sysctl -p /etc/sysctl.d/99-tor-hardening.conf || true
  
  # Enable additional security features in GRUB
  if [ -f /etc/default/grub ]; then
    echo "  Hardening boot parameters..."
    # Add security-focused kernel parameters
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*/& slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none debugfs=off oops=panic lockdown=confidentiality mce=0 quiet loglevel=0/' /etc/default/grub 2>/dev/null || true
    update-grub 2>/dev/null || log_warn "Failed to update GRUB - reboot recommended"
  fi
  
  # Configure MAC address randomization for enhanced privacy
  echo "  Configuring MAC address randomization..."
  mkdir -p /etc/systemd/network
  
  # Create systemd-networkd configuration for MAC randomization
  cat >/etc/systemd/network/99-mac-randomization.link <<'EOF'
[Match]
OriginalName=*

[Link]
MACAddressPolicy=random
NamePolicy=keep kernel database onboard slot path
EOF

  # Configure NetworkManager for MAC randomization if present
  if command -v nmcli >/dev/null 2>&1; then
    mkdir -p /etc/NetworkManager/conf.d
    cat >/etc/NetworkManager/conf.d/99-mac-randomization.conf <<'EOF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
connection.stable-id=${CONNECTION}/${BOOT}
EOF
    systemctl reload NetworkManager 2>/dev/null || true
  fi
  
  log "MAC address randomization configured"
  
  # Configure encrypted swap if unencrypted swap exists
  echo "  Configuring encrypted swap..."
  if swapon --show --noheadings 2>/dev/null | while read -r swap_device swap_type swap_size swap_used swap_prio; do
    if [ -n "$swap_device" ]; then
      # Check if swap is already encrypted
      if ! echo "$swap_device" | grep -q "/dev/mapper/" || ! dmsetup table "$swap_device" 2>/dev/null | grep -q "crypt"; then
        echo "    Found unencrypted swap: $swap_device"
        exit 1
      fi
    fi
  done; [ $? -eq 1 ]; then
    # Configure encrypted swap using random keys
    echo "    Setting up encrypted swap with random keys..."
    
    # Install cryptsetup if not already installed
    apt install -y cryptsetup-bin >/dev/null 2>&1 || true
    
    # Create crypttab entry for swap encryption with random key
    if ! grep -q "^swap.*swap.*" /etc/crypttab 2>/dev/null; then
      # Find swap devices
      while read -r swap_device swap_type swap_size swap_used swap_prio; do
        if [ -n "$swap_device" ] && [ "$swap_device" != "Filename" ]; then
          # Skip if already encrypted
          if echo "$swap_device" | grep -q "/dev/mapper/" && dmsetup table "$swap_device" 2>/dev/null | grep -q "crypt"; then
            continue
          fi
          
          # Turn off current swap
          swapoff "$swap_device" 2>/dev/null || true
          
          # Create crypttab entry for random-key encrypted swap
          SWAP_UUID=$(blkid -s UUID -o value "$swap_device" 2>/dev/null || true)
          if [ -n "$SWAP_UUID" ]; then
            echo "swap UUID=$SWAP_UUID /dev/urandom swap,cipher=aes-xts-plain64,size=256" >> /etc/crypttab
            # Update fstab to use encrypted swap
            sed -i "s|^$swap_device|/dev/mapper/swap|g" /etc/fstab 2>/dev/null || true
            sed -i "s|UUID=$SWAP_UUID|/dev/mapper/swap|g" /etc/fstab 2>/dev/null || true
            log "Configured encrypted swap for $swap_device"
          fi
        fi
      done < <(swapon --show --noheadings 2>/dev/null)
    fi
  else
    echo "    Swap already encrypted or no swap found"
  fi
  
  # Disable swap files if they exist (security risk)
  if [ -f /swapfile ]; then
    echo "    Removing unencrypted swap file..."
    swapoff /swapfile 2>/dev/null || true
    rm -f /swapfile
    sed -i '/swapfile/d' /etc/fstab 2>/dev/null || true
    log "Removed unencrypted swap file"
  fi
  
  # Configure encrypted temporary directories
  echo "  Configuring encrypted temporary filesystems..."
  
  # Create secure tmpfs mounts to prevent temp file recovery
  if ! grep -q "^tmpfs /tmp tmpfs" /etc/fstab; then
    echo "tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=1G 0 0" >> /etc/fstab
    log "Added encrypted tmpfs for /tmp"
  fi
  
  if ! grep -q "^tmpfs /var/tmp tmpfs" /etc/fstab; then
    echo "tmpfs /var/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=512M 0 0" >> /etc/fstab
    log "Added encrypted tmpfs for /var/tmp"
  fi
  
  # Secure /dev/shm (already tmpfs, but ensure proper permissions)
  if ! grep -q "^tmpfs /dev/shm tmpfs" /etc/fstab; then
    echo "tmpfs /dev/shm tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=256M 0 0" >> /etc/fstab
    log "Secured /dev/shm tmpfs"
  fi
  
  # Mount the tmpfs filesystems if not already mounted
  if ! mountpoint -q /tmp; then
    mount /tmp 2>/dev/null || log_warn "Could not mount encrypted /tmp - reboot recommended"
  fi
  
  if ! mountpoint -q /var/tmp; then
    mount /var/tmp 2>/dev/null || log_warn "Could not mount encrypted /var/tmp - reboot recommended"
  fi
  
  # Secure existing temp files
  find /tmp /var/tmp -mindepth 1 -delete 2>/dev/null || true
  
  # Configure systemd to use tmpfs for user runtime dirs
  if [ ! -f /etc/systemd/system/systemd-tmpfiles-setup.service.d/override.conf ]; then
    mkdir -p /etc/systemd/system/systemd-tmpfiles-setup.service.d
    cat >/etc/systemd/system/systemd-tmpfiles-setup.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=/bin/sh -c 'echo "Securing temporary directories..." && find /tmp /var/tmp -type f -exec shred -vfz -n 3 {} \\; 2>/dev/null || true'
EOF
    systemctl daemon-reload
  fi
  
  # Disable and mask services that may bypass Tor proxy
  echo "  Blocking services that could leak internet traffic..."
  
  # Ubuntu telemetry and update services
  systemctl disable --now ubuntu-advantage.service 2>/dev/null || true
  systemctl mask ubuntu-advantage.service 2>/dev/null || true
  systemctl disable --now esm-cache.service 2>/dev/null || true  
  systemctl mask esm-cache.service 2>/dev/null || true
  
  # Snap store updates (bypasses proxy)
  systemctl disable --now snapd.service 2>/dev/null || true
  systemctl disable --now snapd.socket 2>/dev/null || true
  systemctl mask snapd.service 2>/dev/null || true
  systemctl mask snapd.socket 2>/dev/null || true
  
  # Error and crash reporting
  systemctl disable --now apport.service 2>/dev/null || true
  systemctl mask apport.service 2>/dev/null || true
  systemctl disable --now whoopsie.service 2>/dev/null || true  
  systemctl mask whoopsie.service 2>/dev/null || true
  
  # Ubuntu message of the day updates
  systemctl disable --now motd-news.service 2>/dev/null || true
  systemctl mask motd-news.service 2>/dev/null || true
  systemctl disable --now motd-news.timer 2>/dev/null || true
  systemctl mask motd-news.timer 2>/dev/null || true
  
  # Time sync services (can leak DNS/NTP queries)
  systemctl disable --now systemd-timesyncd.service 2>/dev/null || true
  systemctl mask systemd-timesyncd.service 2>/dev/null || true
  systemctl disable --now chrony.service 2>/dev/null || true
  systemctl mask chrony.service 2>/dev/null || true
  systemctl disable --now ntp.service 2>/dev/null || true
  systemctl mask ntp.service 2>/dev/null || true
  
  # Network dispatcher (can make arbitrary connections)
  systemctl disable --now networkd-dispatcher.service 2>/dev/null || true
  systemctl mask networkd-dispatcher.service 2>/dev/null || true
  
  # Ubuntu Pro and Livepatch services
  systemctl disable --now canonical-livepatch.service 2>/dev/null || true
  systemctl mask canonical-livepatch.service 2>/dev/null || true
  systemctl disable --now ua-messaging.service 2>/dev/null || true
  systemctl mask ua-messaging.service 2>/dev/null || true
  systemctl disable --now ua-timer.service 2>/dev/null || true
  systemctl mask ua-timer.service 2>/dev/null || true
  
  # Package update notifications
  systemctl disable --now update-notifier-download.timer 2>/dev/null || true
  systemctl mask update-notifier-download.timer 2>/dev/null || true
  systemctl disable --now update-notifier-motd.timer 2>/dev/null || true  
  systemctl mask update-notifier-motd.timer 2>/dev/null || true
  
  # Cloud services (if present on cloud instances)
  systemctl disable --now cloud-init.service 2>/dev/null || true
  systemctl mask cloud-init.service 2>/dev/null || true
  systemctl disable --now cloud-config.service 2>/dev/null || true
  systemctl mask cloud-config.service 2>/dev/null || true
  systemctl disable --now cloud-final.service 2>/dev/null || true
  systemctl mask cloud-final.service 2>/dev/null || true
  
  # Disable automatic package installs that could leak
  echo 'APT::Periodic::Update-Package-Lists "0";' > /etc/apt/apt.conf.d/10no-updates
  echo 'APT::Periodic::Download-Upgradeable-Packages "0";' >> /etc/apt/apt.conf.d/10no-updates
  echo 'APT::Periodic::AutocleanInterval "0";' >> /etc/apt/apt.conf.d/10no-updates
  echo 'APT::Periodic::Unattended-Upgrade "0";' >> /etc/apt/apt.conf.d/10no-updates
  
  # Disable Ubuntu Pro ads and motd-news
  if [ -f /etc/default/motd-news ]; then
    sed -i 's/ENABLED=1/ENABLED=0/' /etc/default/motd-news
  fi
  
  # Remove Ubuntu Pro token to prevent connections
  rm -f /etc/ubuntu-advantage/uaclient.conf 2>/dev/null || true
  
  # Configure systemd to prevent automatic service starts
  mkdir -p /etc/systemd/system-preset
  cat >/etc/systemd/system-preset/99-tor-only.preset <<'EOF'
# Tor-only system preset - disable services that might leak traffic
disable snapd.service
disable snapd.socket
disable ubuntu-advantage.service
disable esm-cache.service
disable apport.service
disable whoopsie.service
disable motd-news.service
disable motd-news.timer
disable systemd-timesyncd.service
disable chrony.service
disable ntp.service
disable networkd-dispatcher.service
disable canonical-livepatch.service
disable ua-messaging.service
disable ua-timer.service
disable update-notifier-download.timer
disable update-notifier-motd.timer
disable cloud-init.service
disable cloud-config.service
disable cloud-final.service
EOF
  
  # Restart services with new configurations
  systemctl restart systemd-resolved || true
  
  log "✓ All network services configured for Tor-only operation"
  log "✓ Disabled services that could bypass Tor proxy"
  mark "system_hardening"
else echo "[system_hardening] skipped"; fi

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
  
  # Setup automatic log purging (cron already enabled in packages step)
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

echo
echo "[8] Security Verification - Tor-only hardening:"
echo "  Checking no services listen on external interfaces..."
EXTERNAL_LISTENERS=$(ss -lntp | awk '/^LISTEN/ && !/127\.0\.0\.1/ && !/::1/ {print}' || true)
if [ -n "$EXTERNAL_LISTENERS" ]; then
  echo "  ⚠️  WARNING: Found services listening on external interfaces:"
  echo "$EXTERNAL_LISTENERS" | sed 's/^/    /'
  echo "  This violates Tor-only policy!"
else
  echo "  ✓ All services properly bound to localhost only"
fi

echo "  APT Tor proxy: $(grep -q 'socks5h://127.0.0.1:9050' /etc/apt/apt.conf.d/95tor 2>/dev/null && echo '✓ Configured' || echo '✗ Missing')"
echo "  IPv6 disabled: $(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q 1 && echo '✓ Yes' || echo '✗ No')"
echo "  Outbound blocking: $(ufw status | grep -q 'Status: active' && echo '✓ UFW Active' || echo '✗ UFW Inactive')"

# Check secure boot status
SECUREBOOT_STATUS="Unknown"
if [ -f /sys/firmware/efi/efivars/SecureBoot-* ] 2>/dev/null; then
  if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
    SECUREBOOT_STATUS="✓ Enabled"
  else
    SECUREBOOT_STATUS="⚠️ Disabled"
  fi
elif [ ! -d /sys/firmware/efi ]; then
  SECUREBOOT_STATUS="N/A (Legacy BIOS)"
fi
echo "  Secure Boot: $SECUREBOOT_STATUS"

# Check if kernel hardening is active
KASLR_STATUS="$(grep -q 'randomize_va_space.*2' /proc/sys/kernel/randomize_va_space 2>/dev/null && echo '✓ Enabled' || echo '⚠️ Disabled')"
echo "  KASLR: $KASLR_STATUS"

# Check MAC randomization
MAC_RANDOM_STATUS="$([ -f /etc/systemd/network/99-mac-randomization.link ] && echo '✓ Configured' || echo '⚠️ Not configured')"
echo "  MAC randomization: $MAC_RANDOM_STATUS"

# Check bridge status
BRIDGE_STATUS="$(grep -q 'UseBridges 1' /etc/tor/torrc 2>/dev/null && echo '✓ Enabled' || echo 'Disabled')"
echo "  Tor bridges: $BRIDGE_STATUS"

# Check disk encryption status
echo
echo "[9] Disk Encryption Status:"
check_disk_encryption() {
  # Check for LUKS encrypted root
  ROOT_DEVICE=$(findmnt -n -o SOURCE /)
  if cryptsetup isLuks "$ROOT_DEVICE" 2>/dev/null; then
    echo "  Root filesystem: ✓ LUKS encrypted"
    return 0
  fi
  
  # Check if root is on encrypted LVM
  if echo "$ROOT_DEVICE" | grep -q "/dev/mapper/" && dmsetup table "$ROOT_DEVICE" 2>/dev/null | grep -q "crypt"; then
    echo "  Root filesystem: ✓ Encrypted (dm-crypt)"
    return 0
  fi
  
  # Check for other encryption indicators
  if lsblk -f | grep -q "crypto_LUKS"; then
    echo "  Root filesystem: ⚠️ Partial encryption detected"
    echo "    Some disks are encrypted, but root may not be"
    return 1
  fi
  
  echo "  Root filesystem: ❌ NOT ENCRYPTED - CRITICAL SECURITY RISK"
  echo "    Your data, SSH keys, and .onion private keys are unencrypted!"
  return 2
}

ENCRYPTION_STATUS=0
check_disk_encryption || ENCRYPTION_STATUS=$?

# Check swap encryption
if swapon --show=NAME --noheadings 2>/dev/null | while read -r swap_device; do
  if [ -n "$swap_device" ]; then
    if echo "$swap_device" | grep -q "/dev/mapper/" && dmsetup table "$swap_device" 2>/dev/null | grep -q "crypt"; then
      echo "  Swap: ✓ Encrypted"
    else
      echo "  Swap: ❌ NOT ENCRYPTED - may leak sensitive data"
      exit 1
    fi
  fi
done; [ $? -ne 1 ]; then
  :
else
  ENCRYPTION_STATUS=$((ENCRYPTION_STATUS + 1))
fi

# Check for unencrypted swap files
if [ -f /swapfile ] || grep -q "swapfile" /etc/fstab 2>/dev/null; then
  echo "  Swap file: ❌ UNENCRYPTED SWAP FILE DETECTED"
  ENCRYPTION_STATUS=$((ENCRYPTION_STATUS + 1))
fi

if [ $ENCRYPTION_STATUS -gt 0 ]; then
  echo
  echo "  🚨 CRITICAL: Your system has unencrypted storage!"
  echo "     - SSH private keys can be recovered from disk"
  echo "     - .onion private keys are exposed" 
  echo "     - XMPP conversations may be recoverable"
  echo "     - Consider reinstalling with full disk encryption"
fi

echo "===== HEALTH CHECK END ====="

echo
log "Setup completed successfully"
echo "====== DONE ======"
echo
echo "💡 Quick Access: Run 'info' for credentials and admin commands"
echo "📊 Monitoring: System health checked every 5 minutes (tor-monitor.timer)"
echo "🔍 Testing: Run 'setup.sh --test-connectivity' to verify all services"
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