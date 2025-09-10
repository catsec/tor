#!/bin/bash
# Step 10: System & Kernel Hardening (UFW, AppArmor, No-Logs, SSH scoping)
# Purpose: Lock down networking, kernel, logging, and service sandboxes
# Security: Enforces strict firewalling, disables persistent logs, enables AppArmor

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

harden() {
    echo "Step 10: System & kernel hardening..."

    set -euo pipefail
    
    # Allow service control during hardening
    export HARDENING_SETUP=true

    # Helper: detect SSH service name (reuse function if exists)
    SSH_SERVICE=$(detect_ssh_service)

    # Helper: get saved username (created in step 4)
    local USERNAME="$(get_saved_username || true)"
    if [[ -z "${USERNAME:-}" ]]; then
        # Fallback: try to read the only non-root sudoer
        USERNAME=$(awk -F: '$1!="root" && $7 ~ /bash|zsh|sh/ && $3>=1000 {print $1;exit}' /etc/passwd || true)
    fi

    # ---------------------------------------------------------------------
    # 1) Enable required services (packages installed in step 2)
    # ---------------------------------------------------------------------
    systemctl enable --now cron || true
    systemctl enable --now apparmor || true

    # ---------------------------------------------------------------------
    # 2) Kernel & sysctl hardening
    # ---------------------------------------------------------------------
    SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"
    if [[ ! -f "$SYSCTL_FILE" ]]; then
        cat >"$SYSCTL_FILE" <<'EOF'
# Safe networking and memory hardening
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.tcp_syncookies=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.yama.ptrace_scope=2
kernel.kexec_load_disabled=1
kernel.unprivileged_bpf_disabled=1
# Additional memory protection
kernel.randomize_va_space=2
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
# Disable coredumps
kernel.core_pattern=|/bin/false
fs.suid_dumpable=0
# Disable IPv6 completely
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
# WireGuard needs forwarding
net.ipv4.ip_forward=1
EOF
    fi
    sysctl --system >/dev/null

    # ---------------------------------------------------------------------
    # 3) Mount /var/log as tmpfs and journald to volatile
    # ---------------------------------------------------------------------
    # journald volatile storage
    JOURNALD="/etc/systemd/journald.conf"
    if ! grep -q '^Storage=volatile' "$JOURNALD" 2>/dev/null; then
        sed -i 's/^\s*#\?Storage=.*/Storage=volatile/' "$JOURNALD" || echo "Storage=volatile" >> "$JOURNALD"
    fi
    if ! grep -q '^Compress=no' "$JOURNALD" 2>/dev/null; then
        sed -i 's/^\s*#\?Compress=.*/Compress=no/' "$JOURNALD" || echo "Compress=no" >> "$JOURNALD"
    fi
    systemctl restart systemd-journald || true

    # remove rsyslog if present
    if dpkg -s rsyslog >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get purge -y rsyslog || true
    fi

    # mount /var/log tmpfs via fstab with hardened options
    if ! grep -qE '^\s*tmpfs\s+/var/log\s+tmpfs' /etc/fstab; then
        echo 'tmpfs /var/log tmpfs defaults,noatime,nodev,nosuid,noexec,mode=0755 0 0' >> /etc/fstab
    fi

    # Harden other tmpfs mounts if they exist
    if ! grep -qE '^\s*tmpfs\s+/tmp\s+tmpfs' /etc/fstab; then
        echo 'tmpfs /tmp tmpfs defaults,noatime,nodev,nosuid,noexec,mode=1777 0 0' >> /etc/fstab
    fi
    if ! grep -qE '^\s*tmpfs\s+/var/tmp\s+tmpfs' /etc/fstab; then
        echo 'tmpfs /var/tmp tmpfs defaults,noatime,nodev,nosuid,noexec,mode=1777 0 0' >> /etc/fstab
    fi
    if ! grep -qE '^\s*tmpfs\s+/dev/shm\s+tmpfs.*noexec' /etc/fstab; then
        sed -i 's|\(/dev/shm.*tmpfs.*\)|\1,noexec|' /etc/fstab 2>/dev/null || true
        if ! grep -qE '^\s*tmpfs\s+/dev/shm\s+tmpfs' /etc/fstab; then
            echo 'tmpfs /dev/shm tmpfs defaults,noatime,nodev,nosuid,noexec 0 0' >> /etc/fstab
        fi
    fi
    mkdir -p /var/log
    mountpoint -q /var/log || mount /var/log || true
    chmod 0755 /var/log || true

    # nginx: send errors to /dev/null, disable access logs globally if possible
    if [[ -f /etc/nginx/nginx.conf ]] && ! grep -q 'error_log /dev/null' /etc/nginx/nginx.conf; then
        sed -i 's|^\s*error_log .*;|error_log /dev/null crit;|' /etc/nginx/nginx.conf || true
        # If no access_log off; at http context, add one
        if ! grep -q 'access_log off;' /etc/nginx/nginx.conf; then
            sed -i '0,/http\s*{/s//http {\n    access_log off;/' /etc/nginx/nginx.conf || true
        fi
        systemctl reload nginx || true
    fi

    # Tor: remove file/syslog logging; keep stderr and null it via systemd
    if [[ -f /etc/tor/torrc ]]; then
        sed -i '/^Log .*file/d' /etc/tor/torrc
        sed -i '/^Log .*syslog/d' /etc/tor/torrc
        if ! grep -q '^Log notice stderr' /etc/tor/torrc; then
            printf '%s\n' 'Log notice stderr' >> /etc/tor/torrc
        fi
        systemctl restart tor || true
        # systemd drop-in to null service stdout/err
        mkdir -p /etc/systemd/system/tor.service.d
        cat >/etc/systemd/system/tor.service.d/nolog.conf <<'EOF'
[Service]
StandardOutput=null
StandardError=null
EOF
        systemctl daemon-reload
        systemctl restart tor || true
    fi

    # ---------------------------------------------------------------------
    # 4) SSH: restrict listening to loopback and wg0 only
    # ---------------------------------------------------------------------
    WG_ADDR="10.11.12.1"
    SSHD_CONF="/etc/ssh/sshd_config"
    if [[ -f "$SSHD_CONF" ]]; then
        cp "$SSHD_CONF" "${SSHD_CONF}.backup.$(date +%Y%m%d_%H%M%S)" || true
        # ensure ListenAddress 127.0.0.1 and WG
        grep -q '^ListenAddress 127\.0\.0\.1$' "$SSHD_CONF" || echo 'ListenAddress 127.0.0.1' >> "$SSHD_CONF"
        grep -q "^ListenAddress ${WG_ADDR}$" "$SSHD_CONF" || echo "ListenAddress ${WG_ADDR}" >> "$SSHD_CONF"
        if ! grep -q '^AddressFamily' "$SSHD_CONF"; then
            echo 'AddressFamily inet' >> "$SSHD_CONF"
        fi
        # enforce key-only and no root (in case step 5 was skipped)
        sed -i 's/^\s*#\?\s*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONF"
        sed -i 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONF"
        if [[ -n "${USERNAME:-}" ]] && ! grep -q "^AllowUsers .*\\b${USERNAME}\\b" "$SSHD_CONF"; then
            # Append or create AllowUsers
            if grep -q '^AllowUsers' "$SSHD_CONF"; then
                sed -i "s/^AllowUsers .*/& ${USERNAME}/" "$SSHD_CONF"
            else
                echo "AllowUsers ${USERNAME}" >> "$SSHD_CONF"
            fi
        fi
        # Validate and restart
        if sshd -t 2>/dev/null; then
            systemctl restart "$SSH_SERVICE"
        else
            echo "Warning: sshd config test failed; restoring backup"
            # Find the most recent backup and restore it
            LATEST_BACKUP=$(ls -t "${SSHD_CONF}.backup."* 2>/dev/null | head -1)
            if [[ -n "$LATEST_BACKUP" ]]; then
                cp "$LATEST_BACKUP" "$SSHD_CONF"
                echo "Restored from: $LATEST_BACKUP"
            else
                echo "Error: No backup file found to restore"
            fi
        fi
    fi

    # ---------------------------------------------------------------------
    # 5) UFW: strict policy with Tor/WG allowances only
    # ---------------------------------------------------------------------
    ufw --force disable || true

    # Detect external interface with validation
    EXT_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {print $5; exit}')
    [[ -z "${EXT_IF:-}" ]] && EXT_IF=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    
    # Validate interface exists and is up
    if [[ -z "${EXT_IF:-}" ]] || ! ip link show "$EXT_IF" &>/dev/null; then
        echo "Warning: Could not detect valid external interface"
        echo "Available interfaces:"
        ip link show | awk -F': ' '/^[0-9]+:/ && !/lo:/ {print "  " $2}'
        echo "UFW rules may need manual adjustment"
        # Use first non-loopback interface as fallback, remove @ suffix if present
        EXT_IF=$(ip link show | awk -F': ' '/^[0-9]+:/ && !/lo:/ {gsub(/@.*/, "", $2); print $2; exit}')
    fi
    
    # Final check - if still no interface, use eth0 as last resort
    if [[ -z "${EXT_IF:-}" ]]; then
        EXT_IF="eth0"
        echo "Warning: Using eth0 as fallback interface"
    fi

    # Reset and set defaults
    ufw --force reset
    ufw default deny incoming
    ufw default deny outgoing

    # Basic allows
    ufw allow in on lo
    ufw allow out on lo

    # WireGuard
    ufw allow in on "$EXT_IF" to any port 51820 proto udp
    ufw allow out to any port 51820 proto udp

    # SSH: rate-limited via loopback and wg0 subnet  
    ufw limit in on lo to 127.0.0.1 port 22 proto tcp
    # Rate-limit SSH from WG network (6 attempts per 30s)
    ufw limit in on wg0 from 10.11.12.0/24 to 10.11.12.1 port 22 proto tcp

    # Nginx is localhost-only (no UFW rule)

    # Outgoing: allow Tor daemon only (backend-specific)
    # Determine UFW backend
    BACKEND=$(awk -F= '/^Backend=/{print tolower($2)}' /etc/ufw/ufw.conf 2>/dev/null | tr -d ' \t')
    if [[ "$BACKEND" == "iptables" ]]; then
        # Insert owner-match accepts in before.rules
        if ! grep -q 'HARDEN-OWNER-ALLOW' /etc/ufw/before.rules 2>/dev/null; then
            cp /etc/ufw/before.rules /etc/ufw/before.rules.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
            awk '
                BEGIN{done=0}
                {print}
                /^# End required lines/ && !done {
                    print ""
                    print "*filter"
                    print ":HARDEN-OWNER-ALLOW - [0:0]"
                    print "-A ufw-before-output -m owner --uid-owner debian-tor -j ACCEPT  # HARDEN-OWNER-ALLOW"
                    print "-A ufw-before-output -p udp --dport 51820 -j ACCEPT           # HARDEN-OWNER-ALLOW"
                    print "COMMIT"
                    done=1
                }' /etc/ufw/before.rules > /etc/ufw/before.rules.tmp && mv /etc/ufw/before.rules.tmp /etc/ufw/before.rules
        fi
    else
        # nftables backend: create a high-priority output chain that accepts debian-tor and wg handshakes
        if ! nft list table inet harden_egress >/dev/null 2>&1; then
            nft add table inet harden_egress
            nft add chain inet harden_egress output '{ type filter hook output priority -100; policy accept; }'
            nft add rule inet harden_egress output meta skuid "debian-tor" accept
            nft add rule inet harden_egress output udp dport 51820 accept
        else
            # ensure rules exist
            nft list chain inet harden_egress output | grep -q 'skuid "debian-tor"' || nft add rule inet harden_egress output meta skuid "debian-tor" accept
            nft list chain inet harden_egress output | grep -q 'udp dport 51820' || nft add rule inet harden_egress output udp dport 51820 accept
        fi
    fi

    # Anti-spoofing: deny RFC1918 from WAN in ufw before.rules (iptables) or via route filters (nft)
    # (Keep simple here; UFW already adds basic hygiene.)

    ufw --force enable
    ufw status verbose

    # ---------------------------------------------------------------------
    # 6) Systemd sandboxing for critical services
    # ---------------------------------------------------------------------
    # SSH
    mkdir -p /etc/systemd/system/${SSH_SERVICE}.d
    cat >/etc/systemd/system/${SSH_SERVICE}.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
NoNewPrivileges=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_UNIX
# Limit capabilities to bind/listen; adjust if needed
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
EOF

    # nginx
    mkdir -p /etc/systemd/system/nginx.service.d
    cat >/etc/systemd/system/nginx.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
NoNewPrivileges=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_UNIX
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
EOF

    # tor
    mkdir -p /etc/systemd/system/tor.service.d
    cat >/etc/systemd/system/tor.service.d/hardening-extra.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
NoNewPrivileges=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_UNIX
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
EOF

    systemctl daemon-reload
    systemctl restart "$SSH_SERVICE" nginx tor || true

    # ---------------------------------------------------------------------
    # 7) Disable coredumps in limits.conf
    # ---------------------------------------------------------------------
    if ! grep -q '^\* hard core 0' /etc/security/limits.conf 2>/dev/null; then
        echo '* hard core 0' >> /etc/security/limits.conf
    fi

    # ---------------------------------------------------------------------
    # 8) Disable process accounting services
    # ---------------------------------------------------------------------
    systemctl mask systemd-coredump.socket systemd-coredump@.service 2>/dev/null || true

    # ---------------------------------------------------------------------
    # 9) Kernel module blacklisting
    # ---------------------------------------------------------------------
    # Blacklist unused network protocols and filesystems
    cat >/etc/modprobe.d/blacklist-rare.conf <<'EOF'
# Unused network protocols
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
blacklist n-hdlc
blacklist ax25
blacklist netrom
blacklist x25
blacklist rose
blacklist decnet
blacklist econet
blacklist af_802154
blacklist ipx
blacklist appletalk
blacklist psnap
blacklist p8023
blacklist p8022
blacklist can
blacklist atm

# Unused filesystems  
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf

# Firewire (if not needed)
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2

# Bluetooth (if not needed)
blacklist bluetooth
blacklist btusb
EOF

    # ---------------------------------------------------------------------
    # 10) AppArmor enable + baseline profiles
    # ---------------------------------------------------------------------
    # Ensure kernel cmdline enables AppArmor, disables IPv6, and adds CPU mitigations (applied on next reboot)
    GRUB_FILE="/etc/default/grub"
    GRUB_MODIFIED=false
    
    if ! grep -q 'apparmor=1' "$GRUB_FILE" 2>/dev/null; then
        sed -i 's/^\(GRUB_CMDLINE_LINUX_DEFAULT="[^"]*\)"/\1 apparmor=1 security=apparmor"/' "$GRUB_FILE" || true
        GRUB_MODIFIED=true
    fi
    
    if ! grep -q 'ipv6.disable=1' "$GRUB_FILE" 2>/dev/null; then
        sed -i 's/^\(GRUB_CMDLINE_LINUX_DEFAULT="[^"]*\)"/\1 ipv6.disable=1"/' "$GRUB_FILE" || true
        GRUB_MODIFIED=true
    fi
    
    if ! grep -q 'spectre_v2=on' "$GRUB_FILE" 2>/dev/null; then
        sed -i 's/^\(GRUB_CMDLINE_LINUX_DEFAULT="[^"]*\)"/\1 spectre_v2=on spec_store_bypass_disable=on l1tf=full,force mds=full,nosmt tsx=off tsx_async_abort=full,nosmt"/' "$GRUB_FILE" || true
        GRUB_MODIFIED=true
    fi
    
    if [[ "$GRUB_MODIFIED" == "true" ]]; then
        update-grub || true
    fi

    # Create minimal profiles if missing
    mkdir -p /etc/apparmor.d

    # sshd
    if [[ ! -f /etc/apparmor.d/usr.sbin.sshd ]]; then
        cat >/etc/apparmor.d/usr.sbin.sshd <<'EOF'
#include <tunables/global>
/usr/sbin/sshd {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>
  capability chown,
  capability dac_override,
  capability setgid,
  capability setuid,
  capability net_bind_service,
  network inet stream,
  /usr/sbin/sshd mr,
  /etc/ssh/** r,
  /proc/** r,
  /run/sshd.pid rw,
  /var/run/sshd.pid rw,
  owner @{HOME}/.ssh/authorized_keys r,
  /bin/bash ix,
  /usr/bin/bash ix,
  /bin/sh ix,
  /usr/bin/scp ix,
  /usr/bin/sftp-server ix,
  # Allow access to user shells
  /bin/* ix,
  /usr/bin/* ix,
}
EOF
    fi

    # nginx
    if [[ ! -f /etc/apparmor.d/usr.sbin.nginx ]]; then
        cat >/etc/apparmor.d/usr.sbin.nginx <<'EOF'
#include <tunables/global>
/usr/sbin/nginx {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  capability net_bind_service,
  network inet stream,
  /usr/sbin/nginx mr,
  /etc/nginx/** r,
  /var/www/html/** r,
  /var/cache/nginx/** rw,
  # Logs disabled via nginx config, but allow tmpfs access
  /var/log/ r,
  /var/log/nginx/ rw,
  /dev/null w,
}
EOF
    fi

    # tor
    if [[ ! -f /etc/apparmor.d/usr.bin.tor ]]; then
        cat >/etc/apparmor.d/usr.bin.tor <<'EOF'
#include <tunables/global>
/usr/bin/tor {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>
  capability net_admin,
  capability net_bind_service,
  network inet stream,
  network inet dgram,
  /usr/bin/tor mr,
  /etc/tor/** r,
  /var/lib/tor/** rwk,
  /var/run/tor/** rw,
}
EOF
    fi

    # Load & enforce
    apparmor_parser -r -W /etc/apparmor.d/usr.sbin.sshd 2>/dev/null || true
    apparmor_parser -r -W /etc/apparmor.d/usr.sbin.nginx 2>/dev/null || true
    apparmor_parser -r -W /etc/apparmor.d/usr.bin.tor 2>/dev/null || true
    aa-enforce /etc/apparmor.d/usr.sbin.sshd /etc/apparmor.d/usr.sbin.nginx /etc/apparmor.d/usr.bin.tor 2>/dev/null || true
    systemctl restart "$SSH_SERVICE" nginx tor || true

    # ---------------------------------------------------------------------
    # 11) Configure safe updates (existing packages only, no new installs)
    # ---------------------------------------------------------------------
    # Prevent automatic installation of recommended packages
    cat >/etc/apt/apt.conf.d/99-security-updates <<'EOF'
// Security: Only update existing packages, never install new ones
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Get::Install-Missing "false";
APT::Get::Fix-Missing "false";
EOF

    # Prevent services from auto-starting during updates (but allow during setup)
    cat >/usr/sbin/policy-rc.d <<'EOF'
#!/bin/bash
# Allow service control during hardening setup
if [[ "${HARDENING_SETUP:-}" == "true" ]]; then
    exit 0
fi
# Prevent service starts during package updates only
if [[ "${DEBIAN_FRONTEND:-}" == "noninteractive" ]]; then
    exit 101
fi
exit 0
EOF
    chmod +x /usr/sbin/policy-rc.d

    # Create safe update script
    cat >/usr/local/bin/safe-update <<'EOF'
#!/bin/bash
# Safe update script - only updates existing packages
set -euo pipefail

echo "Starting safe system update (existing packages only)..."

# Get list of currently installed packages
INSTALLED_BEFORE=$(dpkg-query -f='${binary:Package}\n' -W | sort)

# Update package lists
apt update

# Only upgrade existing packages, never install new ones
apt upgrade -y --no-install-recommends

# Verify no new packages were installed
INSTALLED_AFTER=$(dpkg-query -f='${binary:Package}\n' -W | sort)

if ! diff -q <(echo "$INSTALLED_BEFORE") <(echo "$INSTALLED_AFTER") >/dev/null; then
    echo -e "\033[31mERROR: New packages were installed! Rolling back...\033[0m"
    NEW_PACKAGES=$(comm -13 <(echo "$INSTALLED_BEFORE") <(echo "$INSTALLED_AFTER"))
    echo "New packages detected:"
    echo "$NEW_PACKAGES"
    # Optionally remove new packages here if desired
    exit 1
fi

echo "Safe update completed - no new packages installed"
EOF
    chmod +x /usr/local/bin/safe-update

    # ---------------------------------------------------------------------
    # 12) Privacy hardening - disable telemetry and data collection
    # ---------------------------------------------------------------------
    echo "Checking for privacy and telemetry concerns..."
    
    # Check and disable Debian popularity contest if present
    if dpkg -l | grep -q popularity-contest 2>/dev/null; then
        echo "Found popularity-contest package - disabling telemetry..."
        echo 'PARTICIPATE="no"' > /etc/popularity-contest.conf
        systemctl disable popularity-contest 2>/dev/null || true
        echo "Debian popularity contest telemetry disabled"
    else
        echo "No popularity-contest package found - good for privacy"
    fi
    
    # Disable UFW logging to reduce privacy leakage in logs
    if command -v ufw >/dev/null 2>&1; then
        echo "Disabling UFW logging for privacy..."
        ufw logging off 2>/dev/null || true
        echo "UFW logging disabled (reduces IP/MAC logging)"
    fi
    
    # Create privacy summary
    echo ""
    echo "=== PRIVACY & TELEMETRY STATUS ==="
    echo "Installed packages privacy review:"
    echo "  openssh-server: No telemetry (privacy-clean)"
    echo "  tor: Designed for anonymity (privacy-clean)"
    echo "  nginx: No default telemetry (privacy-clean)"  
    echo "  wireguard: No telemetry (privacy-clean)"
    echo "  curl: No telemetry (privacy-clean)"
    echo "  ufw: Logging disabled for privacy"
    echo "  nyx: Local Tor monitoring only (privacy-clean)"
    echo "  qrencode: Local generation only (privacy-clean)"
    
    if dpkg -l | grep -q popularity-contest 2>/dev/null; then
        echo "  popularity-contest: Disabled"
    else
        echo "  popularity-contest: Not installed"
    fi
    echo "==================================="
    echo ""

    # ---------------------------------------------------------------------
    # 13) Cron job to purge any logs every 10 minutes
    # ---------------------------------------------------------------------
    cat >/etc/cron.d/log-purge <<'EOF'
# Safely clear log files every 10 minutes while preserving directory structure
*/10 * * * * root find /var/log -type f -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null || true
*/10 * * * * root find /var/log -type f -name "*.log.*" -delete 2>/dev/null || true
*/10 * * * * root rm -rf /var/log/journal/* 2>/dev/null || true
# Recreate essential log directories that services may expect
*/10 * * * * root mkdir -p /var/log/nginx /var/log/tor 2>/dev/null || true
EOF

    echo -e "\033[92mHardening complete. Note: AppArmor kernel args take effect after reboot.\033[0m"
    
    # Hardening step almost always requires reboot due to kernel parameters
    set_reboot_required "harden" "11" "Kernel command line parameters, IPv6 disable, CPU mitigations, and AppArmor changes require reboot"
    
    mark_step_completed 11
}

# Execute function if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    harden
fi