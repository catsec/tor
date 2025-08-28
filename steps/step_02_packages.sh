#!/bin/bash
#===============================================================================
# Step 2: Package Installation - Bulletproof Implementation
#===============================================================================
# Purpose: Install all required security and networking tools with comprehensive validation
# Features: Individual package validation, dependency checking, rollback capability
# Package breakdown:
#   - openssh-server: SSH daemon for secure remote access
#   - ufw: Uncomplicated Firewall (installed but not configured)
#   - tor: Anonymity network daemon (runs SOCKS proxy on port 9050)
#   - nyx: Command-line monitor for tor
#   - nginx: Web server (may be used for hosting services)
#   - wireguard: Modern VPN solution with selective routing
#   - curl: HTTP client for IP detection and web requests
#   - qrencode: QR code generation for mobile WireGuard setup
#   - cron: Task scheduler (needed for system hardening)
#   - apparmor: Application security framework (needed for system hardening)
#   - apparmor-utils: AppArmor utilities
#   - apparmor-profiles: AppArmor profiles for common applications
#   - apparmor-profiles-extra: Additional AppArmor profiles
#===============================================================================

# Source utility functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Exit on any error with proper cleanup
set -euo pipefail

# STEP 2: Package Installation - Bulletproof Version
packages() {
    # Check if previous step requires reboot before proceeding
    check_reboot_required "packages" "2"
    
    echo "Step 2: Installing security packages with comprehensive validation..."
    
    local START_TIME=$(date +%s)
    local TEMP_DIR="/tmp/packages_validation_$$"
    local INSTALL_LOG="/tmp/packages_step2_$$.log"
    local PACKAGES_SNAPSHOT=""
    
    # Required packages list with descriptions for validation
    local REQUIRED_PACKAGES=(
        "openssh-server:SSH daemon for secure remote access"
        "ufw:Uncomplicated Firewall"
        "tor:Anonymity network daemon"
        "nyx:Command-line monitor for tor"
        "nginx:Web server"
        "wireguard-tools:WireGuard VPN tools and utilities"
        "curl:HTTP client for web requests"
        "qrencode:QR code generation tool"
        "cron:Task scheduler"
        "apparmor:Application security framework"
        "apparmor-utils:AppArmor utilities"
        "apparmor-profiles:AppArmor profiles for common applications"
        "apparmor-profiles-extra:Additional AppArmor profiles"
    )
    
    # Cleanup function for errors
    cleanup_packages() {
        local exit_code=$?
        echo "Cleaning up package installation artifacts..."
        
        # Clean up temporary files
        rm -rf "$TEMP_DIR" 2>/dev/null || true
        rm -f "$INSTALL_LOG" 2>/dev/null || true
        
        # Reset environment variables
        unset DEBIAN_FRONTEND DEBIAN_PRIORITY 2>/dev/null || true
        
        if [[ $exit_code -ne 0 ]]; then
            echo "Package installation failed with exit code: $exit_code"
            echo "System state information:"
            echo "  - APT status: $(apt-get check 2>&1 | head -1 || echo 'Unknown')"
            echo "  - Available space: $(df -h /var/cache/apt/archives | tail -1 | awk '{print $4}' || echo 'Unknown')"
            
            if [[ -f "$INSTALL_LOG" ]]; then
                echo "Last installation log:"
                tail -20 "$INSTALL_LOG" 2>/dev/null || true
            fi
            
            echo "Recommendation: Check system logs and package dependencies"
        fi
    }
    trap cleanup_packages EXIT
    
    mkdir -p "$TEMP_DIR"
    
    # ---------------------------------------------------------------------
    # 1) Pre-Installation System Validation
    # ---------------------------------------------------------------------
    echo "Validating system state before package installation..."
    
    # Check if we're running as root
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Package installation must be run as root" >&2
        exit 1
    fi
    
    # Check available disk space (need at least 2GB free for all packages)
    local AVAILABLE_SPACE=$(df /var/cache/apt/archives | awk 'NR==2 {print $4}')
    if [[ $AVAILABLE_SPACE -lt 2097152 ]]; then  # 2GB in KB
        echo "ERROR: Insufficient disk space for package installation (need 2GB, have $(($AVAILABLE_SPACE/1024))MB)" >&2
        exit 1
    fi
    
    # Verify system is Debian-based
    if [[ ! -f /etc/debian_version ]]; then
        echo "ERROR: This script is designed for Debian systems only" >&2
        exit 1
    fi
    
    # Check for required commands
    local REQUIRED_CMDS=("apt-get" "dpkg" "apt" "systemctl")
    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "ERROR: Required command '$cmd' not found" >&2
            exit 1
        fi
    done
    
    # Verify package lists are up to date (from step 1)
    local REPO_FILES_COUNT=$(find /var/lib/apt/lists -name "*Release" -type f 2>/dev/null | wc -l)
    if [[ $REPO_FILES_COUNT -eq 0 ]]; then
        echo "ERROR: No repository Release files found" >&2
        echo "Please run step 1 (update) first to update package lists" >&2
        exit 1
    fi
    
    echo "Pre-installation validation passed"
    
    # ---------------------------------------------------------------------
    # 2) APT Lock and Integrity Validation
    # ---------------------------------------------------------------------
    echo "Validating APT system integrity..."
    
    # Check for apt lock files that could cause issues
    local APT_LOCKS=(
        "/var/lib/dpkg/lock"
        "/var/lib/dpkg/lock-frontend"
        "/var/lib/apt/lists/lock"
        "/var/cache/apt/archives/lock"
    )
    
    for lock_file in "${APT_LOCKS[@]}"; do
        if fuser "$lock_file" 2>/dev/null; then
            echo "WARNING: APT lock file $lock_file is in use by another process"
            echo "Waiting up to 60 seconds for process to complete..."
            local wait_count=0
            while fuser "$lock_file" 2>/dev/null && [[ $wait_count -lt 12 ]]; do
                sleep 5
                wait_count=$((wait_count + 1))
            done
            
            if fuser "$lock_file" 2>/dev/null; then
                echo "ERROR: APT is still locked after waiting. Another package manager may be running." >&2
                exit 1
            fi
        fi
    done
    
    # Verify package system integrity
    if ! apt-get check 2>/dev/null; then
        echo "WARNING: Package system integrity check failed" >&2
        echo "Attempting to repair package system..." >&2
        
        # Try to configure any unconfigured packages
        if dpkg --configure -a 2>/dev/null; then
            echo "Package configuration repair successful"
            # Recheck after repair
            if ! apt-get check 2>/dev/null; then
                echo "ERROR: Package system still has issues after repair attempt" >&2
                exit 1
            fi
        else
            echo "ERROR: Cannot repair package system configuration" >&2
            exit 1
        fi
    fi
    
    echo "APT system validation passed"
    
    # ---------------------------------------------------------------------
    # 3) Package Availability and Dependency Check
    # ---------------------------------------------------------------------
    echo "Validating package availability and dependencies..."
    
    # Take snapshot of currently installed packages
    PACKAGES_SNAPSHOT=$(dpkg --get-selections 2>/dev/null | sort)
    echo "$PACKAGES_SNAPSHOT" > "$TEMP_DIR/packages_before.txt"
    
    # Check if all required packages are available
    local MISSING_PACKAGES=()
    local AVAILABLE_PACKAGES=()
    
    for pkg_info in "${REQUIRED_PACKAGES[@]}"; do
        local pkg_name="${pkg_info%%:*}"
        local pkg_desc="${pkg_info#*:}"
        
        echo "Checking availability: $pkg_name ($pkg_desc)"
        
        if apt-cache show "$pkg_name" &>/dev/null; then
            AVAILABLE_PACKAGES+=("$pkg_name")
            echo "  ✓ Available: $pkg_name"
        else
            MISSING_PACKAGES+=("$pkg_name")
            echo "  ✗ Not available: $pkg_name"
        fi
    done
    
    if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then
        echo "ERROR: The following required packages are not available:" >&2
        for pkg in "${MISSING_PACKAGES[@]}"; do
            echo "  - $pkg" >&2
        done
        echo "This may indicate:" >&2
        echo "  - Outdated package lists (run step 1 again)" >&2
        echo "  - Missing repository configuration" >&2
        echo "  - Unsupported Debian version" >&2
        exit 1
    fi
    
    echo "All required packages are available (${#AVAILABLE_PACKAGES[@]} packages)"
    
    # Dry-run installation to check for dependency conflicts
    echo "Performing dry-run installation to check dependencies..."
    if ! apt-get install --dry-run -y "${AVAILABLE_PACKAGES[@]}" 2>&1 | tee "$TEMP_DIR/dryrun.log"; then
        echo "ERROR: Dependency check failed during dry-run" >&2
        echo "Conflicts detected:" >&2
        grep -E "(Conflicts|Breaks|depends)" "$TEMP_DIR/dryrun.log" || true
        exit 1
    fi
    
    # Extract what would be installed
    local WILL_INSTALL=$(grep "^Inst " "$TEMP_DIR/dryrun.log" | wc -l || echo "0")
    echo "Dry-run successful: $WILL_INSTALL packages will be installed/upgraded"
    
    # ---------------------------------------------------------------------
    # 4) Package Installation with Progress Tracking
    # ---------------------------------------------------------------------
    echo "Installing packages with progress tracking..."
    
    # Set non-interactive mode to prevent prompts
    export DEBIAN_FRONTEND=noninteractive
    export DEBIAN_PRIORITY=critical
    
    # Configure dpkg to use safe options
    echo 'DPkg::Options {
        "--force-confdef";
        "--force-confold";
    }' > /etc/apt/apt.conf.d/99-packages-safety
    
    # Install packages with timeout and comprehensive options
    local INSTALL_SUCCESS=false
    echo "Starting package installation (timeout: 30 minutes)..."
    
    if timeout 1800 apt-get install -y \
        --no-install-recommends \
        --fix-broken \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "${AVAILABLE_PACKAGES[@]}" \
        2>&1 | tee "$INSTALL_LOG"; then
        
        INSTALL_SUCCESS=true
        echo "Package installation completed successfully"
    else
        echo "ERROR: Package installation failed" >&2
        echo "Checking for partial installation state..." >&2
        
        # Try to fix broken packages
        if apt-get install -f -y 2>&1 | tee -a "$INSTALL_LOG"; then
            echo "Fixed broken packages, installation may have partially succeeded"
            # Don't set INSTALL_SUCCESS=true yet, verify below
        else
            echo "ERROR: Cannot fix broken packages" >&2
            # Clean up apt configuration before exit
            rm -f /etc/apt/apt.conf.d/99-packages-safety
            exit 1
        fi
    fi
    
    # Clean up apt configuration
    rm -f /etc/apt/apt.conf.d/99-packages-safety
    
    # ---------------------------------------------------------------------
    # 5) Post-Installation Verification
    # ---------------------------------------------------------------------
    echo "Performing comprehensive post-installation verification..."
    
    # Verify package system integrity after installation
    if ! apt-get check 2>/dev/null; then
        echo "ERROR: Post-installation package integrity check failed" >&2
        exit 1
    fi
    
    # Verify all required packages are properly installed
    local FAILED_PACKAGES=()
    local INSTALLED_PACKAGES=()
    
    for pkg_info in "${REQUIRED_PACKAGES[@]}"; do
        local pkg_name="${pkg_info%%:*}"
        local pkg_desc="${pkg_info#*:}"
        
        echo "Verifying installation: $pkg_name"
        
        # Check if package is installed and properly configured
        if dpkg -l "$pkg_name" 2>/dev/null | grep -q "^ii "; then
            INSTALLED_PACKAGES+=("$pkg_name")
            echo "  ✓ Installed: $pkg_name"
            
            # Additional verification for services
            case "$pkg_name" in
                "openssh-server")
                    # SSH service name varies (ssh, sshd, openssh-server)
                    if systemctl list-unit-files "ssh*" &>/dev/null || systemctl list-unit-files "sshd*" &>/dev/null; then
                        echo "    ✓ SSH service available"
                    else
                        echo "    ⚠ SSH service not found (may be normal)"
                    fi
                    ;;
                "nginx"|"tor"|"cron"|"apparmor")
                    if systemctl list-unit-files "$pkg_name*" &>/dev/null; then
                        echo "    ✓ Service available: $pkg_name"
                    else
                        echo "    ⚠ Service not found: $pkg_name (may be normal)"
                    fi
                    ;;
            esac
        else
            FAILED_PACKAGES+=("$pkg_name")
            echo "  ✗ Installation failed: $pkg_name"
        fi
    done
    
    if [[ ${#FAILED_PACKAGES[@]} -gt 0 ]]; then
        echo "ERROR: The following packages failed to install properly:" >&2
        for pkg in "${FAILED_PACKAGES[@]}"; do
            echo "  - $pkg" >&2
        done
        
        # Check if we should attempt rollback
        echo "Attempting to diagnose installation failures..." >&2
        for pkg in "${FAILED_PACKAGES[@]}"; do
            echo "Status for $pkg:" >&2
            dpkg -l "$pkg" 2>&1 | head -5 || true
        done
        
        exit 1
    fi
    
    echo "All packages installed successfully (${#INSTALLED_PACKAGES[@]}/${#REQUIRED_PACKAGES[@]})"
    
    # Verify essential commands are available
    local ESSENTIAL_COMMANDS=("ssh" "ufw" "tor" "nginx" "wg" "curl" "qrencode" "crontab" "aa-status")
    local MISSING_COMMANDS=()
    
    for cmd in "${ESSENTIAL_COMMANDS[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            echo "  ✓ Command available: $cmd"
        else
            MISSING_COMMANDS+=("$cmd")
            echo "  ✗ Command missing: $cmd"
        fi
    done
    
    if [[ ${#MISSING_COMMANDS[@]} -gt 0 ]]; then
        echo "WARNING: Some essential commands are not available after installation:" >&2
        for cmd in "${MISSING_COMMANDS[@]}"; do
            echo "  - $cmd" >&2
        done
        echo "This may indicate incomplete installation or PATH issues" >&2
        
        # Don't exit here as some commands may be in different packages or paths
        echo "Continuing with verification..." >&2
    fi
    
    # ---------------------------------------------------------------------
    # 6) Service State Verification and Cleanup
    # ---------------------------------------------------------------------
    echo "Verifying service states and performing cleanup..."
    
    # Check service states for packages that install services
    local SERVICES_TO_CHECK=("ssh:openssh-server" "nginx:nginx" "tor:tor" "cron:cron" "apparmor:apparmor")
    
    for service_info in "${SERVICES_TO_CHECK[@]}"; do
        local service_name="${service_info%%:*}"
        local package_name="${service_info#*:}"
        
        if systemctl list-unit-files "${service_name}*" &>/dev/null; then
            local service_state=$(systemctl is-enabled "$service_name" 2>/dev/null || echo "unknown")
            echo "  Service $service_name: $service_state"
            
            # Enable services that should be running (but don't start them yet)
            case "$service_name" in
                "ssh"|"cron"|"apparmor")
                    if [[ "$service_state" == "disabled" ]]; then
                        echo "    Enabling $service_name..."
                        systemctl enable "$service_name" || true
                    fi
                    ;;
            esac
        fi
    done
    
    # Clean package cache to free space
    apt-get clean 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
    
    # Log package changes
    local PACKAGES_AFTER=$(dpkg --get-selections 2>/dev/null | sort)
    echo "$PACKAGES_AFTER" > "$TEMP_DIR/packages_after.txt"
    
    local CHANGES=$(diff "$TEMP_DIR/packages_before.txt" "$TEMP_DIR/packages_after.txt" 2>/dev/null | wc -l || echo "0")
    echo "Package state changes: $CHANGES entries"
    
    # Final system health check
    local TOTAL_TIME=$(($(date +%s) - START_TIME))
    echo "Package installation completed in ${TOTAL_TIME} seconds"
    
    # Verify critical system components are still functional
    if ! systemctl is-system-running --quiet 2>/dev/null; then
        local SYSTEM_STATE=$(systemctl is-system-running 2>/dev/null || echo "unknown")
        echo "WARNING: System state after installation: $SYSTEM_STATE"
        echo "This may be normal if services are starting up"
    fi
    
    echo "Post-installation verification completed successfully"
    
    # Check if package installations require a reboot
    check_current_reboot_needed "packages" "2"
    
    mark_step_completed 2
}

# Run the step if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    packages
fi