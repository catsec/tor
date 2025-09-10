#!/bin/bash
#===============================================================================
# Step 3: Installation Verification - Bulletproof Implementation
#===============================================================================
# Purpose: Comprehensive verification of all package installations and service availability
# Features: Individual package verification, service state checking, dependency validation
# Package verification:
#   - openssh-server: SSH daemon service detection and configuration validation
#   - ufw: Firewall binary and service availability
#   - tor: Tor binary, service, and configuration file validation
#   - nyx: Tor monitoring tool availability
#   - nginx: Web server binary and service validation
#   - wireguard: WireGuard tools and kernel module availability
#   - curl: HTTP client for connectivity testing
#   - qrencode: QR code generation tool
#   - cron: Task scheduler service
#   - apparmor: Security framework and utilities
#===============================================================================

# Source utility functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Exit on any error with proper cleanup
set -euo pipefail

# STEP 3: Installation Verification - Bulletproof Version
verify() {
    # Check if previous step requires reboot before proceeding
    check_reboot_required "verify" "3"
    
    echo "Step 3: Comprehensive installation verification..."
    
    local START_TIME=$(date +%s)
    local TEMP_DIR="/tmp/verify_validation_$$"
    local VERIFY_LOG="/tmp/verify_step3_$$.log"
    
    # Cleanup function for errors
    cleanup_verify() {
        local exit_code=$?
        echo "Cleaning up verification artifacts..."
        
        # Clean up temporary files
        rm -rf "$TEMP_DIR" 2>/dev/null || true
        rm -f "$VERIFY_LOG" 2>/dev/null || true
        
        if [[ $exit_code -ne 0 ]]; then
            echo "Verification failed with exit code: $exit_code"
            echo "System state information:"
            echo "  - System load: $(uptime | awk -F'load average:' '{print $2}' || echo 'Unknown')"
            echo "  - Memory usage: $(free -h | awk '/^Mem:/ {print $3 "/" $2}' || echo 'Unknown')"
            echo "  - Disk usage: $(df -h / | awk 'NR==2 {print $5}' || echo 'Unknown')"
            
            if [[ -f "$VERIFY_LOG" ]]; then
                echo "Verification log summary:"
                tail -10 "$VERIFY_LOG" 2>/dev/null || true
            fi
            
            echo "Recommendation: Review package installation in step 2"
        fi
    }
    trap cleanup_verify EXIT
    
    mkdir -p "$TEMP_DIR"
    
    # ---------------------------------------------------------------------
    # 1) Pre-Verification System Check
    # ---------------------------------------------------------------------
    echo "Performing pre-verification system check..."
    
    # Check if we're running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "\033[31mERROR: Verification must be run as root\033[0m" >&2
        exit 1
    fi
    
    # Verify basic system tools are available
    local REQUIRED_SYSTEM_CMDS=("systemctl" "dpkg" "which" "ps" "ss")
    for cmd in "${REQUIRED_SYSTEM_CMDS[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "\033[31mERROR: Required system command '$cmd' not found\033[0m" >&2
            exit 1
        fi
    done
    
    # Check system health indicators
    if ! systemctl is-system-running --quiet 2>/dev/null; then
        local SYSTEM_STATE=$(systemctl is-system-running 2>/dev/null || echo "unknown")
        echo "WARNING: System state: $SYSTEM_STATE (may be normal during startup)"
    fi
    
    echo "Pre-verification system check passed"
    
    # ---------------------------------------------------------------------
    # 2) Package Installation Verification
    # ---------------------------------------------------------------------
    echo "Verifying individual package installations..."
    
    # Define required packages with their validation criteria
    local REQUIRED_VERIFICATIONS=(
        "openssh-server:SSH daemon service:systemctl:sshd ssh openssh-server"
        "ufw:Uncomplicated Firewall:command:ufw"
        "iptables:IPv4 packet filter:command:iptables"
        "nftables:Modern packet filtering:command:nft"
        "tor:Anonymity network daemon:command:tor"
        "nyx:Tor monitoring tool:command:nyx"
        "nginx:Web server:command:nginx"
        "wireguard-tools:WireGuard VPN tools:command:wg"
        "curl:HTTP client:command:curl"
        "qrencode:QR code generator:command:qrencode"
        "cron:Task scheduler:systemctl:cron crond"
        "apparmor:Security framework:command:aa-status"
        "apparmor-utils:AppArmor utilities:command:aa-complain"
        "prosody:XMPP server:command:prosodyctl"
    )
    
    local FAILED_VERIFICATIONS=()
    local PASSED_VERIFICATIONS=()
    
    for verification in "${REQUIRED_VERIFICATIONS[@]}"; do
        local package="${verification%%:*}"
        local temp="${verification#*:}"
        local description="${temp%%:*}"
        temp="${temp#*:}"
        local check_type="${temp%%:*}"
        local check_targets="${temp#*:}"
        
        echo "Verifying: $package ($description)"
        
        case "$check_type" in
            "command")
                local command_found=false
                for cmd in $check_targets; do
                    if command -v "$cmd" &>/dev/null; then
                        command_found=true
                        echo "  [OK] Command available: $cmd"
                        # Additional validation for command functionality
                        case "$cmd" in
                            "ufw")
                                if ufw --version &>/dev/null; then
                                    echo "    [OK] UFW is functional"
                                else
                                    echo "    [WARNING] UFW version check failed"
                                fi
                                ;;
                            "tor")
                                if tor --version &>/dev/null; then
                                    echo "    [OK] Tor is functional"
                                else
                                    echo "    [WARNING] Tor version check failed"
                                fi
                                ;;
                            "nginx")
                                if nginx -t &>/dev/null; then
                                    echo "    [OK] Nginx configuration is valid"
                                else
                                    echo "    [WARNING] Nginx configuration test failed"
                                fi
                                ;;
                            "wg")
                                if wg --version &>/dev/null; then
                                    echo "    [OK] WireGuard is functional"
                                else
                                    echo "    [WARNING] WireGuard version check failed"
                                fi
                                ;;
                            "prosodyctl")
                                if prosodyctl --version &>/dev/null; then
                                    echo "    [OK] Prosody control tool is functional"
                                else
                                    echo "    [WARNING] Prosodyctl version check failed"
                                fi
                                ;;
                            "iptables")
                                if iptables --version &>/dev/null; then
                                    echo "    [OK] iptables is functional"
                                else
                                    echo "    [WARNING] iptables version check failed"
                                fi
                                ;;
                            "nft")
                                if nft --version &>/dev/null; then
                                    echo "    [OK] nftables is functional"
                                else
                                    echo "    [WARNING] nft version check failed"
                                fi
                                ;;
                        esac
                        break
                    fi
                done
                
                if [[ "$command_found" == "true" ]]; then
                    PASSED_VERIFICATIONS+=("$package")
                else
                    FAILED_VERIFICATIONS+=("$package")
                    echo -e "  \033[31m[ERROR] No commands found: $check_targets\033[0m"
                fi
                ;;
                
            "systemctl")
                local service_found=false
                for service in $check_targets; do
                    if systemctl list-unit-files "$service*" &>/dev/null; then
                        service_found=true
                        local service_state=$(systemctl is-enabled "$service" 2>/dev/null || echo "not-found")
                        echo "  [OK] Service available: $service (state: $service_state)"
                        
                        # Check if service can be started (don't actually start it)
                        if systemctl status "$service" &>/dev/null; then
                            local active_state=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
                            echo "    Service status: $active_state"
                        fi
                        break
                    fi
                done
                
                if [[ "$service_found" == "true" ]]; then
                    PASSED_VERIFICATIONS+=("$package")
                else
                    FAILED_VERIFICATIONS+=("$package")
                    echo -e "  \033[31m[ERROR] No services found: $check_targets\033[0m"
                fi
                ;;
        esac
    done
    
    # Report verification results
    echo ""
    echo "Package verification summary:"
    echo "  Passed: ${#PASSED_VERIFICATIONS[@]} packages"
    echo "  Failed: ${#FAILED_VERIFICATIONS[@]} packages"
    
    if [[ ${#FAILED_VERIFICATIONS[@]} -gt 0 ]]; then
        echo ""
        echo "FAILED VERIFICATIONS:"
        for failed in "${FAILED_VERIFICATIONS[@]}"; do
            echo "  - $failed"
        done
        echo ""
        echo -e "\033[31mERROR: Package verification failed for ${#FAILED_VERIFICATIONS[@]} packages\033[0m" >&2
        echo "Please run step 2 (packages) again to fix installation issues" >&2
        exit 1
    fi
    
    echo "All package verifications passed successfully"
    
    # ---------------------------------------------------------------------
    # 3) SSH Service Detection and Validation
    # ---------------------------------------------------------------------
    echo "Performing SSH service detection and validation..."
    
    # Use shared detection function but add comprehensive validation
    local SSH_SERVICE=$(detect_ssh_service)
    
    if [[ -z "$SSH_SERVICE" ]]; then
        echo -e "\033[31mERROR: Could not detect SSH service (tried: ssh, sshd, openssh-server)\033[0m" >&2
        echo "SSH service detection failed - this will prevent SSH hardening" >&2
        exit 1
    fi
    
    echo "SSH service detected: $SSH_SERVICE"
    
    # Validate SSH service functionality
    if systemctl is-enabled "$SSH_SERVICE" &>/dev/null; then
        local ssh_enabled_state=$(systemctl is-enabled "$SSH_SERVICE" 2>/dev/null)
        echo "  [OK] SSH service is enabled: $ssh_enabled_state"
    else
        echo "  [WARNING] SSH service is not enabled (will be enabled in SSH hardening step)"
    fi
    
    # Check SSH configuration file exists
    if [[ -f "/etc/ssh/sshd_config" ]]; then
        echo "  [OK] SSH configuration file exists: /etc/ssh/sshd_config"
        
        # Basic configuration validation
        if sshd -t 2>/dev/null; then
            echo "  [OK] SSH configuration is valid"
        else
            echo "  [WARNING] SSH configuration has issues (will be fixed in hardening)"
        fi
    else
        echo -e "  \033[31m[ERROR] SSH configuration file missing: /etc/ssh/sshd_config\033[0m"
        echo -e "\033[31mERROR: SSH configuration file not found\033[0m" >&2
        exit 1
    fi
    
    # ---------------------------------------------------------------------
    # 4) Service Dependencies and Configuration Files
    # ---------------------------------------------------------------------
    echo "Validating service dependencies and configuration files..."
    
    # Check critical configuration files and directories
    local CONFIG_CHECKS=(
        "/etc/tor:directory:tor configuration directory"
        "/etc/nginx:directory:nginx configuration directory"
        "/usr/share/apparmor:directory:AppArmor profiles directory"
        "/var/log:directory:system log directory"
        "/etc/systemd:directory:systemd configuration directory"
    )
    
    local CONFIG_WARNINGS=()
    
    for check in "${CONFIG_CHECKS[@]}"; do
        local path="${check%%:*}"
        local temp="${check#*:}"
        local type="${temp%%:*}"
        local description="${temp#*:}"
        
        case "$type" in
            "directory")
                if [[ -d "$path" ]]; then
                    echo "  [OK] Found $description: $path"
                else
                    CONFIG_WARNINGS+=("Missing $description: $path")
                    echo "  [WARNING] Missing $description: $path"
                fi
                ;;
            "file")
                if [[ -f "$path" ]]; then
                    echo "  [OK] Found $description: $path"
                else
                    CONFIG_WARNINGS+=("Missing $description: $path")
                    echo "  [WARNING] Missing $description: $path"
                fi
                ;;
        esac
    done
    
    if [[ ${#CONFIG_WARNINGS[@]} -gt 0 ]]; then
        echo ""
        echo "Configuration warnings (${#CONFIG_WARNINGS[@]}):"
        for warning in "${CONFIG_WARNINGS[@]}"; do
            echo "  - $warning"
        done
        echo "These may be resolved in subsequent configuration steps"
    fi
    
    # ---------------------------------------------------------------------
    # 5) Network and Kernel Module Availability
    # ---------------------------------------------------------------------
    echo "Checking network and kernel module availability..."
    
    # Check for WireGuard kernel support
    if modinfo wireguard &>/dev/null; then
        echo "  [OK] WireGuard kernel module available"
    elif [[ -f "/sys/module/wireguard/version" ]]; then
        echo "  [OK] WireGuard kernel module loaded"
    else
        echo "  [WARNING] WireGuard kernel module not found (may need kernel headers)"
    fi
    
    # Check network stack availability
    if [[ -d "/proc/sys/net" ]]; then
        echo "  [OK] Network stack available"
        
        # Check IPv4 forwarding capability
        if [[ -f "/proc/sys/net/ipv4/ip_forward" ]]; then
            echo "  [OK] IPv4 forwarding control available"
        fi
        
        # Check if we can manipulate iptables (needed for UFW)
        if command -v iptables &>/dev/null; then
            echo "  [OK] iptables command available"
        else
            echo "  [WARNING] iptables command not found"
        fi
    else
        echo -e "  \033[31m[ERROR] Network stack not available\033[0m"
        echo -e "\033[31mERROR: Network stack unavailable - VPN and firewall setup will fail\033[0m" >&2
        exit 1
    fi
    
    # ---------------------------------------------------------------------
    # 6) System Resource Validation
    # ---------------------------------------------------------------------
    echo "Validating system resources for service operation..."
    
    # Check available memory (services need sufficient RAM)
    local AVAILABLE_MEM=$(awk '/MemAvailable:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo "0")
    if [[ $AVAILABLE_MEM -gt 256 ]]; then
        echo "  [OK] Sufficient memory available: ${AVAILABLE_MEM}MB"
    else
        echo "  [WARNING] Low memory available: ${AVAILABLE_MEM}MB (may affect service performance)"
    fi
    
    # Check disk space for logs and temporary files
    local AVAILABLE_DISK=$(df /var/log | awk 'NR==2 {print int($4/1024)}' 2>/dev/null || echo "0")
    if [[ $AVAILABLE_DISK -gt 100 ]]; then
        echo "  [OK] Sufficient disk space: ${AVAILABLE_DISK}MB"
    else
        echo "  [WARNING] Low disk space: ${AVAILABLE_DISK}MB (may affect logging)"
    fi
    
    # Check if we can create temporary files
    if touch "$TEMP_DIR/test_write" 2>/dev/null; then
        rm -f "$TEMP_DIR/test_write"
        echo "  [OK] Filesystem write capability confirmed"
    else
        echo -e "  \033[31m[ERROR] Cannot write to temporary directory\033[0m"
        echo -e "\033[31mERROR: Filesystem write issues detected\033[0m" >&2
        exit 1
    fi
    
    local TOTAL_TIME=$(($(date +%s) - START_TIME))
    echo -e "\033[92mVerification completed in ${TOTAL_TIME} seconds\033[0m"
    
    # Check if this step requires a reboot
    check_current_reboot_needed "verify" "3"
    
    mark_step_completed 3
}

# Run the step if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    verify
fi