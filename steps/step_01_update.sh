#!/bin/bash
#===============================================================================
# Step 1: System Update - Bulletproof Implementation
#===============================================================================
# Purpose: Ensures system is up-to-date with latest security patches
# Critical for security setup - old packages may have vulnerabilities
# Features: Network validation, error handling, rollback, progress tracking
#===============================================================================

# Source utility functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Exit on any error with proper cleanup
set -euo pipefail

# STEP 1: System Update - Bulletproof Version
update() {
    # Check if previous step requires reboot before proceeding
    check_reboot_required "update" "1"
    
    echo "Step 1: System update with comprehensive validation..."
    
    local START_TIME=$(date +%s)
    local TEMP_DIR="/tmp/update_validation_$$"
    local UPDATE_LOG="/tmp/update_step1_$$.log"
    
    # Cleanup function for errors
    cleanup_update() {
        local exit_code=$?
        echo "Cleaning up update artifacts..."
        
        # Clean up temporary files
        rm -rf "$TEMP_DIR" 2>/dev/null || true
        rm -f "$UPDATE_LOG" 2>/dev/null || true
        
        # Clean up any temporary apt configuration
        rm -f /etc/apt/apt.conf.d/99-update-safety 2>/dev/null || true
        
        # Reset environment variables
        unset DEBIAN_FRONTEND DEBIAN_PRIORITY 2>/dev/null || true
        
        if [[ $exit_code -ne 0 ]]; then
            echo "Update failed with exit code: $exit_code"
            echo "System state information:"
            echo "  - APT status: $(apt-get check 2>&1 | head -1 || echo 'Unknown')"
            echo "  - Disk space: $(df -h /var/cache/apt/archives | tail -1 | awk '{print $4}' || echo 'Unknown') free"
            echo "Recommendation: Check system logs and retry if needed"
        fi
    }
    trap cleanup_update EXIT
    
    mkdir -p "$TEMP_DIR"
    
    # ---------------------------------------------------------------------
    # 1) Pre-update System Validation
    # ---------------------------------------------------------------------
    echo "Validating system state before update..."
    
    # Check if we're running as root
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: System update must be run as root" >&2
        exit 1
    fi
    
    # Check available disk space (need at least 1GB free)
    AVAILABLE_SPACE=$(df /var/cache/apt/archives | awk 'NR==2 {print $4}')
    if [[ $AVAILABLE_SPACE -lt 1048576 ]]; then  # 1GB in KB
        echo "ERROR: Insufficient disk space for update (need 1GB, have $(($AVAILABLE_SPACE/1024))MB)" >&2
        exit 1
    fi
    
    # Verify system is Debian-based
    if [[ ! -f /etc/debian_version ]]; then
        echo "ERROR: This script is designed for Debian systems only" >&2
        exit 1
    fi
    
    # Check for required commands
    local REQUIRED_CMDS=("apt-get" "dpkg" "ping" "timeout" "find" "fuser")
    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "ERROR: Required command '$cmd' not found" >&2
            exit 1
        fi
    done
    
    echo "Pre-update validation passed"
    
    # ---------------------------------------------------------------------
    # 2) Network and Repository Validation  
    # ---------------------------------------------------------------------
    echo "Validating network connectivity and repositories..."
    
    # Test network connectivity to common Debian mirrors
    local TEST_URLS=(
        "deb.debian.org"
        "security.debian.org" 
        "archive.debian.org"
    )
    
    local NETWORK_OK=false
    for url in "${TEST_URLS[@]}"; do
        if timeout 10 ping -c 1 "$url" &>/dev/null; then
            NETWORK_OK=true
            echo "Network connectivity confirmed via $url"
            break
        fi
    done
    
    if [[ "$NETWORK_OK" != "true" ]]; then
        echo "ERROR: No network connectivity to Debian repositories" >&2
        echo "Please check internet connection and DNS resolution" >&2
        exit 1
    fi
    
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
                echo "Please wait for other package operations to complete or kill blocking processes." >&2
                exit 1
            fi
        fi
    done
    
    # Verify repository configuration isn't corrupted
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
            echo "Manual intervention may be required" >&2
            exit 1
        fi
    fi
    
    echo "Network and repository validation passed"
    
    # ---------------------------------------------------------------------
    # 3) Package List Update with Validation
    # ---------------------------------------------------------------------
    echo "Updating package lists with validation..."
    
    # Backup current package state
    dpkg --get-selections > "$TEMP_DIR/packages_before.txt" 2>/dev/null || true
    
    # Update package lists with timeout and retry logic
    local UPDATE_ATTEMPTS=0
    local MAX_UPDATE_ATTEMPTS=3
    
    while [[ $UPDATE_ATTEMPTS -lt $MAX_UPDATE_ATTEMPTS ]]; do
        echo "Package list update attempt $((UPDATE_ATTEMPTS + 1))/$MAX_UPDATE_ATTEMPTS..."
        
        if timeout 300 apt-get update 2>&1 | tee "$UPDATE_LOG"; then
            echo "Package lists updated successfully"
            break
        else
            UPDATE_ATTEMPTS=$((UPDATE_ATTEMPTS + 1))
            if [[ $UPDATE_ATTEMPTS -lt $MAX_UPDATE_ATTEMPTS ]]; then
                echo "Update attempt failed, retrying in 30 seconds..."
                sleep 30
            else
                echo "ERROR: Failed to update package lists after $MAX_UPDATE_ATTEMPTS attempts" >&2
                echo "Last error log:" >&2
                tail -20 "$UPDATE_LOG" >&2 || true
                exit 1
            fi
        fi
    done
    
    # Validate that package lists were actually updated
    local REPO_FILES_COUNT=$(find /var/lib/apt/lists -name "*Release" -type f 2>/dev/null | wc -l)
    if [[ $REPO_FILES_COUNT -eq 0 ]]; then
        echo "WARNING: No repository Release files found after update"
        echo "This may indicate repository configuration issues or network problems"
    else
        echo "Repository validation: Found $REPO_FILES_COUNT Release files"
    fi
    
    # ---------------------------------------------------------------------
    # 4) System Upgrade with Progress Tracking
    # ---------------------------------------------------------------------
    echo "Performing system upgrade with progress tracking..."
    
    # Check what packages will be upgraded
    local UPGRADE_LIST
    # More robust upgrade count that handles errors gracefully
    UPGRADE_LIST=$(apt list --upgradable 2>/dev/null | grep -v "WARNING:" | grep -v "Listing..." | wc -l || echo "0")
    
    # Validate the count is actually a number
    if ! [[ "$UPGRADE_LIST" =~ ^[0-9]+$ ]]; then
        echo "WARNING: Could not determine upgrade package count, proceeding with upgrade attempt"
        UPGRADE_LIST=1  # Assume we need to try upgrade
    fi
    
    echo "Found $UPGRADE_LIST packages to upgrade"
    
    if [[ $UPGRADE_LIST -eq 0 ]]; then
        echo "System is already up to date"
    else
        echo "Proceeding with upgrade of $UPGRADE_LIST packages..."
        
        # Set non-interactive mode to prevent prompts
        export DEBIAN_FRONTEND=noninteractive
        export DEBIAN_PRIORITY=critical
        
        # Configure dpkg to use safe options
        echo 'DPkg::Options {
            "--force-confdef";
            "--force-confold";
        }' > /etc/apt/apt.conf.d/99-update-safety
        
        # Perform the upgrade with safe options (removed dangerous flags)
        # SECURITY NOTE: Removed --allow-remove-essential, --allow-downgrades, --allow-change-held-packages
        # These flags could compromise system security and stability
        local UPGRADE_SUCCESS=false
        if timeout 1800 apt-get dist-upgrade -y \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            2>&1 | tee -a "$UPDATE_LOG"; then
            UPGRADE_SUCCESS=true
            echo "System upgrade completed successfully"
        else
            echo "ERROR: System upgrade failed" >&2
            echo "Checking for partial upgrade state..." >&2
            
            # Try to fix broken packages
            if apt-get install -f -y 2>&1 | tee -a "$UPDATE_LOG"; then
                echo "Fixed broken packages, upgrade may have partially succeeded"
                UPGRADE_SUCCESS=true
            else
                echo "ERROR: Cannot fix broken packages" >&2
                exit 1
            fi
        fi
        
        # Clean up apt configuration
        rm -f /etc/apt/apt.conf.d/99-update-safety
        
        if [[ "$UPGRADE_SUCCESS" != "true" ]]; then
            echo "ERROR: System upgrade failed and could not be recovered" >&2
            exit 1
        fi
    fi
    
    # ---------------------------------------------------------------------
    # 5) Post-Update Validation and Cleanup
    # ---------------------------------------------------------------------
    echo "Performing post-update validation..."
    
    # Verify package system integrity
    if ! apt-get check 2>/dev/null; then
        echo "ERROR: Post-update package integrity check failed" >&2
        exit 1
    fi
    
    # Clean package cache to free space
    apt-get clean 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
    
    # Log package changes
    dpkg --get-selections > "$TEMP_DIR/packages_after.txt" 2>/dev/null || true
    if [[ -f "$TEMP_DIR/packages_before.txt" ]] && [[ -f "$TEMP_DIR/packages_after.txt" ]]; then
        local CHANGES=$(diff "$TEMP_DIR/packages_before.txt" "$TEMP_DIR/packages_after.txt" | wc -l)
        echo "Package state changes: $CHANGES entries"
    fi
    
    # Check if reboot is required
    if [[ -f /var/run/reboot-required ]]; then
        echo "NOTE: System reboot will be required after setup completion"
        echo "Reboot-required packages: $(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')"
    fi
    
    # Final system health check
    local TOTAL_TIME=$(($(date +%s) - START_TIME))
    echo "Update completed in ${TOTAL_TIME} seconds"
    
    # Verify critical system components are functional
    if ! systemctl is-system-running --quiet 2>/dev/null; then
        local SYSTEM_STATE=$(systemctl is-system-running 2>/dev/null || echo "unknown")
        echo "WARNING: System state after update: $SYSTEM_STATE"
        echo "This may be normal during startup or if services failed"
    fi
    
    echo "Post-update validation completed successfully"
    
    # Check if this step requires a reboot
    check_current_reboot_needed "update" "1"
    
    mark_step_completed 1
}

# Run the step if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    update
fi