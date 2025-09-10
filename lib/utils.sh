#!/bin/bash
#===============================================================================
# Shared Utility Functions for Debian Security Setup Script
#===============================================================================
# This file contains all utility functions used by the main setup script
# and individual step scripts.
#===============================================================================

# Exit immediately on any error
set -e

# Ensure we're using bash 4+ for associative arrays (on target Debian system)
if [[ ${BASH_VERSION%%.*} -lt 4 ]]; then
    echo "Warning: This script requires bash 4+ for full functionality" >&2
    echo "On Debian systems, this should work correctly" >&2
fi

#===============================================================================
# CONFIGURATION
#===============================================================================

# State file location - stores completed steps and username for persistence
STATUS_FILE="/var/tmp/debian-setup-status"

# Reboot flag file - tracks when system reboot is required
REBOOT_FLAG_FILE="/var/tmp/debian-setup-reboot-required"

#===============================================================================
# UTILITY FUNCTIONS
#===============================================================================

# Convert human-readable step name to numeric ID
get_step_number() {
    local step_name="$1"
    
    # Use case statement for compatibility with older bash versions
    case "$step_name" in
        "update") echo "1" ;;
        "packages") echo "2" ;;
        "verify") echo "3" ;;
        "user") echo "4" ;;
        "ssh") echo "5" ;;
        "verifyssh") echo "6" ;;
        "wireguard") echo "7" ;;
        "tor") echo "8" ;;
        "site") echo "9" ;;
        "harden") echo "10" ;;
        "info") echo "11" ;;
        *)
            echo "Invalid step: $step_name" >&2
            echo "Valid steps: update, packages, verify, user, ssh, verifyssh, wireguard, tor, site, harden, info" >&2
            exit 1
            ;;
    esac
}

# Get the highest completed step number from state file
get_last_completed_step() {
    if [[ -f "$STATUS_FILE" ]]; then
        local status_line=$(cat "$STATUS_FILE")
        echo "${status_line%%:*}"
    else
        echo "0"
    fi
}

# Record completion of a step, optionally with additional data
mark_step_completed() {
    local step_num=$1
    local user_data=${2:-}
    
    if [[ -n "$user_data" ]]; then
        echo "$step_num:$user_data" > "$STATUS_FILE"
    else
        echo "$step_num" > "$STATUS_FILE"
    fi
    
    chmod 644 "$STATUS_FILE" 2>/dev/null || true
    echo -e "\033[92mStep $step_num completed and saved to state file\033[0m"
}

# Extract saved username from state file
get_saved_username() {
    if [[ -f "$STATUS_FILE" ]]; then
        local status_line=$(cat "$STATUS_FILE")
        if [[ "$status_line" == *":"* ]]; then
            echo "${status_line#*:}"
        fi
    fi
}

# Detect SSH service name across different distributions
detect_ssh_service() {
    if systemctl list-unit-files | grep -q "^ssh\.service"; then
        echo "ssh"
    elif systemctl list-unit-files | grep -q "^sshd\.service"; then
        echo "sshd"
    else
        echo ""
    fi
}

# Security check: Verify only expected users exist on the system
check_user_security() {
    local expected_username="$1"
    local warn_only="${2:-true}"
    
    echo "Performing user security check..."
    
    local login_users=()
    while IFS=: read -r username _ uid _ _ _ shell; do
        if [[ "$uid" -eq 0 ]] || [[ "$uid" -ge 1000 ]]; then
            if [[ "$shell" =~ ^/bin/(bash|sh|zsh|dash)$|^/usr/bin/(bash|fish|zsh)$ ]]; then
                login_users+=("$username")
            fi
        fi
    done < /etc/passwd
    
    local expected_users=("root")
    if [[ -n "$expected_username" ]]; then
        expected_users+=("$expected_username")
    fi
    
    local unexpected_users=()
    for user in "${login_users[@]}"; do
        local is_expected=false
        for expected in "${expected_users[@]}"; do
            if [[ "$user" == "$expected" ]]; then
                is_expected=true
                break
            fi
        done
        if ! $is_expected; then
            unexpected_users+=("$user")
        fi
    done
    
    if [[ ${#unexpected_users[@]} -eq 0 ]]; then
        echo "User security check passed: Only expected users found"
        echo "  Login-capable users: ${login_users[*]}"
    else
        echo "WARNING: Unexpected users detected on system!"
        echo "  Expected users: ${expected_users[*]}"
        echo "  All login users: ${login_users[*]}"
        echo "  Unexpected users: ${unexpected_users[*]}"
        echo ""
        echo "SECURITY ALERT: These additional users could indicate:"
        echo "  - System compromise or unauthorized access"
        echo "  - Default accounts not removed during setup"
        echo "  - Additional users created outside this script"
        echo ""
        echo "Please verify these accounts are legitimate and remove if necessary:"
        for user in "${unexpected_users[@]}"; do
            echo "  sudo userdel -r $user  # Remove user and home directory"
        done
        echo ""
        
        if [[ "$warn_only" != "true" ]]; then
            echo "Stopping execution due to user security concern."
            exit 1
        else
            read -p "Continue anyway? (yes/no): " continue_choice
            if [[ "$continue_choice" != "yes" ]]; then
                echo "Script stopped by user due to security concern."
                exit 0
            fi
        fi
    fi
}

# Determines if a step should run based on current state and command arguments
should_run_step() {
    local step_num=$1
    local last_completed=$(get_last_completed_step)
    
    # FORCE MODE: Execute specific step (--step argument)
    if [[ -n "$FORCE_STEP" && "$FORCE_STEP" == "$step_num" ]]; then
        if [[ "$step_num" -gt $((last_completed + 1)) ]]; then
            echo "Error: Cannot force step $step_num when only step $last_completed is completed"
            echo "Missing dependencies from previous steps."
            echo "Steps that need to be completed first:"
            for ((i=last_completed+1; i<step_num; i++)); do
                case $i in
                    1) echo "  - Step 1 (update): Update system packages" ;;
                    2) echo "  - Step 2 (packages): Install security packages" ;;
                    3) echo "  - Step 3 (verify): Verify installations" ;;
                    4) echo "  - Step 4 (user): Create user account" ;;
                    5) echo "  - Step 5 (ssh): Setup SSH key authentication" ;;
                    6) echo "  - Step 6 (verifyssh): Verify SSH connection is working" ;;
                    7) echo "  - Step 7 (wireguard): Setup WireGuard VPN with one peer" ;;
                    8) echo "  - Step 8 (tor): Configure Tor proxy with secure settings" ;;
                    9) echo "  - Step 9 (site): Setup hardened nginx site with demo page" ;;
                    10) echo "  - Step 10 (harden): System and kernel hardening" ;;
                esac
            done
            echo "Please run steps in order or use --continue mode."
            exit 1
        fi
        return 0
    fi
    
    # CONTINUE MODE: Execute from specified step onwards (--continue argument)
    if [[ -n "$CONTINUE_FROM" && "$step_num" -ge "$CONTINUE_FROM" ]]; then
        return 0
    fi
    
    # NORMAL MODE: Sequential execution - only run next step in sequence
    if [[ "$step_num" -gt "$last_completed" ]]; then
        return 0
    fi
    
    # SKIP: Step already completed or not ready to run
    return 1
}

#===============================================================================
# REBOOT MANAGEMENT FUNCTIONS
#===============================================================================

# Check if system requires reboot and handle accordingly
check_reboot_required() {
    local step_name="$1"
    local step_num="$2"
    
    # Check if reboot flag exists (set by previous step)
    if [[ -f "$REBOOT_FLAG_FILE" ]]; then
        echo ""
        echo "==============================================================================="
        echo "                           SYSTEM REBOOT REQUIRED"
        echo "==============================================================================="
        echo ""
        
        local flag_info=$(cat "$REBOOT_FLAG_FILE" 2>/dev/null || echo "Unknown step")
        echo "A previous step ($flag_info) has flagged that a system reboot is required"
        echo "before proceeding with step $step_num ($step_name)."
        echo ""
        echo "This is typically required when:"
        echo "  - Kernel updates were installed"
        echo "  - Core system libraries were updated" 
        echo "  - Boot parameters were changed"
        echo "  - System configuration requires reboot to take effect"
        echo ""
        echo "SECURITY NOTICE: Continuing without reboot may result in:"
        echo "  - Running on vulnerable kernel/libraries"
        echo "  - Incomplete system configuration"
        echo "  - Setup script failures or security issues"
        echo ""
        
        # Prompt user for reboot
        while true; do
            read -p "Reboot now to continue setup safely? (yes/no): " reboot_choice
            case $reboot_choice in
                yes|y|YES|Y)
                    echo ""
                    echo "Initiating system reboot..."
                    echo "After reboot, run: sudo setup.sh"
                    echo "Setup will continue from step $step_num ($step_name)"
                    echo ""
                    sleep 3
                    
                    # Clear reboot flag and reboot
                    rm -f "$REBOOT_FLAG_FILE"
                    sync
                    reboot
                    exit 0
                    ;;
                no|n|NO|N)
                    echo ""
                    echo "WARNING: Proceeding without reboot is NOT RECOMMENDED"
                    echo "This may cause setup failures or security vulnerabilities"
                    echo ""
                    read -p "Are you absolutely sure you want to continue? (type 'FORCE' to proceed): " force_choice
                    if [[ "$force_choice" == "FORCE" ]]; then
                        echo "Clearing reboot flag and continuing (NOT RECOMMENDED)..."
                        rm -f "$REBOOT_FLAG_FILE"
                        return 0
                    else
                        echo "Please reboot the system and run the setup script again."
                        exit 0
                    fi
                    ;;
                *)
                    echo "Please answer 'yes' or 'no'"
                    ;;
            esac
        done
    fi
    
    return 0
}

# Set reboot required flag with step information
set_reboot_required() {
    local step_name="$1"
    local step_num="$2"
    local reason="$3"
    
    echo ""
    echo "==============================================================================="
    echo "                          REBOOT REQUIRED FLAG SET"
    echo "==============================================================================="
    echo ""
    echo "Step $step_num ($step_name) has determined that a system reboot is required."
    echo "Reason: $reason"
    echo ""
    
    # Save reboot flag with step information
    echo "Step $step_num ($step_name): $reason" > "$REBOOT_FLAG_FILE"
    chmod 644 "$REBOOT_FLAG_FILE" 2>/dev/null || true
    
    echo "Reboot flag has been set. The next step will require system reboot."
    echo "You can continue with the current step, but the next step will prompt for reboot."
    echo ""
}

# Check if current session needs reboot (kernel/core updates)
check_current_reboot_needed() {
    local step_name="$1"
    local step_num="$2"
    
    local reboot_needed=false
    local reboot_reasons=()
    
    # Check standard reboot-required file
    if [[ -f /var/run/reboot-required ]]; then
        reboot_needed=true
        reboot_reasons+=("System packages require reboot")
    fi
    
    # Check if kernel was updated (different running vs available)
    local running_kernel=$(uname -r)
    local installed_kernel=$(dpkg -l | grep "^ii  linux-image-" | awk '{print $2}' | sed 's/linux-image-//' | sort -V | tail -1)
    
    if [[ -n "$installed_kernel" && "$running_kernel" != "$installed_kernel" ]]; then
        reboot_needed=true
        reboot_reasons+=("Kernel updated (running: $running_kernel, installed: $installed_kernel)")
    fi
    
    # Check for core library updates that need reboot
    if [[ -n "$(lsof 2>/dev/null | grep -E '(deleted|DEL)' | grep -E '(libc|libssl|libcrypto)' | head -1)" ]]; then
        reboot_needed=true
        reboot_reasons+=("Core libraries updated, processes using old versions")
    fi
    
    # If reboot needed, set the flag
    if [[ "$reboot_needed" == "true" ]]; then
        local combined_reason=$(IFS='; '; echo "${reboot_reasons[*]}")
        set_reboot_required "$step_name" "$step_num" "$combined_reason"
        return 0
    fi
    
    return 1
}