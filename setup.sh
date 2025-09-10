#!/bin/bash
#===============================================================================
# Debian 13 Security Setup Script - Main Orchestration
#===============================================================================
# 
# PURPOSE:
#   Comprehensive security hardening script for fresh Debian 13 installations.
#   Sets up SSH key authentication, creates non-root user, configures WireGuard
#   VPN with selective routing, and prepares Tor proxy access.
#
# DESIGN PHILOSOPHY:
#   - Stateful: Tracks progress and allows resuming from any step
#   - Safe: Validates dependencies and provides rollback capabilities  
#   - Flexible: Supports both sequential and individual step execution
#   - User-friendly: Clear instructions and error messages
#   - Modular: Each step is in a separate file for maintainability
#
# EXECUTION PHASES:
#   Phase 1 (Steps 1-5): Run as root on fresh Debian system
#   Phase 2 (Steps 6-10): Run as root OR user with sudo (via SSH connection)
#
# Usage: ./setup.sh [options]
# Options:
#   -s, --step NAME      Force execute specific step (ignores dependencies)
#   -c, --continue NAME  Continue from step NAME and update state file
#   -h, --help          Show this help message
#
# SECURITY NOTICE:
#   This script is designed for DEFENSIVE security purposes only.
#   It creates secure infrastructure for legitimate privacy and security needs.
#===============================================================================

# Exit immediately on any error
set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source utility functions
source "$SCRIPT_DIR/lib/utils.sh"

# Import reboot flag file location
REBOOT_FLAG_FILE="/var/tmp/debian-setup-reboot-required"

# Global variables for command-line argument processing
FORCE_STEP=""
CONTINUE_FROM=""

#===============================================================================
# COMMAND LINE ARGUMENT PARSING
#===============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--step)
            if [[ -z "$2" ]]; then
                echo "Error: --step requires a step name" >&2
                echo "Valid steps: update, packages, verify, user, ssh, verifyssh, wireguard, tor, site, xmpp, harden, info" >&2
                exit 1
            fi
            FORCE_STEP=$(get_step_number "$2")
            shift 2
            ;;
        -c|--continue)
            if [[ -z "$2" ]]; then
                echo "Error: --continue requires a step name" >&2
                echo "Valid steps: update, packages, verify, user, ssh, verifyssh, wireguard, tor, site, xmpp, harden, info" >&2
                exit 1
            fi
            CONTINUE_FROM=$(get_step_number "$2")
            shift 2
            ;;
        --info)
            # Run info step directly without state management
            SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
            if [[ -f "$SCRIPT_DIR/steps/step_12_info.sh" ]]; then
                source "$SCRIPT_DIR/steps/step_12_info.sh"
                info
                exit 0
            else
                echo "Error: Info step not found: $SCRIPT_DIR/steps/step_12_info.sh"
                exit 1
            fi
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -s, --step STEP    Force execute specific step (update|packages|verify|user|ssh|verifyssh|wireguard|tor|site|xmpp|harden|info)"
            echo "  -c, --continue STEP Continue from step and update state file"
            echo "  --info             Display complete system configuration and usage info"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Steps:"
            echo "  update    - Update system packages"
            echo "  packages  - Install security packages"
            echo "  verify    - Verify installations"
            echo "  user      - Create user account"
            echo "  ssh       - Setup SSH key authentication and harden SSH"
            echo "  verifyssh - Verify SSH connection is working"
            echo "  wireguard - Setup WireGuard VPN with one peer"
            echo "  tor       - Configure Tor proxy with secure settings"
            echo "  site      - Setup hardened nginx site with demo page"
            echo "  xmpp      - Install and configure XMPP server"
            echo "  harden    - System and kernel hardening, UFW, AppArmor, no-logs"
            echo "  info      - Display complete system configuration and usage info"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

#===============================================================================
# ROOT PRIVILEGE CHECK
#===============================================================================

if [ "$(id -u)" -ne 0 ]; then
    if [[ -n "$FORCE_STEP" && ("$FORCE_STEP" -eq 6 || "$FORCE_STEP" -eq 7 || "$FORCE_STEP" -eq 8 || "$FORCE_STEP" -eq 9 || "$FORCE_STEP" -eq 10 || "$FORCE_STEP" -eq 11 || "$FORCE_STEP" -eq 12) ]] || \
       [[ -n "$CONTINUE_FROM" && "$CONTINUE_FROM" -ge 6 ]]; then
        if ! sudo -n true 2>/dev/null; then
            echo "Steps 6-12 require sudo access when not running as root" >&2
            echo "Please run: sudo $0 [options]" >&2
            echo "Or run as root for all steps" >&2
            exit 1
        fi
        echo "Running with sudo privileges for steps 6-12"
    else
        echo "Steps 1-5 must be run as root" >&2
        echo "Please run: sudo $0 [options]" >&2
        exit 1
    fi
fi

#===============================================================================
# CONTINUE MODE SETUP
#===============================================================================

if [[ -n "$CONTINUE_FROM" ]]; then
    if [[ -f "$STATUS_FILE" ]]; then
        cp "$STATUS_FILE" "${STATUS_FILE}.backup"
        echo "State file backed up to ${STATUS_FILE}.backup"
    fi
    
    saved_username=$(get_saved_username)
    prev_step=$((CONTINUE_FROM - 1))
    
    if [[ "$prev_step" -lt 0 ]]; then
        prev_step=0
    fi
    
    if [[ -n "$saved_username" ]]; then
        echo "$prev_step:$saved_username" > "$STATUS_FILE"
    else
        echo "$prev_step" > "$STATUS_FILE"
        if [[ "$CONTINUE_FROM" -ge 5 ]]; then
            echo "Warning: No username found in state file for steps 5+"
            echo "If step 4 (user creation) was completed, the username should be saved"
            echo "You may need to run step 4 first if you haven't created a user"
        fi
    fi
    
    chmod 644 "$STATUS_FILE" 2>/dev/null || true
    echo "State file updated to continue from step $CONTINUE_FROM"
fi

#===============================================================================
# GLOBAL SCRIPT INSTALLATION
#===============================================================================

copy_script_to_bin() {
    local script_path="$(realpath "$0")"
    local script_name="setup.sh"
    local bin_path="/usr/local/bin/$script_name"
    local info_path="/usr/local/bin/info"
    
    # Copy main setup script
    if [[ "$script_path" != "$bin_path" ]]; then
        if [[ ! -f "$bin_path" ]] || [[ "$script_path" -nt "$bin_path" ]]; then
            echo "Copying setup script to $bin_path for global access..."
            cp "$script_path" "$bin_path"
            chmod +x "$bin_path"
            echo "Script is now available globally as 'setup.sh'"
        fi
    fi
    
    # Create info command wrapper
    if [[ ! -f "$info_path" ]] || [[ "$script_path" -nt "$info_path" ]]; then
        echo "Creating info command for easy system information access..."
        cat > "$info_path" << 'EOF'
#!/bin/bash
# System Information Command - Debian Security Setup
# Shows complete system configuration and usage information

# Simply call the setup script with --info flag
exec /usr/local/bin/setup.sh --info "$@"
EOF
        chmod +x "$info_path"
        echo "Info command created: Use 'info' to display system configuration"
    fi
}

copy_script_to_bin

#===============================================================================
# INITIAL SECURITY CHECK
#===============================================================================

echo "Performing critical security check..."

login_users=()
while IFS=: read -r username _ uid _ _ _ shell; do
    if [[ "$uid" -eq 0 ]] || [[ "$uid" -ge 1000 ]]; then
        if [[ "$shell" =~ ^/bin/(bash|sh|zsh|dash)$|^/usr/bin/(bash|fish|zsh)$ ]]; then
            login_users+=("$username")
        fi
    fi
done < /etc/passwd

non_root_users=()
for user in "${login_users[@]}"; do
    if [[ "$user" != "root" ]]; then
        non_root_users+=("$user")
    fi
done

if [[ ${#non_root_users[@]} -gt 0 ]]; then
    echo -e "\033[31mSECURITY ERROR: System has existing users other than root!\033[0m"
    echo ""
    echo "Found login-capable users: ${login_users[*]}"
    echo "Non-root users detected: ${non_root_users[*]}"
    echo ""
    echo "This script is designed for FRESH Debian 13 installations with only root."
    echo "Running on a system with existing users poses security risks:"
    echo "  - Existing users may have weak passwords or SSH keys"
    echo "  - Unknown user permissions and access levels"
    echo "  - Potential for privilege escalation attacks"
    echo "  - Cannot guarantee secure baseline configuration"
    echo ""
    read -p "Delete these users and continue? (y/N): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "Removing existing non-root users..."
        for user in "${non_root_users[@]}"; do
            if id "$user" &>/dev/null; then
                echo "Removing user: $user"
                if deluser --remove-home --quiet "$user" 2>/dev/null; then
                    echo "  Successfully removed user: $user"
                else
                    echo -e "\033[31m  ERROR: Failed to remove user: $user\033[0m"
                    echo "  You may need to manually remove this user before continuing."
                    exit 1
                fi
            fi
        done
        echo ""
        echo -e "\033[92mAll non-root users removed. System is now secure for setup.\033[0m"
    else
        echo ""
        echo "Exiting. Cannot proceed with existing users present."
        echo "To manually remove users, run:"
        for user in "${non_root_users[@]}"; do
            echo "  deluser --remove-home $user"
        done
        exit 1
    fi
else
    echo "Security check passed: Only root user detected"
    echo "  System is ready for secure configuration"
fi
echo ""

#===============================================================================
# STEP EXECUTION
#===============================================================================

# Source and execute each step based on should_run_step logic
declare -a STEPS=(
    "1:update:$SCRIPT_DIR/steps/step_01_update.sh"
    "2:packages:$SCRIPT_DIR/steps/step_02_packages.sh"
    "3:verify:$SCRIPT_DIR/steps/step_03_verify.sh"
    "4:user:$SCRIPT_DIR/steps/step_04_user.sh"
    "5:ssh:$SCRIPT_DIR/steps/step_05_ssh.sh"
    "6:verifyssh:$SCRIPT_DIR/steps/step_06_verifyssh.sh"
    "7:wireguard:$SCRIPT_DIR/steps/step_07_wireguard.sh"
    "8:tor:$SCRIPT_DIR/steps/step_08_tor.sh"
    "9:site:$SCRIPT_DIR/steps/step_09_site.sh"
    "10:xmpp:$SCRIPT_DIR/steps/step_10_xmpp.sh"
    "11:harden:$SCRIPT_DIR/steps/step_11_harden.sh"
    "12:info:$SCRIPT_DIR/steps/step_12_info.sh"
)

for step_info in "${STEPS[@]}"; do
    IFS=':' read -r step_num step_name step_file <<< "$step_info"
    
    if should_run_step "$step_num"; then
        echo "==============================================================================="
        echo "Executing Step $step_num: $step_name"
        echo "==============================================================================="
        
        # Check if previous step requires reboot before proceeding (except step 1)
        if [[ "$step_num" -gt 1 ]]; then
            check_reboot_required "$step_name" "$step_num"
        fi
        
        if [[ -f "$step_file" ]]; then
            source "$step_file"
            
            # Call the function directly (each step file defines a function matching the step name)
            case "$step_name" in
                "update") update ;;
                "packages") packages ;;
                "verify") verify ;;
                "user") user ;;
                "ssh") ssh ;;
                "verifyssh") verifyssh ;;
                "wireguard") wireguard ;;
                "tor") tor ;;
                "site") site ;;
                "xmpp") xmpp ;;
                "harden") harden ;;
                "info") info ;;
            esac
        else
            echo "Error: Step file not found: $step_file"
            exit 1
        fi
        
        echo -e "\033[92mStep $step_num ($step_name) completed successfully\033[0m"
        echo ""
        
        # Special handling for step 5 (SSH hardening)
        if [[ "$step_num" -eq 5 ]]; then
            echo -e "\033[92mSSH hardening completed. Script must terminate for security.\033[0m"
            echo "To continue, reconnect via SSH and run: sudo $0"
            echo ""
            echo "Connection command will be similar to:"
            username=$(get_saved_username)
            if [[ -n "$username" ]]; then
                echo "  ssh $username@YOUR_SERVER_IP"
            else
                echo "  ssh YOUR_USERNAME@YOUR_SERVER_IP"
            fi
            exit 0
        fi
    fi
done

echo "==============================================================================="
echo -e "\033[92mAll applicable steps completed successfully!\033[0m"
echo "==============================================================================="
last_step=$(get_last_completed_step)
echo -e "\033[92mCurrent status: Step $last_step completed\033[0m"

if [[ "$last_step" -eq 11 ]]; then
    # Check if reboot is required before running info step
    if [[ -f "$REBOOT_FLAG_FILE" ]]; then
        echo ""
        echo -e "\033[92mSetup steps completed, but system reboot is required!\033[0m"
        echo ""
        echo "A reboot is needed to activate:"
        cat "$REBOOT_FLAG_FILE" 2>/dev/null || echo "System configuration changes"
        echo ""
        echo "After reboot, run: sudo setup.sh"
        echo "The setup will then display configuration info (step 11)"
    else
        echo ""
        echo -e "\033[92mComplete Debian 13 security setup finished!\033[0m"
        echo ""
        echo "Running final step to display configuration info..."
        echo ""
        
        # Automatically run info step at completion
        if [[ -f "$SCRIPT_DIR/steps/step_11_info.sh" ]]; then
            source "$SCRIPT_DIR/steps/step_11_info.sh"
            info
        else
            echo "Error: Info step not found, but setup is complete"
        fi
    fi
elif [[ "$last_step" -eq 12 ]]; then
    echo ""
    echo -e "\033[92mSetup is complete. Use 'sudo setup.sh --info' to view configuration details again.\033[0m"
    
    # Clean up any remaining reboot flags since setup is fully complete
    rm -f "$REBOOT_FLAG_FILE" 2>/dev/null || true
else
    echo ""
    echo "To continue setup, run: $0"
    if [[ "$last_step" -ge 5 ]]; then
        echo "Make sure you're connected via SSH if you've completed step 5"
    fi
    
    # Check if there's a pending reboot
    if [[ -f "$REBOOT_FLAG_FILE" ]]; then
        echo ""
        echo "NOTE: A system reboot is currently required."
        echo "The next step will prompt you to reboot before continuing."
    fi
fi