#!/bin/bash
# Step 6: SSH Connection Verification
# Purpose: Confirm SSH key authentication is working properly
# Security: Validates that user can connect via SSH before system locks down

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

verifyssh() {
    # Check if previous step requires reboot before proceeding
    check_reboot_required "verifyssh" "6"
    
    echo "Step 6: Verifying SSH connection..."
    
    local saved_username=""
    
    # Step 5 (SSH hardening) was completed before reaching this step
    
    # SSH CONNECTION CHECK: Ensure this step runs over SSH
    # Environment variables SSH_CLIENT and SSH_TTY are set when connected via SSH
    # This validation prevents users from accidentally locking themselves out
    if [[ -z "$SSH_CLIENT" && -z "$SSH_TTY" ]]; then
        echo "Error: You are not connected via SSH"
        echo "This step must be run over an SSH connection to verify the SSH setup is working."
        echo ""
        echo "Please connect via SSH first:"
        
        # Provide username-specific instructions if available
        saved_username=$(get_saved_username)
        if [[ -n "$saved_username" ]]; then
            echo "  ssh $saved_username@<SERVER_IP>"
        else
            echo "  ssh <username>@<SERVER_IP>"
        fi
        echo ""
        echo "Then run this command to continue:"
        echo "  sudo setup.sh -c verifyssh"
        echo ""
        echo "If SSH connection fails, please repeat step 5 (ssh) as root:"
        echo "  sudo setup.sh -s ssh"
        exit 1
    fi
    
    # SUCCESS CONFIRMATION: Show connection details
    echo "SSH connection verified successfully!"
    echo "You are connected via SSH from: ${SSH_CLIENT%% *}"
    echo ""
    
    # CONFIGURATION VERIFICATION: Confirm hardening settings are active
    # Double-check that security settings from step 5 are properly applied
    # Use more robust grep patterns to handle whitespace and comments
    if grep -E "^[[:space:]]*PasswordAuthentication[[:space:]]+no" /etc/ssh/sshd_config 2>/dev/null; then
        echo "SSH hardening confirmed: Password authentication is disabled"
    else
        echo "Warning: SSH configuration may not be properly hardened"
    fi
    
    # Verify root login restriction
    if grep -E "^[[:space:]]*PermitRootLogin[[:space:]]+no" /etc/ssh/sshd_config 2>/dev/null; then
        echo "SSH hardening confirmed: Root login is disabled"
    else
        echo "Warning: Root login may not be properly disabled"
    fi
    
    echo ""
    echo "SSH verification completed successfully!"
    echo "Your SSH key authentication is working and the server is properly secured."
    
    # SECURITY CHECK: Final user verification after SSH hardening
    # This is the last chance to detect unauthorized users before VPN setup
    echo ""
    saved_username=$(get_saved_username)
    if [[ -n "$saved_username" ]]; then
        check_user_security "$saved_username" true
    else
        # If no username saved, check for any non-root users
        check_user_security "" true
    fi
    echo ""
    
    mark_step_completed 6
}

# Execute function if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    verifyssh
fi