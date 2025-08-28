#!/bin/bash
# Step 5: SSH Key Authentication Setup
# Purpose: Configure SSH for secure key-based authentication and disable root login
# Security: Eliminates password-based attacks, restricts root access

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

ssh() {
    # Check if previous step requires reboot before proceeding
    check_reboot_required "ssh" "5"
    
    echo "Step 5: Setting up SSH key authentication..."
    
    # VARIABLE DECLARATION: Ensure username is properly scoped
    local username=""
    
    # SSH service was installed and verified in steps 2-3
    local SSH_SERVICE=$(detect_ssh_service)
    
    # Start SSH service if not running (required for configuration)
    if ! systemctl is-active "$SSH_SERVICE" &>/dev/null; then
        echo "Warning: SSH service ($SSH_SERVICE) is not running. Starting it now..."
        systemctl start "$SSH_SERVICE"
        
        # Verify service started successfully before proceeding
        if ! systemctl is-active "$SSH_SERVICE" &>/dev/null; then
            echo "Error: Failed to start SSH service ($SSH_SERVICE)"
            exit 1
        fi
        echo "SSH service ($SSH_SERVICE) started successfully"
    fi
    
    # Get username from step 4 (already validated and created)
    username=$(get_saved_username)
    
    # SERVER IP DETECTION: Determine local IP address for SSH instructions
    # Uses multiple fallback methods for reliability across different systems
    # Note: This gets LOCAL IP, not public IP (appropriate for SSH setup)
    local SERVER_IP=""
    
    # Method 1: Use ip route command (most reliable on modern Linux)
    # Gets IP that would be used to reach 1.1.1.1 (reliable external target)
    if command -v ip >/dev/null 2>&1; then
        SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}')
    fi
    
    # Method 2: Use hostname -I (backup method)
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    
    # Method 3: Use hostname -i (older systems)
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(hostname -i 2>/dev/null | awk '{print $1}')
    fi
    
    # Method 4: Manual input if all automatic methods fail
    if [[ -z "$SERVER_IP" ]]; then
        echo "Warning: Could not determine server IP address automatically"
        while true; do
            read -p "Please enter the server IP address: " SERVER_IP
            # IPv4 validation: Check format and octet ranges
            if [[ "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                # Validate each octet is 0-255
                local valid=true
                IFS='.' read -ra OCTETS <<< "$SERVER_IP"
                for octet in "${OCTETS[@]}"; do
                    if [[ "$octet" -gt 255 ]]; then
                        valid=false
                        break
                    fi
                done
                if $valid; then
                    break
                fi
            fi
            echo "Error: Please enter a valid IPv4 address (e.g., 192.168.1.100)"
        done
    fi
    
    # PREPARE USER ACCOUNT FOR SSH KEY AUTHENTICATION
    # Create .ssh directory structure with proper permissions
    echo "Preparing user account for SSH key authentication..."
    
    # Create .ssh directory for the user
    sudo -u "$username" mkdir -p "/home/$username/.ssh"
    chmod 700 "/home/$username/.ssh"
    chown "$username:$username" "/home/$username/.ssh"
    
    # Create empty authorized_keys file if it doesn't exist
    if [[ ! -f "/home/$username/.ssh/authorized_keys" ]]; then
        sudo -u "$username" touch "/home/$username/.ssh/authorized_keys"
        chmod 600 "/home/$username/.ssh/authorized_keys"
        chown "$username:$username" "/home/$username/.ssh/authorized_keys"
    fi
    
    echo "SSH directory structure prepared for user: $username"
    echo ""
    
    # SYSTEM-SPECIFIC SSH SETUP: Provide tailored instructions for each OS
    # Different operating systems have different SSH key generation methods
    echo "Please select your client system:"
    echo "1) Linux"
    echo "2) macOS" 
    echo "3) Windows"
    read -p "Enter choice (1-3): " system_choice
    
    # SYSTEM SELECTION: Map user choice to system identifier
    local client_system=""
    case $system_choice in
        1)
            client_system="linux"
            ;;
        2)
            client_system="macos"
            ;;
        3)
            client_system="windows"
            ;;
        *)
            echo "Invalid choice. Exiting."
            exit 1
            ;;
    esac
    
    # DISPLAY SYSTEM-SPECIFIC INSTRUCTIONS
    # Each OS requires different methods for SSH key generation and deployment
    echo ""
    echo "=== SSH Key Setup Instructions for $client_system ==="
    echo ""
    
    case $client_system in
        "linux"|"macos")
            # Unix-like systems: Standard OpenSSH tools available
            echo "On your $client_system machine, run these commands:"
            echo ""
            echo "1. Generate SSH key pair:"
            echo "   ssh-keygen -t ed25519 -C \"your-email@example.com\""
            echo "   (Press Enter to accept default location, optionally set passphrase)"
            echo ""
            echo "2. Copy public key to server:"
            echo "   ssh-copy-id $username@$SERVER_IP"
            echo ""
            echo "3. Test connection:"
            echo "   ssh $username@$SERVER_IP"
            ;;
        "windows")
            # Windows: Multiple options depending on Windows version and user preference
            echo "On your Windows machine:"
            echo ""
            echo "Option A - Using PowerShell (Windows 10+):"
            echo "1. Generate SSH key pair:"
            echo "   ssh-keygen -t ed25519 -C \"your-email@example.com\""
            echo ""
            echo "2. Copy public key to server:"
            echo "   type \$env:USERPROFILE\\.ssh\\id_ed25519.pub | ssh $username@$SERVER_IP \"mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys\""
            echo ""
            echo "Option B - Using PuTTY:"
            echo "1. Download and install PuTTY and PuTTYgen"
            echo "2. Use PuTTYgen to generate an SSH key pair"
            echo "3. Save private key and copy public key text"
            echo "4. Connect to server with current credentials and run:"
            echo "   echo 'PASTE_PUBLIC_KEY_HERE' >> ~/.ssh/authorized_keys"
            echo ""
            echo "5. Test connection with PuTTY using the private key"
            ;;
    esac
    
    # SECURITY NOTICE: Explain what hardening will occur
    # Important to warn user before making security changes
    echo ""
    echo "After setting up your SSH key, this script will:"
    echo "- Disable SSH password authentication"
    echo "- Disable root SSH login"
    echo "- Restart SSH service"
    echo ""
    echo "IMPORTANT: Ensure you can connect via SSH key BEFORE continuing!"
    echo "Test your connection first, then return here."
    echo ""
    
    # USER CONFIRMATION: Require explicit confirmation before security lockdown
    # This prevents accidental lockout from the server
    local ssh_confirmed=""
    read -p "Have you successfully set up SSH key authentication and tested it? (yes/no): " ssh_confirmed
    
    if [[ "$ssh_confirmed" != "yes" ]]; then
        echo "Please set up SSH key authentication first, then run: setup.sh -c ssh"
        exit 0
    fi
    
    # SSH HARDENING: Apply secure configuration settings
    # This configuration eliminates password-based attacks
    echo "Hardening SSH configuration..."
    
    # Ensure SSH host keys exist (required on fresh Debian install)
    echo "Generating SSH host keys if missing..."
    ssh-keygen -A 2>/dev/null || true
    
    # Verify host keys were created
    for key_type in rsa ecdsa ed25519; do
        if [[ ! -f "/etc/ssh/ssh_host_${key_type}_key" ]]; then
            echo "Warning: SSH host key missing: /etc/ssh/ssh_host_${key_type}_key"
        fi
    done
    
    # Backup original configuration (safety measure)
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Apply SSH hardening settings
    cat > /etc/ssh/sshd_config << EOF
# SSH Hardened Configuration - Generated by Debian Security Setup
# Based on Debian 13 defaults with security hardening

# Include drop-in configs
Include /etc/ssh/sshd_config.d/*.conf

# Network
Port 22

# Host Keys (Debian 13 defaults)
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication (HARDENED - no passwords)
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes

# Key-based authentication only
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Security settings (HARDENED)
X11Forwarding no
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 60
StrictModes yes

# Allow only specific users (HARDENED)
AllowUsers $username

# Subsystem (required for SFTP)
Subsystem sftp /usr/lib/openssh/sftp-server

# Logging
SyslogFacility AUTH
LogLevel INFO

# Banner (optional)
# Banner /etc/issue.net
EOF
    
    # Test SSH configuration
    if sshd -t; then
        echo "SSH configuration is valid"
        
        # Ensure SSH service is enabled for boot
        systemctl enable "$SSH_SERVICE"
        
        # Restart SSH service with new configuration
        systemctl restart "$SSH_SERVICE"
        
        # Verify SSH service restarted successfully
        if ! systemctl is-active "$SSH_SERVICE" &>/dev/null; then
            echo "Error: SSH service ($SSH_SERVICE) failed to start after configuration change"
            cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
            systemctl restart "$SSH_SERVICE"
            exit 1
        fi
        echo "SSH service ($SSH_SERVICE) restarted with hardened configuration"
        echo ""
        echo "SSH hardening completed:"
        echo "- Password authentication disabled"
        echo "- Root login disabled"
        echo "- Only key-based authentication allowed"
        echo "- Only user '$username' can connect"
        echo ""
        echo "SSH hardening completed successfully."
        echo "Connection command: ssh $username@$SERVER_IP"
        echo ""
        echo "IMPORTANT: You must now reconnect via SSH to continue the setup."
        echo "After connecting via SSH, run: sudo setup.sh"
        echo "The script will continue with step 6 (verifyssh) to verify the SSH connection."
        mark_step_completed 5
        exit 0
    else
        echo "SSH configuration test failed! Restoring backup..."
        cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
        systemctl restart "$SSH_SERVICE"
        echo "Original SSH configuration restored and service restarted"
        exit 1
    fi
}

# Execute function if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    ssh
fi