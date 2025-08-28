#!/bin/bash
#===============================================================================
# Step 4: User Creation - Bulletproof Implementation
#===============================================================================
# Purpose: Create secure non-root user account with comprehensive validation
# Features: Enhanced security validation, system state checking, rollback capability
# User validation:
#   - Username compliance with Linux standards and security best practices
#   - Password strength enforcement with comprehensive character validation
#   - Sudo group membership and functional testing
#   - Home directory and shell configuration verification
#   - System user account audit and security validation
#===============================================================================

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Exit on any error with proper cleanup
set -euo pipefail

# STEP 4: User Creation - Bulletproof Version
user() {
    # Check if previous step requires reboot before proceeding
    check_reboot_required "user" "4"
    
    echo "Step 4: Comprehensive user account creation..."
    
    local START_TIME=$(date +%s)
    local TEMP_DIR="/tmp/user_validation_$$"
    local USER_LOG="/tmp/user_step4_$$.log"
    local CREATED_USER=""
    local PASSWORD_ATTEMPTS=0
    local MAX_PASSWORD_ATTEMPTS=5
    
    # Cleanup function for errors and rollback
    cleanup_user() {
        local exit_code=$?
        echo "Cleaning up user creation artifacts..."
        
        # Clean up temporary files
        rm -rf "$TEMP_DIR" 2>/dev/null || true
        rm -f "$USER_LOG" 2>/dev/null || true
        
        # Remove any temporary scripts and password files
        find /tmp -name "sudo_test_script_$$*" -type f -delete 2>/dev/null || true
        find /tmp -name "sudo_pass_$$*" -type f -delete 2>/dev/null || true
        find /tmp -name "sudo_config_test_$$*" -type f -delete 2>/dev/null || true
        
        if [[ $exit_code -ne 0 && -n "${CREATED_USER:-}" ]]; then
            echo "User creation failed, attempting rollback..."
            
            # Check if user was created and attempt cleanup
            if id "$CREATED_USER" &>/dev/null; then
                echo "Removing partially created user: $CREATED_USER"
                
                # Kill any processes owned by the user
                pkill -u "$CREATED_USER" 2>/dev/null || true
                sleep 2
                
                # Remove user and home directory
                userdel -r "$CREATED_USER" 2>/dev/null || {
                    echo "Failed to remove user cleanly, manual cleanup may be required"
                    echo "User: $CREATED_USER"
                    echo "Home directory: /home/$CREATED_USER"
                }
            fi
        fi
        
        if [[ $exit_code -ne 0 ]]; then
            echo "User creation failed with exit code: $exit_code"
            echo "System state information:"
            echo "  - Active users: $(who | wc -l || echo 'Unknown')"
            echo "  - System load: $(uptime | awk -F'load average:' '{print $2}' || echo 'Unknown')"
            
            if [[ -f "$USER_LOG" ]]; then
                echo "User creation log summary:"
                tail -10 "$USER_LOG" 2>/dev/null || true
            fi
            
            echo "Recommendation: Check system logs and user management configuration"
        fi
    }
    trap cleanup_user EXIT
    
    mkdir -p "$TEMP_DIR"
    
    # ---------------------------------------------------------------------
    # 1) Pre-Creation System Validation
    # ---------------------------------------------------------------------
    echo "Validating system state for user creation..."
    
    # Check if we're running as root
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: User creation must be run as root" >&2
        exit 1
    fi
    
    # Verify essential commands for user management are available
    local REQUIRED_USER_CMDS=("useradd" "usermod" "userdel" "chpasswd" "groups" "id" "su" "sudo" "passwd")
    for cmd in "${REQUIRED_USER_CMDS[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "ERROR: Required user management command '$cmd' not found" >&2
            exit 1
        fi
    done
    
    # Check if sudo group exists
    if ! getent group sudo &>/dev/null; then
        echo "ERROR: sudo group does not exist on this system" >&2
        echo "This may indicate a missing or misconfigured sudo package" >&2
        exit 1
    fi
    
    # Verify /etc/passwd and /etc/shadow are writable
    if [[ ! -w /etc/passwd ]]; then
        echo "ERROR: Cannot write to /etc/passwd" >&2
        exit 1
    fi
    
    if [[ ! -w /etc/shadow ]]; then
        echo "ERROR: Cannot write to /etc/shadow" >&2
        exit 1
    fi
    
    # Check disk space for home directory
    local AVAILABLE_HOME_SPACE=$(df /home 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    if [[ $AVAILABLE_HOME_SPACE -lt 102400 ]]; then  # 100MB in KB
        echo "ERROR: Insufficient disk space for user home directory (need 100MB, have $(($AVAILABLE_HOME_SPACE/1024))MB)" >&2
        exit 1
    fi
    
    echo "Pre-creation system validation passed"
    
    # ---------------------------------------------------------------------
    # 2) Enhanced Username Input and Validation
    # ---------------------------------------------------------------------
    echo "Collecting and validating username..."
    
    local username=""
    local USERNAME_ATTEMPTS=0
    local MAX_USERNAME_ATTEMPTS=5
    
    while [[ $USERNAME_ATTEMPTS -lt $MAX_USERNAME_ATTEMPTS ]]; do
        read -p "Enter username: " username
        USERNAME_ATTEMPTS=$((USERNAME_ATTEMPTS + 1))
        
        # Trim whitespace
        username=$(echo "$username" | tr -d '[:space:]')
        
        # Check if username is empty
        if [[ -z "$username" ]]; then
            echo "Username cannot be empty. Please enter a valid username."
            continue
        fi
        
        # USERNAME VALIDATION: Enhanced Linux username standards
        # Pattern: ^[a-z][a-z0-9_-]*$ means:
        #   - Must start with lowercase letter (security best practice)
        #   - Can contain lowercase letters, numbers, underscores, hyphens
        #   - No uppercase letters (consistent with system accounts)
        #   - No special characters that could cause security issues
        if [[ ! "$username" =~ ^[a-z][a-z0-9_-]*$ ]]; then
            echo "Invalid username format. Requirements:"
            echo "  - Must start with a lowercase letter (a-z)"
            echo "  - Can contain lowercase letters, numbers, underscores, and hyphens"
            echo "  - No uppercase letters or special characters"
            continue
        fi
        
        # Length validation: 1-32 characters (Linux system limits)
        if [[ ${#username} -lt 2 || ${#username} -gt 32 ]]; then
            echo "Username must be between 2 and 32 characters long."
            continue
        fi
        
        # Prevent reserved usernames that could cause security issues
        local RESERVED_USERNAMES=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "messagebus" "sshd" "ufw" "tor" "debian-tor" "nginx")
        for reserved in "${RESERVED_USERNAMES[@]}"; do
            if [[ "$username" == "$reserved" ]]; then
                echo "Username '$username' is reserved and cannot be used."
                continue 2  # Continue outer loop
            fi
        done
        
        # Prevent duplicate user creation
        if id "$username" &>/dev/null; then
            echo "User '$username' already exists. Please choose a different username."
            continue
        fi
        
        # Check if home directory already exists
        if [[ -d "/home/$username" ]]; then
            echo "Home directory '/home/$username' already exists. Please choose a different username."
            continue
        fi
        
        # If we get here, username is valid
        echo "Username '$username' is valid"
        break
    done
    
    if [[ $USERNAME_ATTEMPTS -ge $MAX_USERNAME_ATTEMPTS ]]; then
        echo "ERROR: Maximum username attempts exceeded ($MAX_USERNAME_ATTEMPTS)" >&2
        exit 1
    fi
    
    CREATED_USER="$username"  # Set for cleanup function
    
    # ---------------------------------------------------------------------
    # 3) Enhanced Password Input and Security Validation
    # ---------------------------------------------------------------------
    echo "Setting up secure password with enhanced validation..."
    
    local password=""
    local password_confirm=""
    
    while [[ $PASSWORD_ATTEMPTS -lt $MAX_PASSWORD_ATTEMPTS ]]; do
        PASSWORD_ATTEMPTS=$((PASSWORD_ATTEMPTS + 1))
        
        echo "Password requirements:"
        echo "  - At least 12 characters long"
        echo "  - At least one uppercase letter (A-Z)"
        echo "  - At least one lowercase letter (a-z)"
        echo "  - At least one number (0-9)"
        echo "  - Cannot contain: single quotes, double quotes, backslashes, dollar signs, backticks"
        echo "  - Cannot contain control characters (tabs, newlines, etc.)"
        echo ""
        
        read -s -p "Enter password: " password
        echo
        read -s -p "Confirm password: " password_confirm
        echo
        
        # Password confirmation check
        if [[ "$password" != "$password_confirm" ]]; then
            echo "Passwords do not match. Please try again."
            continue
        fi
        
        # Length check (minimum 12 characters for security)
        if [[ ${#password} -lt 12 ]]; then
            echo "Password must be at least 12 characters long."
            continue
        fi
        
        # Maximum length check (prevent system limits issues)
        if [[ ${#password} -gt 128 ]]; then
            echo "Password too long (maximum 128 characters)."
            continue
        fi
        
        # Character class validation with detailed feedback
        local missing_requirements=()
        
        if [[ ! "$password" =~ [A-Z] ]]; then
            missing_requirements+=("uppercase letter (A-Z)")
        fi
        
        if [[ ! "$password" =~ [a-z] ]]; then
            missing_requirements+=("lowercase letter (a-z)")
        fi
        
        if [[ ! "$password" =~ [0-9] ]]; then
            missing_requirements+=("number (0-9)")
        fi
        
        if [[ ${#missing_requirements[@]} -gt 0 ]]; then
            echo "Password missing required character types:"
            for req in "${missing_requirements[@]}"; do
                echo "  - $req"
            done
            continue
        fi
        
        # Check for problematic characters that could break system commands
        if [[ "$password" =~ [\'\"\\\$\`] ]]; then
            echo "Password cannot contain: single quotes ('), double quotes (\"), backslashes (\\), dollar signs (\$), or backticks (\`)."
            continue
        fi
        
        # Check for control characters, newlines, tabs
        if printf '%s' "$password" | grep -q $'[\x00-\x1F\x7F]'; then
            echo "Password cannot contain control characters, newlines, tabs, or other non-printable characters."
            continue
        fi
        
        # Additional security checks
        # Check for common weak patterns
        if [[ "$password" =~ ^(.)\1{3,}$ ]]; then
            echo "Password cannot consist of repeating characters."
            continue
        fi
        
        # Check for username in password
        if [[ "${password,,}" == *"${username,,}"* ]]; then
            echo "Password cannot contain the username."
            continue
        fi
        
        # Check for common weak passwords
        local WEAK_PATTERNS=("123456789012" "abcdefghijkl" "qwertyuiop" "password1234")
        local is_weak=false
        for weak in "${WEAK_PATTERNS[@]}"; do
            if [[ "${password,,}" == *"$weak"* ]]; then
                echo "Password contains common weak patterns. Please choose a stronger password."
                is_weak=true
                break
            fi
        done
        
        if [[ "$is_weak" == "true" ]]; then
            continue
        fi
        
        # If we get here, password is valid
        echo "Password meets all security requirements"
        break
    done
    
    if [[ $PASSWORD_ATTEMPTS -ge $MAX_PASSWORD_ATTEMPTS ]]; then
        echo "ERROR: Maximum password attempts exceeded ($MAX_PASSWORD_ATTEMPTS)" >&2
        exit 1
    fi
    
    # ---------------------------------------------------------------------
    # 4) User Account Creation with Comprehensive Validation
    # ---------------------------------------------------------------------
    echo "Creating user account with secure configuration..."
    
    # Create user with comprehensive options
    echo "Creating user: $username"
    if ! useradd -m -s /bin/bash -c "Security Setup User" "$username" 2>&1 | tee "$USER_LOG"; then
        echo "ERROR: Failed to create user account" >&2
        cat "$USER_LOG" >&2
        exit 1
    fi
    
    # Verify user creation
    if ! id "$username" &>/dev/null; then
        echo "ERROR: User creation succeeded but user cannot be found" >&2
        exit 1
    fi
    
    # Verify home directory creation
    if [[ ! -d "/home/$username" ]]; then
        echo "ERROR: Home directory was not created" >&2
        exit 1
    fi
    
    # Set proper home directory permissions
    chown "$username:$username" "/home/$username"
    chmod 700 "/home/$username"
    
    echo "User account created successfully"
    
    # ---------------------------------------------------------------------
    # 5) Secure Password Setting with Validation
    # ---------------------------------------------------------------------
    echo "Setting secure password..."
    
    # SECURE PASSWORD SETTING: Use printf and pipe to avoid shell expansion
    # This method prevents password exposure in process arguments and handles special characters
    if ! printf '%s:%s\n' "$username" "$password" | chpasswd 2>&1 | tee -a "$USER_LOG"; then
        echo "ERROR: Failed to set user password" >&2
        cat "$USER_LOG" >&2
        exit 1
    fi
    
    # Verify password was set by checking shadow file modification time
    local shadow_modified=$(stat -c %Y /etc/shadow 2>/dev/null || echo "0")
    local current_time=$(date +%s)
    if [[ $((current_time - shadow_modified)) -gt 60 ]]; then
        echo "WARNING: Password may not have been set correctly (shadow file not recently modified)"
    fi
    
    echo "Password set successfully"
    
    # ---------------------------------------------------------------------
    # 6) Sudo Privileges Configuration and Verification
    # ---------------------------------------------------------------------
    echo "Configuring sudo privileges..."
    
    # Add user to sudo group
    if ! usermod -aG sudo "$username" 2>&1 | tee -a "$USER_LOG"; then
        echo "ERROR: Failed to add user to sudo group" >&2
        cat "$USER_LOG" >&2
        exit 1
    fi
    
    # Verify sudo group membership
    if ! groups "$username" | grep -q sudo; then
        echo "ERROR: User was not successfully added to sudo group" >&2
        exit 1
    fi
    
    echo "User added to sudo group successfully"
    
    # ---------------------------------------------------------------------
    # 7) Comprehensive Sudo Access Testing
    # ---------------------------------------------------------------------
    echo "Testing sudo access functionality..."
    
    # Create secure temporary script for sudo testing
    local temp_script="/tmp/sudo_test_script_$$_$(date +%s)"
    local temp_password_file="/tmp/sudo_pass_$$_$(date +%s)"
    
    # Write password to temporary file with secure permissions
    printf '%s' "$password" > "$temp_password_file"
    chmod 600 "$temp_password_file"
    
    cat > "$temp_script" << 'SCRIPT_EOF'
#!/bin/bash
# Secure sudo test script
set -euo pipefail
sudo -S -k whoami 2>/dev/null < "$1"
exit_code=$?
sudo -k 2>/dev/null || true  # Clear sudo credentials
exit $exit_code
SCRIPT_EOF
    chmod 700 "$temp_script"
    
    # Test sudo functionality with multiple verification methods
    echo "  Testing basic sudo access..."
    local sudo_test_result=""
    
    # Method 1: Direct sudo test with password file
    if sudo_test_result=$(su - "$username" -c "\"$temp_script\" \"$temp_password_file\"" 2>/dev/null); then
        if [[ "$sudo_test_result" == "root" ]]; then
            echo "  ✓ Basic sudo test passed"
        else
            echo "  ✗ Basic sudo test failed: got '$sudo_test_result', expected 'root'"
            rm -f "$temp_script" "$temp_password_file"
            exit 1
        fi
    else
        echo "  ✗ Basic sudo test failed: command execution error"
        rm -f "$temp_script" "$temp_password_file"
        exit 1
    fi
    
    # Method 2: Test sudo group membership verification
    echo "  Testing sudo group membership..."
    local group_test=""
    if group_test=$(su - "$username" -c "groups" 2>/dev/null); then
        if echo "$group_test" | grep -q sudo; then
            echo "  ✓ Sudo group membership confirmed"
        else
            echo "  ✗ Sudo group membership test failed"
            rm -f "$temp_script" "$temp_password_file"
            exit 1
        fi
    else
        echo "  ✗ Group membership test failed"
        rm -f "$temp_script" "$temp_password_file"
        exit 1
    fi
    
    # Method 3: Test sudo configuration access
    echo "  Testing sudo configuration access..."
    local config_test_script="/tmp/sudo_config_test_$$_$(date +%s)"
    cat > "$config_test_script" << 'CONFIG_TEST_EOF'
#!/bin/bash
sudo -S -k -l 2>/dev/null < "$1" | grep -q "(ALL : ALL)" && echo "config_ok"
CONFIG_TEST_EOF
    chmod 700 "$config_test_script"
    
    local config_result=""
    if config_result=$(su - "$username" -c "\"$config_test_script\" \"$temp_password_file\"" 2>/dev/null); then
        if [[ "$config_result" == "config_ok" ]]; then
            echo "  ✓ Sudo configuration access confirmed"
        else
            echo "  ⚠ Sudo configuration test inconclusive (may be normal)"
        fi
    else
        echo "  ⚠ Sudo configuration test failed (may be normal depending on sudo config)"
    fi
    
    rm -f "$config_test_script"
    rm -f "$temp_script" "$temp_password_file"
    
    echo "Sudo access testing completed successfully"
    
    # ---------------------------------------------------------------------
    # 8) User Account Security Audit
    # ---------------------------------------------------------------------
    echo "Performing comprehensive user account security audit..."
    
    # Verify user account properties
    local user_info=$(getent passwd "$username")
    local uid=$(echo "$user_info" | cut -d: -f3)
    local gid=$(echo "$user_info" | cut -d: -f4)
    local home_dir=$(echo "$user_info" | cut -d: -f6)
    local shell=$(echo "$user_info" | cut -d: -f7)
    
    echo "User account properties:"
    echo "  Username: $username"
    echo "  UID: $uid"
    echo "  GID: $gid"
    echo "  Home: $home_dir"
    echo "  Shell: $shell"
    
    # Verify UID is in normal user range (1000+)
    if [[ $uid -lt 1000 ]]; then
        echo "  ⚠ UID is below 1000 (system user range)"
    else
        echo "  ✓ UID is in normal user range"
    fi
    
    # Verify home directory permissions
    local home_perms=$(stat -c %a "$home_dir" 2>/dev/null || echo "000")
    if [[ "$home_perms" == "700" ]]; then
        echo "  ✓ Home directory permissions are secure (700)"
    else
        echo "  ⚠ Home directory permissions: $home_perms (should be 700)"
        chmod 700 "$home_dir"
        echo "  ✓ Home directory permissions corrected to 700"
    fi
    
    # Verify shell is bash
    if [[ "$shell" == "/bin/bash" ]]; then
        echo "  ✓ Shell is set to /bin/bash"
    else
        echo "  ⚠ Shell is $shell (expected /bin/bash)"
    fi
    
    # Check for proper group memberships
    local user_groups=$(groups "$username")
    echo "  Groups: $user_groups"
    
    # Run comprehensive user security check
    echo ""
    check_user_security "$username" true
    echo ""
    
    # ---------------------------------------------------------------------
    # 9) Final System State Validation
    # ---------------------------------------------------------------------
    echo "Validating final system state..."
    
    # Verify system user count is reasonable
    local total_users=$(awk -F: '$3 >= 1000 {count++} END {print count+0}' /etc/passwd)
    echo "Total non-system users: $total_users"
    
    if [[ $total_users -gt 10 ]]; then
        echo "  ⚠ Large number of user accounts detected"
        echo "  Consider reviewing user accounts before SSH hardening"
    fi
    
    # Verify no conflicting user sessions
    local active_sessions=$(who | grep -c "$username" || echo "0")
    echo "Active sessions for $username: $active_sessions"
    
    # Final verification that user can be used for SSH
    if [[ -d "/home/$username" && -x "/bin/bash" ]]; then
        echo "  ✓ User account ready for SSH access"
    else
        echo "  ✗ User account setup incomplete"
        exit 1
    fi
    
    # Final system health check
    local TOTAL_TIME=$(($(date +%s) - START_TIME))
    echo ""
    echo "User creation completed successfully in ${TOTAL_TIME} seconds"
    echo "User '$username' is ready for SSH hardening configuration"
    
    # Check if this step requires a reboot
    check_current_reboot_needed "user" "4"
    
    # Save username to state file for use in subsequent steps
    mark_step_completed 4 "$username"
}

# Execute function if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    user
fi