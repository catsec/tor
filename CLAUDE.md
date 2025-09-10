# Debian 13 Security Setup Script

## Overview
A comprehensive bash script for setting up a secure Debian 13 server with SSH hardening, WireGuard VPN, and Tor proxy capabilities.

## Script Location
- Main script: `/Users/ram/dev/scripts/tor/setup.sh`
- Installed globally as: `/usr/local/bin/setup.sh`

## Steps Overview
1. **update** - Update system packages (`apt update && apt dist-upgrade`)
2. **packages** - Install security packages (`openssh-server ufw tor nyx nginx wireguard curl qrencode prosody prosody-modules lua-bit32 libjs-bootstrap4 libjs-jquery`)
3. **verify** - Verify all installations and services
4. **user** - Create non-root user with sudo privileges
5. **ssh** - Setup SSH key authentication and harden SSH config
6. **verifyssh** - Verify SSH connection is working (must run via SSH)
7. **wireguard** - Setup WireGuard VPN with selective routing
8. **tor** - Configure Tor proxy with secure settings
9. **site** - Setup hardened nginx site with demo page
10. **xmpp** - Install and configure XMPP server
11. **harden** - System and kernel hardening, UFW, AppArmor, no-logs
12. **info** - Display complete system configuration and usage info

## Key Features

### State Management
- Status file: `/tmp/debian_setup_status`
- Tracks completed steps and saves username
- Supports resume from any step
- Format: `step_number:username` (e.g., `4:myuser`)

### Command Line Options
```bash
./setup.sh                    # Normal execution (continues from last step)
./setup.sh -s step_name       # Force execute specific step
./setup.sh -c step_name       # Continue from step (updates state file)
./setup.sh -h                 # Show help
```

### Network Configuration
- **WireGuard Network**: `10.11.12.x/24`
  - Server: `10.11.12.1`
  - Client: `10.11.12.2`
- **Selective Routing**: Only routes traffic to server IP
- **Services Available via VPN**:
  - Tor SOCKS proxy: `10.11.12.1:9050`
  - SSH access: `10.11.12.1:22`

### Security Features
- SSH hardening (key-only auth, root disabled)
- User validation and sudo testing
- Firewall ready (UFW installed)
- Password requirements (12+ chars, mixed case, numbers)
- Public IP detection via external services

### Special Capabilities
- QR code generation for mobile WireGuard setup (optional)
- Real public IP detection using multiple services
- Comprehensive error handling and rollback
- Dependency validation between steps

## Dependencies Installed
- `openssh-server` - SSH server
- `ufw` - Uncomplicated Firewall
- `tor` - Tor anonymity network
- `nyx` - Tor monitoring tool
- `nginx` - Web server
- `wireguard` - VPN software
- `curl` - HTTP client for IP detection
- `qrencode` - QR code generation
- `prosody` - XMPP server for secure messaging
- `prosody-modules` - Additional modules for Prosody
- `lua-bit32` - Lua bit manipulation library
- `libjs-bootstrap4` - Bootstrap CSS framework for web interfaces
- `libjs-jquery` - jQuery JavaScript library

## Usage Patterns

### Initial Setup (as root)
```bash
# Run complete setup
./setup.sh

# Or step by step
./setup.sh -s update
./setup.sh -s packages
# ... etc
```

### After SSH Hardening (as user via SSH)
```bash
# Continue from SSH verification
sudo setup.sh

# Or specific step
sudo setup.sh -s wireguard
```

## Important Notes
- Steps 1-5: Run as root (fresh Debian default)
- Steps 6-12: Run as created user via SSH (requires sudo)
- Script copies itself to `/usr/local/bin/setup.sh` for global access
- SSH hardening forces script termination - must reconnect via SSH to continue
- WireGuard uses selective routing, not full tunnel
- Site serves only localhost (127.0.0.1:80) with hardened configuration

## Testing Commands
```bash
# Check service status
systemctl status ssh
systemctl status wg-quick@wg0
systemctl status tor
systemctl status nginx

# Verify firewall
ufw status

# Test Tor
curl --socks5 127.0.0.1:9050 https://check.torproject.org

# Check WireGuard
wg show

# Test hardened site
curl http://127.0.0.1
curl --socks5-hostname 127.0.0.1:9050 http://$(cat /var/lib/tor/nginx_hidden_service/hostname)
```

# Important Instructions for Claude
- NEVER use emojis or special characters in command line output or responses
- Keep all output plain text only
- Do what has been asked; nothing more, nothing less
- NEVER create files unless absolutely necessary
- ALWAYS prefer editing existing files to creating new ones
- NEVER proactively create documentation files unless explicitly requested

## Completion Requirements
When asked to perform any task across multiple files or locations:
1. ALWAYS use Grep or Glob to identify ALL instances before starting
2. Create a comprehensive TodoWrite list covering EVERY file/location found
3. Work through ALL items systematically without stopping until complete
4. NEVER claim completion unless ALL instances have been processed
5. If interrupted, always resume from where you left off using the todo list