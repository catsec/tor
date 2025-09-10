# Debian 13 Security Setup Script

A comprehensive bash script for setting up a secure Debian 13 server with SSH hardening, WireGuard VPN, Tor proxy, XMPP messaging, and system hardening.

## Features

- **Automated Security Setup**: Complete server hardening in 12 steps
- **SSH Hardening**: Key-only authentication, root access disabled
- **WireGuard VPN**: Selective routing with QR code generation
- **Tor Proxy**: Anonymous browsing with hidden service support
- **XMPP Server**: Secure messaging with Prosody
- **System Hardening**: UFW firewall, AppArmor, kernel hardening
- **Resume Capability**: Continue from any step if interrupted

## Quick Start

```bash
# Clone and run as root on fresh Debian 13
git clone <repository-url>
cd tor
chmod +x setup.sh
./setup.sh
```

## Installation Steps

| Step | Name | Description | User |
|------|------|-------------|------|
| 1 | update | System package updates | root |
| 2 | packages | Install security packages | root |
| 3 | verify | Verify installations | root |
| 4 | user | Create non-root user | root |
| 5 | ssh | SSH hardening | root |
| 6 | verifyssh | Verify SSH connection | user (via SSH) |
| 7 | wireguard | Setup WireGuard VPN | user |
| 8 | tor | Configure Tor proxy | user |
| 9 | site | Setup nginx with demo | user |
| 10 | xmpp | Install XMPP server | user |
| 11 | harden | System hardening | user |
| 12 | info | Display configuration | user |

## Network Configuration

**WireGuard VPN**: `10.11.12.x/24`
- Server: `10.11.12.1`
- Client: `10.11.12.2`
- Selective routing (only to server IP)

**Services via VPN**:
- Tor SOCKS proxy: `10.11.12.1:9050`
- SSH access: `10.11.12.1:22`

## Usage

```bash
# Normal execution (continues from last step)
./setup.sh

# Force execute specific step
./setup.sh -s step_name

# Continue from step (updates state)
./setup.sh -c step_name

# Show help
./setup.sh -h
```

## State Management

Status tracked in `/tmp/debian_setup_status`:
- Format: `step_number:username`
- Supports resume from interruption
- Maintains user context across steps

## Security Features

- SSH key-only authentication
- Root login disabled
- UFW firewall configuration
- Password requirements (12+ chars, mixed case, numbers)
- AppArmor profiles
- Kernel hardening parameters
- No-logs configuration

## Installed Packages

- `openssh-server` - SSH server
- `ufw` - Firewall
- `tor` - Anonymity network
- `nyx` - Tor monitoring
- `nginx` - Web server
- `wireguard` - VPN software
- `prosody` - XMPP server
- `curl` - HTTP client
- `qrencode` - QR code generation

## Testing

```bash
# Check services
systemctl status ssh wg-quick@wg0 tor nginx prosody

# Test Tor
curl --socks5 127.0.0.1:9050 https://check.torproject.org

# Test WireGuard
wg show

# Test local site
curl http://127.0.0.1
```

## Important Notes

- **Steps 1-5**: Run as root on fresh system
- **Steps 6-12**: Run as created user via SSH with sudo
- SSH hardening forces script termination - reconnect via SSH to continue
- WireGuard uses selective routing, not full tunnel
- Script copies itself to `/usr/local/bin/setup.sh` for global access

## Requirements

- Fresh Debian 13 installation
- Root access for initial setup
- SSH client for steps 6-12
- Internet connection for package installation

## License

MIT License - see LICENSE file for details