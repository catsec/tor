# Tor-Only XMPP Server Setup

```
███╗   ██╗ ██████╗     ██╗      ██████╗  ██████╗ ███████╗
████╗  ██║██╔═══██╗    ██║     ██╔═══██╗██╔════╝ ██╔════╝
██╔██╗ ██║██║   ██║    ██║     ██║   ██║██║  ███╗███████╗
██║╚██╗██║██║   ██║    ██║     ██║   ██║██║   ██║╚════██║
██║ ╚████║╚██████╔╝    ███████╗╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═══╝ ╚═════╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝
```

## ZERO LOGGING POLICY
**THIS SYSTEM LOGS ABSOLUTELY NOTHING. NO TRACES. NO RECORDS. MAXIMUM PRIVACY.**

A fully automated script to deploy a secure, privacy-focused XMPP server accessible only via Tor hidden services on Ubuntu 24.04.3 LTS.

## Features

- **Complete Tor Integration** - All services accessible only via .onion addresses
- **XMPP with OMEMO** - End-to-end encrypted messaging with modern XMPP features
- **Zero Logging** - Maximum privacy with no stored logs or traces
- **Command Line Admin** - Secure server management via prosodyctl
- **File Transfers** - Secure file sharing via SOCKS5 proxy
- **Service Isolation** - Three separate .onion addresses for security compartmentalization
- **Idempotent Setup** - Safe to rerun, uses stamp files to track progress

## Architecture

The script creates three isolated hidden services:

| Service | Purpose | Access |
|---------|---------|--------|
| SSH | Server administration | `ssh123abc.onion:22` |
| Web Demo | Public landing page | `http://web456def.onion/` |
| XMPP | Messaging & file transfer | `xmpp789ghi.onion:5222/5269` |

## Quick Start

### Prerequisites

- Fresh Ubuntu 24.04.3 LTS server (minimal install) **with full disk encryption**
- Root access
- SSH client on your local machine (Linux/macOS/Windows)

**WARNING CRITICAL: Install Ubuntu with full disk encryption (LUKS) during setup. The script will warn if disk encryption is missing.**

### Installation

**Option 1: Run directly from GitHub**
```bash
curl -fsSL https://raw.githubusercontent.com/catsec/tor/refs/heads/main/setup.sh | sudo bash
```

**Option 2: Download and run**
```bash
wget https://raw.githubusercontent.com/catsec/tor/refs/heads/main/setup.sh
sudo bash setup.sh
```

**Option 3: Clone the repository**
```bash
git clone https://github.com/catsec/tor.git
cd tor
sudo bash setup.sh
```

**Follow the prompts:**
- Enter your non-root username for SSH access
- Select your operating system (Linux/macOS/Windows) for SSH key generation instructions
- Generate SSH key pair on your local machine and paste the public key
- Choose enhanced anonymity options (Tor bridges)
- Choose whether to continue via SSH after initial setup

## Setup Process

The script performs these steps automatically:

1. **System Updates** - Updates packages and installs dependencies
2. **SSH Setup** - Configures SSH and guides you through secure key generation
3. **SSH Key Upload** - Interactive setup to add your public SSH key securely
4. **Tor Setup** - Configures hidden services for all components
5. **Nginx Setup** - Deploys dark web landing page
6. **Prosody Installation** - Installs and configures XMPP server
7. **OMEMO Configuration** - Enables end-to-end encryption
8. **SSL Certificates** - Generates certificates for .onion domains
9. **Admin User Creation** - Creates admin account with random password
10. **System Hardening** - Tor-only networking, APT proxy, service isolation
11. **Zero Logging** - Disables all system and service logging
12. **Firewall Setup** - Configures UFW for Tor-only access

## SSH Key Setup

The script now includes an interactive SSH key setup that eliminates the need for GitHub accounts:

### Supported Platforms
- **Linux** - Uses standard `ssh-keygen` command
- **macOS** - Uses standard `ssh-keygen` command  
- **Windows** - Supports both built-in SSH client and PuTTY

### Process
1. Select your operating system
2. Follow platform-specific instructions to generate an Ed25519 key pair
3. Copy your public key and paste it into the script
4. Script validates and installs the key securely

### Privacy Benefits
- **No GitHub dependency** - Your identity isn't linked to public repositories
- **Local key generation** - Keys never leave your machine until you explicitly provide them
- **Validation** - Script ensures key format is correct before proceeding

## Disk Encryption Requirements

### **Why Full Disk Encryption is Critical**

Without full disk encryption, your Tor server provides **zero privacy protection**:

- UNENCRYPTED **SSH private keys** can be recovered from disk
- UNENCRYPTED **.onion private keys** are exposed to anyone with disk access  
- UNENCRYPTED **XMPP conversations** may be recoverable from swap/temp files
- UNENCRYPTED **Server compromise** exposes all historical data

### **Ubuntu Installation with Encryption**

**During Ubuntu 24.04.3 installation:**

1. **Choose "Advanced installation"** 
2. **Enable "Encrypt the new Ubuntu installation"**
3. **Choose a strong passphrase** (20+ characters recommended)
4. **Complete normal installation**

**Alternative: Manual LUKS setup:**
```bash
# Example for advanced users (DESTRUCTIVE - backup first!)
cryptsetup luksFormat /dev/sda2
cryptsetup luksOpen /dev/sda2 ubuntu-encrypted
mkfs.ext4 /dev/mapper/ubuntu-encrypted
# Install Ubuntu to /dev/mapper/ubuntu-encrypted
```

### **Post-Installation Verification**

The script automatically checks disk encryption and will show:

```
[9] Disk Encryption Status:
  Root filesystem: OK LUKS encrypted  
  Swap: OK Encrypted
```

**If you see encryption warnings:**
- CRITICAL **Stop immediately** - Your privacy is compromised
- BACKUP **Back up .onion keys**: `sudo cp -r /var/lib/tor /backup/location`
- RESTORE **Reinstall with encryption** following the guide above
- **Restore .onion keys** using backup/restore feature

### **What the Script Does for Disk Security**

1. **Detects** LUKS/dm-crypt on root filesystem
2. **Encrypts swap** with random keys (if unencrypted)
3. **Removes** unencrypted swap files
4. **Creates encrypted tmpfs** for /tmp, /var/tmp, /dev/shm
5. **Secures** temporary file handling
6. **Warns** about any unencrypted storage

## Configuration

### XMPP Features

- **OMEMO Encryption** - Modern E2EE with forward secrecy
- **Multi-User Chat** - Group messaging support
- **File Transfers** - Secure file sharing via proxy65
- **Message Archive Management** - Optional message history
- **Command Line Administration** - Secure user and server management

### Security Features

- **Complete Network Isolation** - All services bind only to localhost (127.0.0.1)
- **Tor-Only Networking** - APT configured to use Tor SOCKS proxy for updates
- **Enhanced Anonymity** - Optional Tor bridge support for restrictive networks
- **Outbound Connection Blocking** - UFW blocks all outbound except Tor network
- **IPv6 Disabled** - Complete IPv6 stack disabled for reduced attack surface
- **Kernel Hardening** - KASLR, ASLR, syscall restrictions, memory protections
- **MAC Randomization** - Network interface MAC addresses randomized
- **Automatic Monitoring** - 5-minute health checks with alerting
- **Configuration Validation** - Built-in validation for all services
- **Disk Security** - Full encryption detection, encrypted swap, secure tmpfs
- **Secure Backups** - AES-256-GCM encrypted backups with integrity verification
- **Emergency Wipe** - Secure data destruction for compromised systems
- **Automatic Log Purging** - Hourly cleanup of any log files
- **SSH Hardening** - Key-only authentication, localhost binding, root disabled
- **Service Isolation** - Each service uses separate .onion address
- **DNS Hardening** - systemd-resolved configured for localhost only
- **Endpoint Detection & Response** - OSSEC HIDS with custom Tor server rules
- **Malicious Activity Alerts** - Real-time security notifications via XMPP
- **File Integrity Monitoring** - Real-time monitoring of critical Tor files
- **Rootkit Detection** - Advanced malware detection and system compromise alerts
- **Service Leak Prevention** - Blocks 15+ Ubuntu services that bypass proxy settings
- **Network Leak Detection** - Built-in testing for services that might contact internet directly
- **Ubuntu Telemetry Blocking** - Disables Ubuntu Advantage, snap store, crash reporting, MOTD ads
- **Automatic Time Synchronization** - Daily time sync via Tor to prevent clock drift issues
- **Comprehensive Leak Testing** - 8-point verification system for zero-leak operation
- **Time Drift Monitoring** - Real-time monitoring of clock accuracy (critical for Tor)

## After Installation

The script provides connection details for all services:

```
SSH via Tor:  torsocks ssh -p 22 username@ssh123abc.onion
Web (Tor):    http://web456def.onion/

==== XMPP Server Ready ====
Admin account created:
JID: admin@xmpp789ghi.onion
Password: [automatically generated 22-character password]

IMPORTANT: Credentials are stored at: /var/lib/torstack-setup/admin_credentials.txt
To view credentials later: sudo cat /var/lib/torstack-setup/admin_credentials.txt

XMPP Connection (separate .onion):
   Server: xmpp789ghi.onion
   Port: 5222
   OMEMO encryption: Supported
   Use Tor proxy (SOCKS5: 127.0.0.1:9050)

Admin Interface:
   Command Line: prosodyctl (recommended)
   Telnet: telnet 127.0.0.1 5582 (from server console)
   Note: Web admin disabled for security
```

## 👥 User Management

### Retrieving All Information
```bash
# Quick access to everything (installed by setup script)
info

# Shows all onion addresses, admin credentials, and XMPP management commands
```

### Creating Users
```bash
# Add new user
prosodyctl adduser username@xmpp789ghi.onion

# Change user password
prosodyctl passwd username@xmpp789ghi.onion

# Delete user
prosodyctl deluser username@xmpp789ghi.onion

# List all users
prosodyctl list users

# Check server status
prosodyctl status
```

### XMPP Client Setup

Configure any OMEMO-capable XMPP client:
- **Server:** Your XMPP .onion address
- **Port:** 5222
- **Encryption:** OMEMO (recommended)
- **Proxy:** SOCKS5 127.0.0.1:9050 (Tor)

## Advanced Usage

### Rerunning the Script
```bash
# Force reinstall all components
sudo bash setup.sh --force

# Redo specific step
sudo bash setup.sh --redo prosody
```

### Available Steps
- `prompts` - User input and validation
- `packages` - System package installation
- `early_ssh` - Initial SSH setup with connection prompt
- `sshd` - Final SSH hardening
- `tor` - Tor and hidden services configuration
- `nginx` - Web server and demo page
- `prosody` - XMPP server installation
- `prosody_config` - Basic XMPP configuration
- `prosody_onion` - .onion domain and SSL setup
- `help_script` - Install info script with credentials and admin commands
- `system_hardening` - Complete Tor-only system isolation and hardening
- `ufw` - Firewall configuration
- `nologs` - Zero logging setup
- `unattended` - Automatic updates
- `cleanup` - Remove unnecessary services

### Quick Access
```bash
# Show all credentials and XMPP admin commands
info

# Or use full path
/usr/local/bin/info.sh
```

### Server Administration
```bash
# User management
prosodyctl adduser newuser@your-xmpp-onion.onion
prosodyctl passwd user@your-xmpp-onion.onion
prosodyctl deluser user@your-xmpp-onion.onion

# Server management
prosodyctl status
prosodyctl start/stop/restart
prosodyctl reload

# Interactive admin console (from server)
telnet 127.0.0.1 5582
```

### Logs and Debugging
```bash
# Setup log (only log that exists)
tail -f /var/lib/torstack-setup/setup.log

# Check service status
systemctl status tor prosody nginx ssh

# View .onion addresses
cat /var/lib/tor/*/hostname
```

## Security Considerations

### What This Script Does for Privacy
- YES **No external connectivity** - Services only accessible via Tor
- YES **Zero logging** - No traces left on the system
- YES **Service isolation** - Each service on separate .onion
- YES **Strong encryption** - OMEMO for messages, TLS for transport
- YES **Automatic updates** - Security patches applied automatically

### What You Should Do
- SSH **Secure your SSH keys** - Keep private keys safe
- MOBILE **Use secure clients** - Choose OMEMO-capable XMPP apps
- RESTORE **Regular backups** - Backup .onion private keys if needed
- **User management** - Only create accounts for trusted users
- MONITOR **Monitor usage** - Use prosodyctl to check server status and logs

## Disclaimer

This software is provided for educational and privacy purposes. Users are responsible for:
- Complying with local laws and regulations
- Securing their systems and maintaining operational security
- Understanding the risks of running Tor hidden services
- Keeping software updated and monitoring for security issues

The authors are not responsible for misuse or legal consequences.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Management & Monitoring

### **Built-in Tools**
```bash
# Test all connectivity (includes XMPP port testing)
sudo bash setup.sh --test-connectivity

# Validate all configuration files
sudo bash setup.sh --verify-config

# Emergency secure data wipe (DESTRUCTIVE)
sudo bash setup.sh --wipe-data

# View system information and credentials
info

# Check system health manually
tor-monitor.sh

# View system alerts
cat /var/lib/torstack-setup/alerts.txt

# Check monitoring status
systemctl status tor-monitor.timer
```

### **Backup & Recovery**
The script automatically creates encrypted backups of your .onion private keys:

```bash
# Backup location
/var/lib/torstack-setup/onion-keys-backup.tar.gz.enc

# View backup password
sudo cat /var/lib/torstack-setup/backup-password.txt

# Restore from backup (if system is rebuilt)
sudo bash setup.sh --restore-backup <password>
```

**WARNING CRITICAL:** Save the backup password in a secure location. Without it, you cannot restore your .onion addresses.

### **Troubleshooting**

**SSH Access Issues:**
```bash
# Re-setup SSH keys
sudo bash setup.sh --redo early_ssh

# Check SSH status
systemctl status ssh
```

**Tor Connectivity Problems:**
```bash
# Restart Tor service
systemctl restart tor

# Check Tor status
systemctl status tor

# Test connectivity
curl --socks5-hostname 127.0.0.1:9050 http://check.torproject.org
```

**Service Failures:**
```bash
# Check all services
sudo bash setup.sh --test-connectivity

# Restart specific service
systemctl restart [tor|ssh|nginx|prosody]

# Re-run specific setup step
sudo bash setup.sh --redo <step_name>
```

**Nginx Custom Page Issues:**
```bash
# Diagnose why default nginx page is showing
sudo bash setup.sh --diagnose-nginx

# Fix nginx configuration
sudo bash setup.sh --redo nginx

# Manual fixes if needed
sudo rm -f /etc/nginx/sites-enabled/default*
sudo systemctl restart nginx
```

**Time Synchronization Issues:**
```bash
# Check if time drift is causing Tor failures
tor-time-sync.sh

# Manual time sync if automatic sync fails
sudo date -s "$(curl -s --socks5-hostname 127.0.0.1:9050 http://worldtimeapi.org/api/timezone/UTC | grep -o '"datetime":"[^"]*' | cut -d'"' -f4)"

# Restart Tor after time correction
sudo systemctl restart tor

# Check time sync cron jobs
cat /etc/crontab | grep time-sync

# Common time-related Tor errors to watch for:
sudo journalctl -u tor | grep -i "time\|clock\|consensus"
```

**Network Leak Detection:**
```bash
# Test for services bypassing Tor
sudo bash setup.sh --test-leaks

# Shows comprehensive report of:
# - Active external connections
# - Services listening on external interfaces  
# - Problematic systemd services
# - DNS configuration issues
# - APT proxy settings
# - Snap packages (bypass proxy)
# - Time sync services
# - Ubuntu telemetry services
```

**Time Synchronization Management:**
```bash
# Check current time drift
tor-time-sync.sh

# Force time synchronization via Tor
tor-time-sync.sh --force

# View time sync logs
tail -f /var/log/tor-time-sync.log

# Time sync runs automatically:
# - Daily at 3 AM (checks drift, syncs if needed)
# - Weekly at 4 AM Sunday (forced sync)
```

## Endpoint Detection & Response (EDR)

The script automatically installs and configures OSSEC HIDS for advanced threat detection:

### **Automatic Detection**
- **File Integrity Monitoring** - Real-time monitoring of Tor keys, configuration files, and system directories
- **Rootkit Detection** - Scans for malware, trojans, and system compromises  
- **Process Monitoring** - Detects suspicious processes and unauthorized access attempts
- **Custom Rules** - Tor server-specific detection rules for privacy threats

### **XMPP Security Alerts**
Get real-time security notifications via XMPP for critical events:

```bash
# Configure XMPP alerts
sudo nano /var/lib/torstack-setup/xmpp-alerts.conf

# Example configuration:
enabled=true
server=your-xmpp-onion.onion
username=alerts@your-xmpp-onion.onion  
password=your-alert-bot-password
recipient=admin@your-xmpp-onion.onion
use_tor=true
```

**Enable alerts after configuration:**
```bash
# Restart alert service
sudo systemctl restart ossec-xmpp-alerts.timer

# Test alert system
sudo /usr/local/bin/ossec-xmpp-alert.py

# Check alert status
systemctl status ossec-xmpp-alerts.timer
```

### **Threat Detection Rules**
The EDR system includes custom rules for:
- CRITICAL **Critical**: Tor private key access attempts
- CRITICAL **Critical**: Tor daemon termination  
- CRITICAL **Critical**: SSH brute force attacks
- WARNING **Warning**: Configuration file modifications
- WARNING **Warning**: New user account creation
- CRITICAL **Critical**: Services listening on external interfaces
- CRITICAL **Critical**: Suspicious process execution

### **EDR Management**
```bash
# Check EDR status
sudo /var/ossec/bin/ossec-control status

# View security alerts
cat /var/lib/torstack-setup/alerts.txt

# Manual alert processing
sudo /usr/local/bin/ossec-xmpp-alert.py

# View OSSEC logs
sudo tail -f /var/ossec/logs/alerts/alerts.log

# Restart EDR services
sudo systemctl restart ossec ossec-xmpp-alerts.timer
```

## Important Caveats & Limitations

### **Time Synchronization**
- **No NTP services** - All time sync services are disabled to prevent leaks
- **Manual time management** - System relies on daily Tor-based time sync
- **Clock drift impact** - Tor fails with >5 minutes drift, becomes unreliable with >1 minute
- **Automatic solution** - Daily cron jobs sync time via Tor APIs

### **System Updates**
- **Manual updates only** - Automatic updates disabled for security
- **APT via Tor** - All package updates go through Tor (slower but private)
- **Regular maintenance required** - Run `apt update && apt upgrade` monthly

### **Performance Considerations**  
- **Tor latency** - All connections 3-10x slower than direct
- **Limited bandwidth** - Tor network capacity constraints
- **CPU overhead** - Tor encryption uses additional CPU resources

### **Emergency Recovery**
- **Physical access may be required** - If Tor fails, SSH becomes unreachable
- **No remote monitoring** - External uptime services cannot be used
- **Time-sensitive issues** - Clock drift can cause complete connectivity loss

### **Zero-Leak Design**
- **15+ services disabled** - Ubuntu telemetry, updates, error reporting blocked
- **Tor-only networking** - Firewall blocks all direct internet access  
- **No backup services** - System designed for ephemeral operation
- **Verification tools** - Built-in leak detection tests all traffic paths

## Command Reference

### **Setup & Maintenance**
```bash
sudo bash setup.sh                      # Full installation
sudo bash setup.sh --force              # Force reinstall all components
sudo bash setup.sh --redo <step>        # Reinstall specific step
sudo bash setup.sh --help               # Show all options
```

### **Diagnostic & Testing**
```bash
sudo bash setup.sh --test-connectivity  # Test Tor and service connectivity
sudo bash setup.sh --test-leaks         # Comprehensive leak detection
sudo bash setup.sh --diagnose-nginx     # Debug custom page issues
sudo bash setup.sh --verify-config      # Validate configurations
```

### **System Information**
```bash
info                                     # Show all server info and credentials
tor-monitor.sh                          # Manual health check
tor-time-sync.sh                        # Check/sync time via Tor
cat /var/lib/torstack-setup/alerts.txt  # View security alerts
```

### **XMPP Management**
```bash
prosodyctl adduser user@your-onion.onion # Add XMPP user
prosodyctl passwd user@your-onion.onion  # Change user password
prosodyctl deluser user@your-onion.onion # Delete user
prosodyctl status                        # Check XMPP server status
```

### **Emergency Commands**
```bash
sudo bash setup.sh --wipe-data          # Secure data wipe (DESTRUCTIVE)
sudo bash setup.sh --restore-backup     # Restore from encrypted backup
systemctl status tor ssh nginx prosody  # Check service status
```

## Support

- **Issues:** Use GitHub Issues for bug reports
- **Security:** Report security issues privately via email
- **Documentation:** Check the wiki for additional guides
- **Recovery:** Use built-in backup/restore system for .onion keys

---

**WARNING Remember:** This creates a Tor-only server. All access requires Tor Browser or proper SOCKS5 proxy configuration.