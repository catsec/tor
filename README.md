# Tor-Only XMPP Server Setup

```
███╗   ██╗ ██████╗     ██╗      ██████╗  ██████╗ ███████╗
████╗  ██║██╔═══██╗    ██║     ██╔═══██╗██╔════╝ ██╔════╝
██╔██╗ ██║██║   ██║    ██║     ██║   ██║██║  ███╗███████╗
██║╚██╗██║██║   ██║    ██║     ██║   ██║██║   ██║╚════██║
██║ ╚████║╚██████╔╝    ███████╗╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═══╝ ╚═════╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝
```

## 🚫 ZERO LOGGING POLICY
**THIS SYSTEM LOGS ABSOLUTELY NOTHING. NO TRACES. NO RECORDS. MAXIMUM PRIVACY.**

A fully automated script to deploy a secure, privacy-focused XMPP server accessible only via Tor hidden services on Ubuntu 24.04.3 LTS.

## 🔐 Features

- **Complete Tor Integration** - All services accessible only via .onion addresses
- **XMPP with OMEMO** - End-to-end encrypted messaging with modern XMPP features
- **Zero Logging** - Maximum privacy with no stored logs or traces
- **Web Admin Interface** - Easy server management through Tor
- **File Transfers** - Secure file sharing via SOCKS5 proxy
- **Service Isolation** - Four separate .onion addresses for security compartmentalization
- **Idempotent Setup** - Safe to rerun, uses stamp files to track progress

## 🎯 Architecture

The script creates four isolated hidden services:

| Service | Purpose | Access |
|---------|---------|--------|
| 🔑 SSH | Server administration | `ssh123abc.onion:22` |
| 🌐 Web Demo | Public landing page | `http://web456def.onion/` |
| 💬 XMPP | Messaging & file transfer | `xmpp789ghi.onion:5222/5269` |
| ⚙️ Admin Panel | Web management interface | `http://admin012jkl.onion:5280/admin/` |

## 🚀 Quick Start

### Prerequisites

- Fresh Ubuntu 24.04.3 LTS server (minimal install)
- Root access
- GitHub account with SSH public keys

### Installation

**Option 1: Run directly from GitHub**
```bash
curl -fsSL https://raw.githubusercontent.com/catsec/tor/main/setup.sh | sudo bash
```

**Option 2: Download and run**
```bash
wget https://raw.githubusercontent.com/catsec/tor/main/setup.sh
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
- Provide your GitHub username for SSH key retrieval
- Choose whether to continue via SSH after initial setup

## 📋 Setup Process

The script performs these steps automatically:

1. **System Updates** - Updates packages and installs dependencies
2. **SSH Configuration** - Hardens SSH and sets up key-based authentication
3. **Tor Setup** - Configures hidden services for all components
4. **Nginx Setup** - Deploys dark web landing page
5. **Prosody Installation** - Installs and configures XMPP server
6. **OMEMO Configuration** - Enables end-to-end encryption
7. **SSL Certificates** - Generates certificates for .onion domains
8. **Admin User Creation** - Creates admin account with random password
9. **Zero Logging** - Disables all system and service logging
10. **Firewall Setup** - Configures UFW for Tor-only access

## 🔧 Configuration

### XMPP Features

- **OMEMO Encryption** - Modern E2EE with forward secrecy
- **Multi-User Chat** - Group messaging support
- **File Transfers** - Secure file sharing via proxy65
- **Message Archive Management** - Optional message history
- **Web Admin Interface** - User management and server statistics

### Security Features

- **No LAN Binding** - All services listen only on 127.0.0.1
- **Automatic Log Purging** - Hourly cleanup of any log files
- **SSH Hardening** - Key-only authentication, root login disabled
- **Firewall Protection** - UFW configured for localhost-only access
- **Service Isolation** - Each service uses separate .onion address

## 📊 After Installation

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

Web Admin Interface (separate .onion):
   URL: http://admin012jkl.onion:5280/admin/
   Login: admin@xmpp789ghi.onion (password from credentials file above)
```

## 👥 User Management

### Retrieving Admin Credentials
```bash
# View admin login credentials
sudo cat /var/lib/torstack-setup/admin_credentials.txt

# Shows:
# JID: admin@your-xmpp-onion.onion
# Password: [your-22-character-password]
```

### Creating Users
```bash
# Via command line
prosodyctl adduser username@xmpp789ghi.onion

# Via web admin interface
# 1. Navigate to http://admin012jkl.onion:5280/admin/
# 2. Login with admin credentials from file above
# 3. Go to Users section to add new accounts
```

### XMPP Client Setup

Configure any OMEMO-capable XMPP client:
- **Server:** Your XMPP .onion address
- **Port:** 5222
- **Encryption:** OMEMO (recommended)
- **Proxy:** SOCKS5 127.0.0.1:9050 (Tor)

## 🛠️ Advanced Usage

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
- `ufw` - Firewall configuration
- `nologs` - Zero logging setup
- `unattended` - Automatic updates
- `cleanup` - Remove unnecessary services

### Logs and Debugging
```bash
# Setup log (only log that exists)
tail -f /var/lib/torstack-setup/setup.log

# Check service status
systemctl status tor prosody nginx ssh

# View .onion addresses
cat /var/lib/tor/*/hostname
```

## 🔐 Security Considerations

### What This Script Does for Privacy
- ✅ **No external connectivity** - Services only accessible via Tor
- ✅ **Zero logging** - No traces left on the system
- ✅ **Service isolation** - Each service on separate .onion
- ✅ **Strong encryption** - OMEMO for messages, TLS for transport
- ✅ **Automatic updates** - Security patches applied automatically

### What You Should Do
- 🔑 **Secure your SSH keys** - Keep private keys safe
- 📱 **Use secure clients** - Choose OMEMO-capable XMPP apps
- 🔄 **Regular backups** - Backup .onion private keys if needed
- 👥 **User management** - Only create accounts for trusted users
- 🕵️ **Monitor usage** - Check admin panel for suspicious activity

## 🚨 Disclaimer

This software is provided for educational and privacy purposes. Users are responsible for:
- Complying with local laws and regulations
- Securing their systems and maintaining operational security
- Understanding the risks of running Tor hidden services
- Keeping software updated and monitoring for security issues

The authors are not responsible for misuse or legal consequences.

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues:** Use GitHub Issues for bug reports
- **Security:** Report security issues privately via email
- **Documentation:** Check the wiki for additional guides

---

**⚠️ Remember:** This creates a Tor-only server. All access requires Tor Browser or proper SOCKS5 proxy configuration.