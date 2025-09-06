# Network Packet Scanner TUI

A comprehensive Terminal User Interface (TUI) application for capturing and analyzing network packets in real-time. Supports extensive packet types including TCP, UDP, ICMP, ARP, IPv6, and many application protocols.

## 🚀 Features

### **Real-time Packet Capture**
- **Layer 2 Protocols**: Ethernet, ARP, STP, LLC/SNAP, 802.11 WiFi
- **Layer 3 Protocols**: IPv4, IPv6, ICMPv4, ICMPv6, IGMP
- **Layer 4 Protocols**: TCP, UDP, SCTP
- **Application Protocols**: HTTP/HTTPS, DNS, DHCP, NTP, SNMP, SSH, FTP, SMTP, etc.

### **Enhanced Protocol Analysis**
- **TCP Services**: HTTP, HTTPS, SSH, FTP, Telnet, SMTP, POP3, IMAP, RDP, VNC
- **Database Protocols**: MySQL, PostgreSQL, SQL Server, Oracle, Redis, MongoDB
- **Network Services**: DNS, DHCP, NTP, SNMP, Syslog, RADIUS, BGP
- **VPN/Security**: OpenVPN, IPSec/IKE, L2TP, TLS/SSL analysis
- **Virtualization**: VXLAN overlay networks

### **Advanced TUI Interface**
- Real-time packet display with Rich formatting
- Protocol statistics and filtering
- Detailed packet inspection with hex dump
- Connection state tracking
- Network topology visualization

### **Security Analysis**
- Port scan detection algorithms
- DoS attack pattern recognition
- Suspicious traffic identification
- Connection anomaly detection
- Protocol-specific threat analysis

### **Filtering & Search**
- BPF (Berkeley Packet Filter) expressions
- Protocol-based filtering (TCP, UDP, ICMP, etc.)
- IP address and port number filtering
- Size-based and time-range filtering
- Regex pattern matching on packet content

## 📦 Installation

### **Linux (All Distributions)**

**One-click Setup & Run:**
```bash
# Clone the repository
git clone <repository-url>
cd net-scan

# Make executable and run (handles everything automatically)
chmod +x net-scan-linux.sh
sudo ./net-scan-linux.sh
```

The Linux script automatically:
- Detects your Linux distribution (Arch, Debian/Ubuntu, RedHat/Fedora)
- Installs system dependencies if needed
- Creates and manages virtual environment
- Installs Python requirements
- Starts packet capture

### **Windows**

**One-click Setup & Run:**
```batch
REM Download and extract the repository
REM Right-click on net-scan-windows.bat and "Run as Administrator"
net-scan-windows.bat
```

**Requirements for Windows:**
- Python 3.8+ ([Download here](https://python.org))
- Npcap packet capture driver ([Download here](https://nmap.org/npcap/))
- Administrator privileges

### **Manual Installation (Advanced Users)**
```bash
# Create virtual environment manually
python -m venv venv
source venv/bin/activate  # Linux
# OR
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Run tests to verify
python test.py
```

## 🎯 Usage

### **📋 Quick Reference**

| Command | Description |
|---------|-------------|
| `sudo ./net-scan-linux.sh` | Start with auto-detected interface (Linux) |
| `net-scan-windows.bat` | Start with auto-detected interface (Windows) |
| `-i eth0` | Specify network interface |
| `-f "tcp port 80"` | Apply packet filter |
| `-a` | Use advanced TUI interface |
| `-l` | List available network interfaces |
| `-h` | Show help and all options |

### **🐧 Linux Commands**

**Basic Usage:**
```bash
# Start packet capture (auto-detects best interface)
sudo ./net-scan-linux.sh

# List available network interfaces first
sudo ./net-scan-linux.sh -l
# Output: lo, eth0, wlan0 (default)

# Capture on specific interface
sudo ./net-scan-linux.sh -i wlan0

# Show help and all options
sudo ./net-scan-linux.sh -h
```

**Traffic Filtering:**
```bash
# Capture only HTTP traffic
sudo ./net-scan-linux.sh -f "tcp port 80"

# Capture HTTP and HTTPS traffic
sudo ./net-scan-linux.sh -f "tcp port 80 or tcp port 443"

# Monitor specific host
sudo ./net-scan-linux.sh -f "host 192.168.1.1"

# Capture UDP DNS traffic
sudo ./net-scan-linux.sh -f "udp port 53"

# Monitor local network traffic
sudo ./net-scan-linux.sh -f "net 192.168.1.0/24"
```

**Interface Options:**
```bash
# Use simple interface (default - clean table view)
sudo ./net-scan-linux.sh

# Use advanced interface (interactive widgets)
sudo ./net-scan-linux.sh -a

# Combine interface and filter
sudo ./net-scan-linux.sh -i eth0 -f "tcp" -a
```

### **🪟 Windows Commands**

**Basic Usage:**
```batch
REM Start packet capture (run as Administrator)
net-scan-windows.bat

REM List available network interfaces
net-scan-windows.bat -l

REM Capture on specific interface
net-scan-windows.bat -i "Ethernet"

REM Show help
net-scan-windows.bat -h
```

**Traffic Filtering:**
```batch
REM Capture web traffic
net-scan-windows.bat -f "tcp port 80 or tcp port 443"

REM Monitor email traffic
net-scan-windows.bat -f "tcp port 25 or tcp port 110 or tcp port 143"

REM Capture large packets
net-scan-windows.bat -f "greater 1000"
```

### **⚙️ Direct Python Usage (Advanced)**

If you want to use the Python script directly:

```bash
# Activate virtual environment first
source venv/bin/activate  # Linux
# OR
venv\Scripts\activate     # Windows

# Basic usage
sudo venv/bin/python main.py

# List available interfaces
sudo venv/bin/python main.py -l

# Specify network interface
sudo venv/bin/python main.py -i wlan0

# Use simple interface (default)
sudo venv/bin/python main.py --simple

# Use advanced interface
sudo venv/bin/python main.py --advanced-tui

# Apply filters
sudo venv/bin/python main.py -f "tcp port 80"
sudo venv/bin/python main.py -f "host 192.168.1.1"
sudo venv/bin/python main.py -f "udp port 53"
```

## 📚 Filter Examples

### **Common Traffic Types**
```bash
# Web traffic (HTTP/HTTPS)
-f "tcp port 80 or tcp port 443"

# Email protocols  
-f "tcp port 25 or tcp port 110 or tcp port 143 or tcp port 587"

# Database traffic
-f "tcp port 3306 or tcp port 5432 or tcp port 1433"

# DNS queries
-f "udp port 53"

# SSH connections
-f "tcp port 22"

# FTP traffic
-f "tcp port 21 or tcp port 20"
```

### **Network Analysis**
```bash
# Monitor specific host
-f "host 192.168.1.100"

# Local network traffic
-f "net 192.168.1.0/24"

# Large packets (file transfers)
-f "greater 1500"

# Small packets (control traffic)
-f "less 100"

# IPv6 traffic only
-f "ip6"

# Broadcast/multicast traffic
-f "broadcast or multicast"
```

### **Protocol-Specific**
```bash
# TCP with specific flags
-f "tcp[tcpflags] & tcp-syn != 0"  # SYN packets
-f "tcp[tcpflags] & tcp-fin != 0"  # FIN packets

# ICMP ping traffic
-f "icmp[icmptype] == 8 or icmp[icmptype] == 0"

# ARP requests/replies
-f "arp"

# DHCP traffic
-f "udp port 67 or udp port 68"
```

## 🖥️ Interface Types

### **Simple Interface (Default)**
- Clean table-based packet display
- Real-time packet streaming
- Basic statistics panel
- Minimal resource usage
- Perfect for monitoring and logging

**Features:**
- Packet table with timestamp, protocol, source, destination, size
- Live protocol statistics
- Low CPU and memory usage
- Classic terminal interface style

### **Advanced Interface (Optional)**
- Interactive widgets and controls
- Detailed packet inspection
- Advanced filtering controls
- More comprehensive statistics

**Features:**
- Interactive data tables with sorting
- Real-time packet details panel
- Advanced filtering interface
- Network topology visualization
- Connection state tracking

## ⌨️ Controls & Shortcuts

### **All Interfaces**
- `Ctrl+C`: Stop capture and exit
- `Ctrl+Z`: Pause capture (resume with `fg`)

### **Simple Interface (Default)**
- Automatic scrolling table view
- Real-time statistics update
- Clean, readable packet display
- Minimal keyboard interaction needed

### **Advanced Interface (with -a flag)**
- `Tab`: Navigate between panels
- `Enter`: Select/expand items
- `↑/↓`: Scroll through packets
- `q`: Quit application
- `f`: Open filter dialog
- `r`: Reset/refresh display

## ⚡ Quick Start Guide

### **🚀 Get Running in 30 Seconds**

**Linux:**
```bash
# 1. Download
git clone <repository-url>
cd net-scan

# 2. Run (that's it!)
sudo ./net-scan-linux.sh
```

**Windows:**
```batch
REM 1. Download and extract
REM 2. Right-click net-scan-windows.bat → "Run as Administrator"
```

### **✅ First Time Setup Verification**

1. **Check Interface Detection:**
   ```bash
   sudo ./net-scan-linux.sh -l
   # Should show: lo, eth0, wlan0 (default)
   ```

2. **Test Basic Capture:**
   ```bash
   sudo ./net-scan-linux.sh -i lo -f "icmp"
   # In another terminal: ping 127.0.0.1
   # Should see ICMP packets in the scanner
   ```

3. **Verify Web Traffic:**
   ```bash
   sudo ./net-scan-linux.sh -f "tcp port 80"
   # Visit any HTTP website
   # Should see HTTP packets
   ```

## 🔧 Requirements

- **Python 3.8+**
- **Root privileges** (required for raw packet capture)
- **Network interface access**
- **Linux/Unix system** (tested on Arch Linux)

## �️ Troubleshooting

### **❌ Common Issues**

**"Permission denied" or "Operation not permitted":**
```bash
# Solution: Always run with sudo on Linux
sudo ./net-scan-linux.sh

# Check if user is in correct groups (optional)
sudo usermod -a -G wireshark $USER
```

**"No network interfaces found":**
```bash
# List all interfaces
ip link show

# Try specific interface
sudo ./net-scan-linux.sh -i wlan0

# For virtual environments (Docker, VMs)
sudo ./net-scan-linux.sh -i docker0
```

**"Import error" or "Module not found":**
```bash
# Reinstall dependencies
sudo ./net-scan-linux.sh  # Script handles this automatically

# Or manually:
rm -rf venv
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**"Scapy import error" on Windows:**
```batch
REM Install Npcap first
REM Download from: https://nmap.org/npcap/
REM Then run as Administrator:
net-scan-windows.bat
```

**"No packets captured":**
```bash
# Check interface is active
ip addr show wlan0

# Try promiscuous mode
sudo ./net-scan-linux.sh -i wlan0

# Test with local traffic
sudo ./net-scan-linux.sh -i lo -f "icmp"
# Then: ping 127.0.0.1
```

### **🔍 Debugging Commands**

**Check system compatibility:**
```bash
# Verify Python version
python3 --version  # Should be 3.8+

# Test packet capture capability
sudo python3 -c "from scapy.all import *; print('Scapy working')"

# Check available interfaces
cat /proc/net/dev
```

**Verify installation:**
```bash
# Run test suite
python test.py

# Check virtual environment
source venv/bin/activate
pip list | grep -E "(scapy|rich|textual|click)"
```

### **⚙️ Advanced Configuration**

**Custom interface on unusual systems:**
```bash
# Find interface name
sudo ./net-scan-linux.sh -l

# For Docker containers
sudo ./net-scan-linux.sh -i eth0

# For WSL2
sudo ./net-scan-linux.sh -i eth0
```

**Performance tuning:**
```bash
# Limit packet capture rate
sudo ./net-scan-linux.sh -f "tcp and greater 100"

# Monitor specific protocols only
sudo ./net-scan-linux.sh -f "tcp port 80 or tcp port 443"
```

## �📊 Supported Packet Types

### **Network Layer**
- **IPv4**: Standard internet protocol with full header analysis
- **IPv6**: Next-generation internet protocol with extension headers
- **ARP**: Address Resolution Protocol for MAC address discovery
- **ICMP/ICMPv6**: Network diagnostics and error reporting

### **Transport Layer**
- **TCP**: Transmission Control Protocol with flag analysis
- **UDP**: User Datagram Protocol for connectionless communication
- **SCTP**: Stream Control Transmission Protocol

### **Application Protocols**
- **Web**: HTTP, HTTPS, WebSocket
- **Email**: SMTP, POP3, IMAP, SMTPS, POP3S, IMAPS
- **File Transfer**: FTP, SFTP, TFTP, SMB/CIFS, NFS
- **Remote Access**: SSH, Telnet, RDP, VNC
- **Database**: MySQL, PostgreSQL, SQL Server, Oracle, MongoDB, Redis
- **Network Services**: DNS, DHCP, NTP, SNMP, Syslog
- **Security**: TLS/SSL, IPSec, OpenVPN, RADIUS
- **Routing**: BGP, RIP, OSPF
- **Multimedia**: SIP, RTP (VoIP protocols)

### **Specialized Protocols**
- **VXLAN**: Virtual extensible LAN for overlay networks
- **PPPoE**: Point-to-Point Protocol over Ethernet
- **VLAN**: 802.1Q virtual LAN tagging
- **STP**: Spanning Tree Protocol
- **LLDP**: Link Layer Discovery Protocol

## 🛡️ Security Features

### **Attack Detection**
- **Port Scanning**: Detects rapid connection attempts to multiple ports
- **DoS Attacks**: Identifies high-volume traffic from single sources
- **ARP Spoofing**: Monitors for suspicious ARP patterns
- **DNS Tunneling**: Detects unusual DNS query patterns

### **Traffic Analysis**
- **Connection Tracking**: Monitors TCP connection states
- **Bandwidth Analysis**: Identifies high-bandwidth consumers
- **Protocol Anomalies**: Detects unusual protocol usage
- **Geolocation**: IP address origin analysis (future feature)

## 🎨 Interface Options

### **Simple Interface (Recommended)**
- Rich-formatted table display
- Real-time statistics
- Cross-platform compatibility
- Lower resource usage

### **Advanced Interface**
- Interactive Textual-based UI
- Multi-panel layout
- Mouse support
- Advanced filtering controls

## 🚨 Troubleshooting

### **Permission Issues**
```bash
# Ensure you're running with sudo
sudo venv/bin/python main.py

# Check network interface permissions
sudo chmod +r /dev/net/tun
```

### **Virtual Environment Issues**
```bash
# Recreate virtual environment
rm -rf venv
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### **Dependency Issues**
```bash
# Update system packages (Arch Linux)
sudo pacman -Syu
sudo pacman -S python-pip python-venv

# Test installation
python test.py
```

## � Practical Examples

### **🔍 Network Debugging**

**Find who's using bandwidth:**
```bash
# Monitor all traffic and sort by size
sudo ./net-scan-linux.sh -f "greater 1000"
```

**Debug connection issues:**
```bash
# Watch TCP handshakes
sudo ./net-scan-linux.sh -f "tcp[tcpflags] & tcp-syn != 0"

# Monitor failed connections
sudo ./net-scan-linux.sh -f "tcp[tcpflags] & tcp-rst != 0"
```

**Check DNS resolution:**
```bash
# Monitor DNS queries
sudo ./net-scan-linux.sh -f "udp port 53"

# Watch for DNS failures
sudo ./net-scan-linux.sh -f "icmp[icmptype] == 3"
```

### **🛡️ Security Monitoring**

**Detect port scans:**
```bash
# Monitor connection attempts
sudo ./net-scan-linux.sh -f "tcp[tcpflags] & tcp-syn != 0 and not tcp[tcpflags] & tcp-ack != 0"
```

**Watch for unusual traffic:**
```bash
# Non-standard ports
sudo ./net-scan-linux.sh -f "tcp portrange 1024-65535"

# Large packets (potential data exfiltration)
sudo ./net-scan-linux.sh -f "greater 1500"
```

**Monitor specific hosts:**
```bash
# Watch traffic to/from specific IP
sudo ./net-scan-linux.sh -f "host 192.168.1.100"

# Monitor subnet activity
sudo ./net-scan-linux.sh -f "net 10.0.0.0/8"
```

### **📊 Performance Analysis**

**Web server monitoring:**
```bash
# HTTP/HTTPS traffic analysis
sudo ./net-scan-linux.sh -f "tcp port 80 or tcp port 443"

# Monitor response times (watch for retransmissions)
sudo ./net-scan-linux.sh -f "tcp[tcpflags] & tcp-push != 0"
```

**Database traffic:**
```bash
# Monitor database connections
sudo ./net-scan-linux.sh -f "tcp port 3306 or tcp port 5432"

# Watch for connection pools
sudo ./net-scan-linux.sh -f "tcp and host your-db-server"
```

### **🌐 Application Monitoring**

**Email server debugging:**
```bash
# SMTP traffic
sudo ./net-scan-linux.sh -f "tcp port 25 or tcp port 587"

# IMAP/POP3 traffic
sudo ./net-scan-linux.sh -f "tcp port 143 or tcp port 993 or tcp port 110 or tcp port 995"
```

**VoIP troubleshooting:**
```bash
# SIP signaling
sudo ./net-scan-linux.sh -f "tcp port 5060 or udp port 5060"

# RTP media streams
sudo ./net-scan-linux.sh -f "udp portrange 10000-20000"
```

## �📈 Performance

- **Memory Usage**: ~50-100MB for normal operation
- **CPU Usage**: ~5-10% on modern systems
- **Packet Rate**: Handles 1000+ packets/second
- **Storage**: Configurable packet buffer (default: 1000 packets)

## 🔮 Roadmap

- [ ] Packet export to PCAP format
- [ ] GeoIP integration for source tracking
- [ ] Machine learning-based anomaly detection
- [ ] Web interface for remote monitoring
- [ ] Plugin system for custom protocol analysis
- [ ] Integration with Wireshark filters

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- **Scapy**: Powerful packet manipulation library
- **Rich**: Beautiful terminal formatting
- **Textual**: Modern TUI framework
- **Click**: Elegant command-line interfaces# net-scan
# net-scan
