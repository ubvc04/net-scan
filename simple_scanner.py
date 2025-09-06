#!/usr/bin/env python3
"""
Simple Network Scanner - Enhanced with More Packet Types
A lightweight version that works with system Python libraries
"""

import sys
import os

# Add the virtual environment path if it exists
venv_path = os.path.join(os.path.dirname(__file__), 'venv', 'lib', 'python3.13', 'site-packages')
if os.path.exists(venv_path):
    sys.path.insert(0, venv_path)

import time
import socket
import struct
import threading
import signal
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Any

# Try to import scapy, fall back to socket if not available
try:
    from scapy.all import sniff, get_if_list, get_if_addr
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6, ICMPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.dns import DNS
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.ntp import NTP
    from scapy.layers.snmp import SNMP
    from scapy.packet import Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available. Using basic socket capture.")

class PacketInfo:
    """Enhanced packet information with more protocol support"""
    def __init__(self, timestamp, src_ip, dst_ip, protocol, size, 
                 src_port=None, dst_port=None, flags="", details="", packet_type=""):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.size = size
        self.flags = flags
        self.details = details
        self.packet_type = packet_type
    
    def __str__(self):
        port_info = ""
        if self.src_port and self.dst_port:
            port_info = f":{self.src_port} -> :{self.dst_port}"
        
        type_info = f" [{self.packet_type}]" if self.packet_type else ""
        
        return (f"{self.timestamp.strftime('%H:%M:%S.%f')[:-3]} "
                f"{self.protocol}{type_info} {self.src_ip}{port_info} -> "
                f"{self.dst_ip} ({self.size} bytes) {self.flags}")

class EnhancedPacketCapture:
    """Enhanced packet capture with support for many more packet types"""
    
    def __init__(self, interface=None):
        self.interface = interface
        self.packets = []
        self.is_capturing = False
        self.stats = defaultdict(int)
        self.packet_types = defaultdict(int)
        
    def parse_enhanced_packet(self, packet) -> Optional[PacketInfo]:
        """Parse packet with enhanced protocol support"""
        try:
            timestamp = datetime.now()
            src_ip = dst_ip = "Unknown"
            src_port = dst_port = None
            protocol = "Other"
            flags = ""
            details = ""
            packet_type = ""
            
            if not SCAPY_AVAILABLE:
                return None
                
            # Ethernet Layer Analysis
            if packet.haslayer(Ether):
                eth = packet[Ether]
                packet_type = f"Ethernet Type: 0x{eth.type:04x}"
            
            # IPv4 Analysis
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                # Enhanced TCP Analysis
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol = "TCP"
                    
                    # TCP flags analysis
                    flag_list = []
                    if tcp_layer.flags.S: flag_list.append("SYN")
                    if tcp_layer.flags.A: flag_list.append("ACK")
                    if tcp_layer.flags.F: flag_list.append("FIN")
                    if tcp_layer.flags.R: flag_list.append("RST")
                    if tcp_layer.flags.P: flag_list.append("PSH")
                    if tcp_layer.flags.U: flag_list.append("URG")
                    if tcp_layer.flags.E: flag_list.append("ECE")
                    if tcp_layer.flags.C: flag_list.append("CWR")
                    flags = ",".join(flag_list)
                    
                    # Identify application protocols
                    if dst_port == 80 or src_port == 80:
                        packet_type = "HTTP"
                        if packet.haslayer(HTTPRequest):
                            details = f"HTTP Request: {packet[HTTPRequest].Method.decode()} {packet[HTTPRequest].Path.decode()}"
                        elif packet.haslayer(HTTPResponse):
                            details = f"HTTP Response: {packet[HTTPResponse].Status_Code.decode()}"
                    elif dst_port == 443 or src_port == 443:
                        packet_type = "HTTPS/TLS"
                    elif dst_port == 22 or src_port == 22:
                        packet_type = "SSH"
                    elif dst_port == 23 or src_port == 23:
                        packet_type = "Telnet"
                    elif dst_port == 21 or src_port == 21:
                        packet_type = "FTP Control"
                    elif dst_port == 20 or src_port == 20:
                        packet_type = "FTP Data"
                    elif dst_port == 25 or src_port == 25:
                        packet_type = "SMTP"
                    elif dst_port == 110 or src_port == 110:
                        packet_type = "POP3"
                    elif dst_port == 143 or src_port == 143:
                        packet_type = "IMAP"
                    elif dst_port == 993 or src_port == 993:
                        packet_type = "IMAPS"
                    elif dst_port == 995 or src_port == 995:
                        packet_type = "POP3S"
                    elif dst_port == 3389 or src_port == 3389:
                        packet_type = "RDP"
                    elif dst_port == 5900 or src_port == 5900:
                        packet_type = "VNC"
                    elif dst_port in [3306] or src_port in [3306]:
                        packet_type = "MySQL"
                    elif dst_port in [5432] or src_port in [5432]:
                        packet_type = "PostgreSQL"
                    elif dst_port in [1433, 1434] or src_port in [1433, 1434]:
                        packet_type = "SQL Server"
                    elif dst_port in [6379] or src_port in [6379]:
                        packet_type = "Redis"
                    elif dst_port in [27017] or src_port in [27017]:
                        packet_type = "MongoDB"
                
                # Enhanced UDP Analysis
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol = "UDP"
                    
                    # DNS Analysis
                    if packet.haslayer(DNS):
                        dns_layer = packet[DNS]
                        packet_type = "DNS"
                        if dns_layer.qr == 0:  # Query
                            details = f"DNS Query: {dns_layer.qd.qname.decode() if dns_layer.qd else 'Unknown'}"
                        else:  # Response
                            details = f"DNS Response: {dns_layer.ancount} answers"
                    
                    # DHCP Analysis
                    elif packet.haslayer(DHCP):
                        dhcp_layer = packet[DHCP]
                        packet_type = "DHCP"
                        for option in dhcp_layer.options:
                            if option[0] == 'message-type':
                                msg_types = {1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform'}
                                details = f"DHCP {msg_types.get(option[1], 'Unknown')}"
                                break
                    
                    # NTP Analysis
                    elif packet.haslayer(NTP):
                        packet_type = "NTP"
                        ntp_layer = packet[NTP]
                        details = f"NTP version {ntp_layer.version}, mode {ntp_layer.mode}"
                    
                    # SNMP Analysis
                    elif packet.haslayer(SNMP):
                        packet_type = "SNMP"
                        snmp_layer = packet[SNMP]
                        details = f"SNMP version {snmp_layer.version}"
                    
                    # Other UDP services
                    elif dst_port == 53 or src_port == 53:
                        packet_type = "DNS"
                    elif dst_port == 67 or dst_port == 68:
                        packet_type = "DHCP"
                    elif dst_port == 69 or src_port == 69:
                        packet_type = "TFTP"
                    elif dst_port == 123 or src_port == 123:
                        packet_type = "NTP"
                    elif dst_port == 161 or dst_port == 162:
                        packet_type = "SNMP"
                    elif dst_port == 514 or src_port == 514:
                        packet_type = "Syslog"
                    elif dst_port == 1194 or src_port == 1194:
                        packet_type = "OpenVPN"
                    elif dst_port in [4500, 500] or src_port in [4500, 500]:
                        packet_type = "IPSec/IKE"
                
                # ICMP Analysis
                elif packet.haslayer(ICMP):
                    icmp_layer = packet[ICMP]
                    protocol = "ICMP"
                    packet_type = "ICMP"
                    
                    icmp_types = {
                        0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
                        5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
                        10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
                        13: "Timestamp Request", 14: "Timestamp Reply", 15: "Info Request",
                        16: "Info Reply", 17: "Address Mask Request", 18: "Address Mask Reply"
                    }
                    
                    icmp_type_name = icmp_types.get(icmp_layer.type, f"Type {icmp_layer.type}")
                    details = f"ICMP {icmp_type_name} (Code: {icmp_layer.code})"
                    flags = f"Type: {icmp_layer.type}, Code: {icmp_layer.code}"
                
                # Other IP protocols
                else:
                    protocol_names = {
                        1: "ICMP", 2: "IGMP", 4: "IP-in-IP", 6: "TCP", 8: "EGP",
                        9: "IGP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP",
                        51: "AH", 89: "OSPF", 103: "PIM", 112: "VRRP"
                    }
                    protocol = protocol_names.get(ip_layer.proto, f"IP Proto {ip_layer.proto}")
                    packet_type = protocol
            
            # IPv6 Analysis
            elif packet.haslayer(IPv6):
                ipv6_layer = packet[IPv6]
                src_ip = ipv6_layer.src
                dst_ip = ipv6_layer.dst
                protocol = "IPv6"
                packet_type = "IPv6"
                
                if packet.haslayer(ICMPv6):
                    icmpv6_layer = packet[ICMPv6]
                    protocol = "ICMPv6"
                    packet_type = "ICMPv6"
                    details = f"ICMPv6 Type: {icmpv6_layer.type}, Code: {icmpv6_layer.code}"
            
            # ARP Analysis
            elif packet.haslayer(ARP):
                arp_layer = packet[ARP]
                src_ip = arp_layer.psrc
                dst_ip = arp_layer.pdst
                protocol = "ARP"
                packet_type = "ARP"
                
                arp_ops = {1: "Request", 2: "Reply", 3: "RARP Request", 4: "RARP Reply"}
                op_name = arp_ops.get(arp_layer.op, f"Op {arp_layer.op}")
                details = f"ARP {op_name}: Who has {dst_ip}? Tell {src_ip}"
                flags = f"Op: {arp_layer.op}"
            
            # 802.11 Wireless (if available)
            try:
                from scapy.layers.dot11 import Dot11
                if packet.haslayer(Dot11):
                    protocol = "802.11"
                    packet_type = "WiFi"
                    dot11 = packet[Dot11]
                    details = f"WiFi frame type: {dot11.type}, subtype: {dot11.subtype}"
            except ImportError:
                pass
            
            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=len(packet),
                flags=flags,
                details=details,
                packet_type=packet_type
            )
            
        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        packet_info = self.parse_enhanced_packet(packet)
        if packet_info:
            self.packets.append(packet_info)
            self.stats[packet_info.protocol] += 1
            self.packet_types[packet_info.packet_type] += 1
            
            # Keep only last 1000 packets to prevent memory issues
            if len(self.packets) > 1000:
                self.packets = self.packets[-1000:]
    
    def start_capture(self, count=0, timeout=None):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            print("Scapy not available. Cannot capture packets.")
            return
        
        print(f"Starting enhanced packet capture on {self.interface or 'default interface'}...")
        print("Capturing the following packet types:")
        print("• TCP (HTTP, HTTPS, SSH, FTP, Telnet, SMTP, POP3, IMAP, RDP, VNC, Database)")
        print("• UDP (DNS, DHCP, NTP, SNMP, TFTP, Syslog, VPN)")
        print("• ICMP (Ping, Traceroute, Network diagnostics)")
        print("• ARP (Address resolution)")
        print("• IPv6 (ICMPv6)")
        print("• 802.11 WiFi (if available)")
        print("\nPress Ctrl+C to stop...\n")
        
        try:
            self.is_capturing = True
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                count=count,
                timeout=timeout,
                store=0
            )
        except KeyboardInterrupt:
            print("\nCapture stopped by user")
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            self.is_capturing = False
    
    def display_packets(self, limit=20):
        """Display captured packets"""
        print(f"\n{'='*120}")
        print(f"{'Time':<12} {'Protocol':<12} {'Type':<15} {'Source':<25} {'Destination':<25} {'Size':<8} {'Details'}")
        print(f"{'='*120}")
        
        for packet in self.packets[-limit:]:
            src = packet.src_ip
            if packet.src_port:
                src += f":{packet.src_port}"
            
            dst = packet.dst_ip
            if packet.dst_port:
                dst += f":{packet.dst_port}"
            
            print(f"{packet.timestamp.strftime('%H:%M:%S.%f')[:-3]:<12} "
                  f"{packet.protocol:<12} "
                  f"{packet.packet_type:<15} "
                  f"{src:<25} "
                  f"{dst:<25} "
                  f"{packet.size:<8} "
                  f"{packet.details}")
    
    def show_statistics(self):
        """Display capture statistics"""
        print(f"\n{'='*60}")
        print("CAPTURE STATISTICS")
        print(f"{'='*60}")
        print(f"Total packets captured: {len(self.packets)}")
        print(f"Capture status: {'Active' if self.is_capturing else 'Stopped'}")
        
        print("\nProtocol Distribution:")
        print("-" * 30)
        for protocol, count in sorted(self.stats.items()):
            percentage = (count / len(self.packets) * 100) if self.packets else 0
            print(f"{protocol:<15}: {count:>6} ({percentage:5.1f}%)")
        
        print("\nPacket Type Distribution:")
        print("-" * 30)
        for ptype, count in sorted(self.packet_types.items()):
            if ptype:  # Only show non-empty types
                percentage = (count / len(self.packets) * 100) if self.packets else 0
                print(f"{ptype:<15}: {count:>6} ({percentage:5.1f}%)")

def get_available_interfaces():
    """Get available network interfaces"""
    if SCAPY_AVAILABLE:
        return get_if_list()
    else:
        return ["eth0", "wlan0", "lo"]  # Common interface names

def signal_handler(signum, frame):
    """Handle Ctrl+C"""
    print("\n\nShutting down...")
    sys.exit(0)

def main():
    """Main function"""
    print("Enhanced Network Packet Scanner")
    print("=" * 50)
    
    if not SCAPY_AVAILABLE:
        print("⚠️  Warning: Scapy not available. Limited functionality.")
        print("To install Scapy: pip install scapy")
        return
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Get interface
    interfaces = get_available_interfaces()
    print(f"Available interfaces: {', '.join(interfaces)}")
    
    # Use first non-loopback interface or default
    interface = None
    for iface in interfaces:
        if iface != 'lo':
            interface = iface
            break
    
    print(f"Using interface: {interface or 'default'}")
    
    # Check permissions
    if os.geteuid() != 0:
        print("\n⚠️  Warning: Root privileges recommended for packet capture")
        print("Run with: sudo python simple_scanner.py")
    
    # Create capture instance
    capture = EnhancedPacketCapture(interface)
    
    # Start capture in a thread so we can show periodic updates
    def capture_thread():
        capture.start_capture(timeout=10)  # Capture for 10 seconds
    
    print("\nStarting capture thread...")
    thread = threading.Thread(target=capture_thread, daemon=True)
    thread.start()
    
    # Show periodic updates
    try:
        for i in range(10):
            time.sleep(1)
            if i % 2 == 0 and capture.packets:  # Show update every 2 seconds
                print(f"\nCaptured {len(capture.packets)} packets so far...")
                capture.display_packets(limit=5)
    except KeyboardInterrupt:
        pass
    
    # Wait for capture to complete
    thread.join(timeout=2)
    
    # Show final results
    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)
    
    if capture.packets:
        capture.display_packets(limit=30)
        capture.show_statistics()
    else:
        print("No packets captured. Try running with sudo or check your network interface.")

if __name__ == "__main__":
    main()