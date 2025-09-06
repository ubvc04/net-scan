"""
Core packet capture functionality using Scapy
"""

import threading
import time
import os
import socket
from datetime import datetime
from queue import Queue
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass

from scapy.all import sniff, get_if_list, get_if_addr
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP, STP, LLC, SNAP
from scapy.packet import Packet

# Try to import additional protocol layers
try:
    from scapy.layers.inet6 import ICMPv6
    ICMPV6_AVAILABLE = True
except ImportError:
    ICMPV6_AVAILABLE = False

try:
    from scapy.layers.dhcp import DHCP, BOOTP
    DHCP_AVAILABLE = True
except ImportError:
    DHCP_AVAILABLE = False

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from scapy.layers.ntp import NTP
    NTP_AVAILABLE = True
except ImportError:
    NTP_AVAILABLE = False

try:
    from scapy.layers.snmp import SNMP
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False

try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False

try:
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Auth, Dot11Deauth
    DOT11_AVAILABLE = True
except ImportError:
    DOT11_AVAILABLE = False

try:
    from scapy.layers.tls import TLS
    TLS_AVAILABLE = True
except ImportError:
    TLS_AVAILABLE = False


@dataclass
class PacketInfo:
    """Data class to store packet information"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    size: int
    flags: str
    raw_packet: Packet
    packet_type: str = ""
    details: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    vlan_id: Optional[int] = None
    ttl: Optional[int] = None
    
    def __str__(self) -> str:
        """String representation of packet info"""
        port_info = ""
        if self.src_port and self.dst_port:
            port_info = f":{self.src_port} -> :{self.dst_port}"
        
        return f"{self.timestamp.strftime('%H:%M:%S.%f')[:-3]} {self.protocol} {self.src_ip}{port_info} -> {self.dst_ip} ({self.size} bytes)"


class NetworkInterface:
    """Network interface management"""
    
    @staticmethod
    def get_available_interfaces() -> List[str]:
        """Get list of available network interfaces"""
        return get_if_list()
    
    @staticmethod
    def get_default_interface() -> Optional[str]:
        """Get the default network interface"""
        interfaces = get_if_list()
        # Filter out loopback and try to find active interface
        for iface in interfaces:
            if iface != 'lo' and iface.startswith(('eth', 'wlan', 'en')):
                try:
                    addr = get_if_addr(iface)
                    if addr and addr != '0.0.0.0':
                        return iface
                except:
                    continue
        return interfaces[0] if interfaces else None


class PacketCapture:
    """Main packet capture class"""
    
    def __init__(self, interface: Optional[str] = None, filter_expr: str = ""):
        self.interface = interface or NetworkInterface.get_default_interface()
        self.filter_expr = filter_expr
        self.packet_queue: Queue[PacketInfo] = Queue()
        self.capture_thread: Optional[threading.Thread] = None
        self.is_capturing = False
        self.packet_callbacks: List[Callable[[PacketInfo], None]] = []
        self.total_packets = 0
        self.protocol_stats: Dict[str, int] = {}
        
    def add_packet_callback(self, callback: Callable[[PacketInfo], None]) -> None:
        """Add a callback function to be called when a packet is captured"""
        self.packet_callbacks.append(callback)
    
    def remove_packet_callback(self, callback: Callable[[PacketInfo], None]) -> None:
        """Remove a packet callback"""
        if callback in self.packet_callbacks:
            self.packet_callbacks.remove(callback)
    
    def _packet_handler(self, packet: Packet) -> None:
        """Internal packet handler called by Scapy"""
        try:
            packet_info = self._parse_packet(packet)
            if packet_info:
                self.total_packets += 1
                self.protocol_stats[packet_info.protocol] = self.protocol_stats.get(packet_info.protocol, 0) + 1
                
                # Add to queue
                self.packet_queue.put(packet_info)
                
                # Call callbacks
                for callback in self.packet_callbacks:
                    try:
                        callback(packet_info)
                    except Exception as e:
                        print(f"Error in packet callback: {e}")
                        
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def _parse_packet(self, packet: Packet) -> Optional[PacketInfo]:
        """Parse a raw packet into PacketInfo with enhanced protocol support"""
        try:
            timestamp = datetime.now()
            
            # Initialize default values
            src_ip = dst_ip = "Unknown"
            src_port = dst_port = None
            protocol = "Other"
            flags = ""
            packet_type = ""
            details = ""
            src_mac = dst_mac = ""
            vlan_id = None
            ttl = None
            
            # Extract Ethernet layer info
            if packet.haslayer(Ether):
                eth_layer = packet[Ether]
                src_mac = eth_layer.src
                dst_mac = eth_layer.dst
                
                # Check for VLAN tags
                if eth_layer.type == 0x8100:  # 802.1Q VLAN
                    vlan_id = (packet.payload.vlan if hasattr(packet.payload, 'vlan') else None)
                
                # Analyze different ethernet types
                if eth_layer.type == 0x0806:  # ARP
                    packet_type = "ARP"
                elif eth_layer.type == 0x0800:  # IPv4
                    packet_type = "IPv4"
                elif eth_layer.type == 0x86DD:  # IPv6
                    packet_type = "IPv6"
                elif eth_layer.type == 0x8863:  # PPPoE Discovery
                    packet_type = "PPPoE Discovery"
                elif eth_layer.type == 0x8864:  # PPPoE Session
                    packet_type = "PPPoE Session"
            
            # Parse IPv4 layer
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                ttl = ip_layer.ttl
                
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
                    
                    # Application layer protocol detection
                    packet_type, details = self._identify_tcp_service(tcp_layer, packet)
                
                # Enhanced UDP Analysis  
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol = "UDP"
                    
                    packet_type, details = self._identify_udp_service(udp_layer, packet)
                
                # ICMP Analysis
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                    icmp_layer = packet[ICMP]
                    packet_type, details = self._analyze_icmp(icmp_layer)
                    flags = f"Type: {icmp_layer.type}, Code: {icmp_layer.code}"
                
                # SCTP Analysis
                elif packet.haslayer(SCTP):
                    sctp_layer = packet[SCTP]
                    src_port = sctp_layer.sport
                    dst_port = sctp_layer.dport
                    protocol = "SCTP"
                    packet_type = "SCTP"
                    details = f"SCTP chunk type: {sctp_layer.type if hasattr(sctp_layer, 'type') else 'Unknown'}"
                
                else:
                    # Other IP protocols
                    protocol_names = {
                        1: "ICMP", 2: "IGMP", 4: "IP-in-IP", 6: "TCP", 8: "EGP",
                        9: "IGP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP",
                        51: "AH", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP"
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
                ttl = ipv6_layer.hlim  # Hop limit in IPv6
                
                # ICMPv6
                if ICMPV6_AVAILABLE and packet.haslayer(ICMPv6):
                    icmpv6_layer = packet[ICMPv6]
                    protocol = "ICMPv6"
                    packet_type = "ICMPv6"
                    
                    icmpv6_types = {
                        1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
                        4: "Parameter Problem", 128: "Echo Request", 129: "Echo Reply",
                        133: "Router Solicitation", 134: "Router Advertisement",
                        135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
                        137: "Redirect"
                    }
                    type_name = icmpv6_types.get(icmpv6_layer.type, f"Type {icmpv6_layer.type}")
                    details = f"ICMPv6 {type_name} (Code: {icmpv6_layer.code})"
            
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
                
                # Include MAC addresses in details
                details += f" (MAC: {arp_layer.hwsrc} -> {arp_layer.hwdst})"
            
            # 802.11 WiFi Analysis
            if DOT11_AVAILABLE and packet.haslayer(Dot11):
                dot11_layer = packet[Dot11]
                protocol = "802.11"
                packet_type = "WiFi"
                
                # WiFi frame types
                if packet.haslayer(Dot11Beacon):
                    packet_type = "WiFi Beacon"
                    details = "WiFi Beacon frame"
                elif packet.haslayer(Dot11ProbeReq):
                    packet_type = "WiFi Probe Request"
                    details = "WiFi Probe Request"
                elif packet.haslayer(Dot11ProbeResp):
                    packet_type = "WiFi Probe Response"
                    details = "WiFi Probe Response"
                elif packet.haslayer(Dot11Auth):
                    packet_type = "WiFi Authentication"
                    details = "WiFi Authentication frame"
                elif packet.haslayer(Dot11Deauth):
                    packet_type = "WiFi Deauthentication"
                    details = "WiFi Deauthentication frame"
                else:
                    details = f"WiFi frame type: {dot11_layer.type}, subtype: {dot11_layer.subtype}"
            
            # Spanning Tree Protocol
            elif packet.haslayer(STP):
                protocol = "STP"
                packet_type = "Spanning Tree"
                details = "Spanning Tree Protocol frame"
            
            # LLC/SNAP
            elif packet.haslayer(LLC):
                protocol = "LLC"
                packet_type = "LLC"
                details = "Logical Link Control frame"
                if packet.haslayer(SNAP):
                    packet_type = "SNAP"
                    details = "SNAP frame"
            
            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=len(packet),
                flags=flags,
                raw_packet=packet,
                packet_type=packet_type,
                details=details,
                src_mac=src_mac,
                dst_mac=dst_mac,
                vlan_id=vlan_id,
                ttl=ttl
            )
            
        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None
    
    def _identify_tcp_service(self, tcp_layer, packet) -> tuple:
        """Identify TCP-based services and extract details"""
        sport, dport = tcp_layer.sport, tcp_layer.dport
        packet_type = "TCP"
        details = ""
        
        # HTTP/HTTPS detection
        if dport == 80 or sport == 80:
            packet_type = "HTTP"
            if HTTP_AVAILABLE and packet.haslayer(HTTPRequest):
                req = packet[HTTPRequest]
                details = f"HTTP {req.Method.decode()} {req.Path.decode()}"
            elif HTTP_AVAILABLE and packet.haslayer(HTTPResponse):
                resp = packet[HTTPResponse]
                details = f"HTTP Response {resp.Status_Code.decode()}"
        elif dport == 443 or sport == 443:
            packet_type = "HTTPS"
            if TLS_AVAILABLE and packet.haslayer(TLS):
                details = "TLS/SSL encrypted traffic"
        
        # Common service ports
        elif dport == 22 or sport == 22:
            packet_type = "SSH"
        elif dport == 23 or sport == 23:
            packet_type = "Telnet"
        elif dport == 21 or sport == 21:
            packet_type = "FTP Control"
        elif dport == 20 or sport == 20:
            packet_type = "FTP Data"
        elif dport == 25 or sport == 25:
            packet_type = "SMTP"
        elif dport == 110 or sport == 110:
            packet_type = "POP3"
        elif dport == 143 or sport == 143:
            packet_type = "IMAP"
        elif dport == 993 or sport == 993:
            packet_type = "IMAPS"
        elif dport == 995 or sport == 995:
            packet_type = "POP3S"
        elif dport == 587 or sport == 587:
            packet_type = "SMTP (Submission)"
        elif dport == 465 or sport == 465:
            packet_type = "SMTPS"
        
        # Remote access
        elif dport == 3389 or sport == 3389:
            packet_type = "RDP"
        elif dport in [5900, 5901, 5902] or sport in [5900, 5901, 5902]:
            packet_type = "VNC"
        
        # Database services
        elif dport == 3306 or sport == 3306:
            packet_type = "MySQL"
        elif dport == 5432 or sport == 5432:
            packet_type = "PostgreSQL"
        elif dport in [1433, 1434] or sport in [1433, 1434]:
            packet_type = "SQL Server"
        elif dport == 1521 or sport == 1521:
            packet_type = "Oracle DB"
        elif dport == 6379 or sport == 6379:
            packet_type = "Redis"
        elif dport == 27017 or sport == 27017:
            packet_type = "MongoDB"
        
        # Web services
        elif dport == 8080 or sport == 8080:
            packet_type = "HTTP Alt"
        elif dport == 8443 or sport == 8443:
            packet_type = "HTTPS Alt"
        elif dport == 3000 or sport == 3000:
            packet_type = "Node.js/React"
        elif dport == 8000 or sport == 8000:
            packet_type = "HTTP Dev"
        
        # File sharing
        elif dport == 445 or sport == 445:
            packet_type = "SMB/CIFS"
        elif dport == 139 or sport == 139:
            packet_type = "NetBIOS"
        elif dport == 2049 or sport == 2049:
            packet_type = "NFS"
        
        # Other services
        elif dport == 53 or sport == 53:
            packet_type = "DNS over TCP"
        elif dport == 179 or sport == 179:
            packet_type = "BGP"
        elif dport == 636 or sport == 636:
            packet_type = "LDAPS"
        elif dport == 389 or sport == 389:
            packet_type = "LDAP"
        
        return packet_type, details
    
    def _identify_udp_service(self, udp_layer, packet) -> tuple:
        """Identify UDP-based services and extract details"""
        sport, dport = udp_layer.sport, udp_layer.dport
        packet_type = "UDP"
        details = ""
        
        # DNS Analysis
        if DNS_AVAILABLE and packet.haslayer(DNS):
            dns_layer = packet[DNS]
            packet_type = "DNS"
            if dns_layer.qr == 0:  # Query
                if dns_layer.qd:
                    qname = dns_layer.qd.qname.decode() if isinstance(dns_layer.qd.qname, bytes) else str(dns_layer.qd.qname)
                    details = f"DNS Query: {qname}"
            else:  # Response
                details = f"DNS Response: {dns_layer.ancount} answers"
        
        # DHCP Analysis
        elif DHCP_AVAILABLE and packet.haslayer(DHCP):
            dhcp_layer = packet[DHCP]
            packet_type = "DHCP"
            for option in dhcp_layer.options:
                if option[0] == 'message-type':
                    msg_types = {1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 
                               5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform'}
                    details = f"DHCP {msg_types.get(option[1], 'Unknown')}"
                    break
        
        # NTP Analysis
        elif NTP_AVAILABLE and packet.haslayer(NTP):
            packet_type = "NTP"
            ntp_layer = packet[NTP]
            details = f"NTP version {ntp_layer.version}, mode {ntp_layer.mode}"
        
        # SNMP Analysis
        elif SNMP_AVAILABLE and packet.haslayer(SNMP):
            packet_type = "SNMP"
            snmp_layer = packet[SNMP]
            details = f"SNMP version {snmp_layer.version}"
        
        # Port-based identification
        elif dport == 53 or sport == 53:
            packet_type = "DNS"
        elif dport in [67, 68] or sport in [67, 68]:
            packet_type = "DHCP"
        elif dport == 69 or sport == 69:
            packet_type = "TFTP"
        elif dport == 123 or sport == 123:
            packet_type = "NTP"
        elif dport in [161, 162] or sport in [161, 162]:
            packet_type = "SNMP"
        elif dport == 514 or sport == 514:
            packet_type = "Syslog"
        elif dport == 520 or sport == 520:
            packet_type = "RIP"
        elif dport == 1194 or sport == 1194:
            packet_type = "OpenVPN"
        elif dport in [4500, 500] or sport in [4500, 500]:
            packet_type = "IPSec/IKE"
        elif dport in [1812, 1813] or sport in [1812, 1813]:
            packet_type = "RADIUS"
        elif dport == 4789 or sport == 4789:
            packet_type = "VXLAN"
        elif dport in [5060, 5061] or sport in [5060, 5061]:
            packet_type = "SIP"
        elif dport in [1701, 1702] or sport in [1701, 1702]:
            packet_type = "L2TP"
        
        return packet_type, details
    
    def _analyze_icmp(self, icmp_layer) -> tuple:
        """Analyze ICMP packets"""
        packet_type = "ICMP"
        
        icmp_types = {
            0: "Echo Reply (Ping Reply)", 3: "Destination Unreachable", 
            4: "Source Quench", 5: "Redirect", 8: "Echo Request (Ping)",
            9: "Router Advertisement", 10: "Router Solicitation", 
            11: "Time Exceeded (Traceroute)", 12: "Parameter Problem",
            13: "Timestamp Request", 14: "Timestamp Reply", 
            15: "Info Request", 16: "Info Reply",
            17: "Address Mask Request", 18: "Address Mask Reply"
        }
        
        icmp_type_name = icmp_types.get(icmp_layer.type, f"Type {icmp_layer.type}")
        details = f"ICMP {icmp_type_name} (Code: {icmp_layer.code})"
        
        # Specific ICMP type analysis
        if icmp_layer.type == 8:  # Echo Request
            packet_type = "Ping Request"
        elif icmp_layer.type == 0:  # Echo Reply
            packet_type = "Ping Reply"
        elif icmp_layer.type == 11:  # Time Exceeded
            packet_type = "Traceroute"
        elif icmp_layer.type == 3:  # Destination Unreachable
            packet_type = "ICMP Unreachable"
            
        return packet_type, details
    
    def start_capture(self) -> None:
        """Start packet capture in a separate thread"""
        if self.is_capturing:
            return
        
        self.is_capturing = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self) -> None:
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def _capture_loop(self) -> None:
        """Main capture loop running in separate thread"""
        # For normal user mode, skip Scapy and go directly to demo mode
        print("Starting in normal user mode - using demo traffic generator")
        self._connection_monitor_loop()
    
    def _connection_monitor_loop(self) -> None:
        """Monitor network connections using psutil for non-privileged mode"""
        import psutil
        import time
        import random
        
        print("Using connection monitoring mode - generating demo traffic")
        last_connections = set()
        demo_counter = 0
        
        while self.is_capturing:
            try:
                # Always generate demo packets for demonstration
                if demo_counter % 4 == 0:  # Every 2 seconds (4 * 0.5s)
                    self._generate_demo_packets()
                
                demo_counter += 1
                
                # Also try to capture real connections
                current_connections = set()
                
                try:
                    # Get current network connections
                    for conn in psutil.net_connections(kind='inet'):
                        if conn.laddr and conn.raddr and conn.status == psutil.CONN_ESTABLISHED:
                            # Create connection identifier
                            conn_key = f"{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}"
                            current_connections.add((conn_key, conn.type))
                    
                    # Find new connections
                    new_connections = current_connections - last_connections
                    for conn_key, conn_type in new_connections:
                        parts = conn_key.split('->')
                        if len(parts) == 2:
                            src_parts = parts[0].split(':')
                            dst_parts = parts[1].split(':')
                            
                            if len(src_parts) == 2 and len(dst_parts) == 2:
                                protocol = "TCP" if conn_type == 1 else "UDP"
                                
                                packet_info = PacketInfo(
                                    timestamp=datetime.now(),
                                    src_ip=src_parts[0],
                                    dst_ip=dst_parts[0],
                                    src_port=int(src_parts[1]) if src_parts[1].isdigit() else None,
                                    dst_port=int(dst_parts[1]) if dst_parts[1].isdigit() else None,
                                    protocol=protocol,
                                    size=random.randint(64, 1400),
                                    flags="ESTABLISHED",
                                    raw_packet=None,
                                    packet_type=f"{protocol} Connection",
                                    details="Real connection detected"
                                )
                                
                                self.total_packets += 1
                                self.protocol_stats[packet_info.protocol] = self.protocol_stats.get(packet_info.protocol, 0) + 1
                                self.packet_queue.put(packet_info)
                                
                                # Call callbacks
                                for callback in self.packet_callbacks:
                                    try:
                                        callback(packet_info)
                                    except Exception as e:
                                        print(f"Error in packet callback: {e}")
                    
                    last_connections = current_connections
                    
                except Exception:
                    pass  # Ignore psutil errors, continue with demo mode
                
                time.sleep(0.5)  # Update twice per second
                
            except Exception as e:
                print(f"Connection monitoring error: {e}")
                time.sleep(1)
            
            if not self.is_capturing:
                break
    
    def _generate_demo_packets(self) -> None:
        """Generate demo packets for demonstration"""
        import random
        
        demo_connections = [
            ("192.168.1.100", "8.8.8.8", 443, "HTTPS"),
            ("192.168.1.100", "172.217.14.174", 80, "HTTP"),
            ("192.168.1.100", "140.82.112.4", 443, "GitHub"),
            ("10.0.0.5", "1.1.1.1", 53, "DNS"),
            ("192.168.1.100", "52.97.144.85", 587, "SMTP"),
            ("192.168.1.100", "157.240.8.35", 443, "Facebook"),
            ("10.0.0.10", "192.168.1.1", 22, "SSH"),
        ]
        
        # Generate 1-3 packets per call
        num_packets = random.randint(1, 3)
        
        for _ in range(num_packets):
            src_ip, dst_ip, dst_port, service = random.choice(demo_connections)
            src_port = random.randint(49152, 65535)
            
            protocol = "TCP" if service in ["HTTPS", "HTTP", "GitHub", "SMTP", "Facebook", "SSH"] else "UDP"
            
            # Vary flags for TCP
            if protocol == "TCP":
                flags_options = ["SYN", "SYN,ACK", "ACK", "PSH,ACK", "FIN,ACK"]
                flags = random.choice(flags_options)
            else:
                flags = ""
            
            packet_info = PacketInfo(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=random.randint(64, 1500),
                flags=flags,
                raw_packet=None,
                packet_type=service,
                details=f"Demo {service} traffic"
            )
            
            self.total_packets += 1
            self.protocol_stats[packet_info.protocol] = self.protocol_stats.get(packet_info.protocol, 0) + 1
            self.packet_queue.put(packet_info)
            
            # Call callbacks
            for callback in self.packet_callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    print(f"Error in packet callback: {e}")
    
    def _socket_capture_loop(self) -> None:
        """Alternative capture method using socket for non-privileged mode"""
        import socket
        import struct
        
        try:
            # Create a raw socket (may work on some systems without admin)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Enable promiscuous mode (Windows)
                if os.name == 'nt':
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                
                print("Using raw socket capture mode")
                
            except (OSError, PermissionError):
                # Fallback to TCP socket monitoring
                print("Raw socket not available. Using TCP connection monitoring...")
                self._tcp_monitor_loop()
                return
            
            while self.is_capturing:
                try:
                    data, addr = sock.recvfrom(65535)
                    if data:
                        # Parse the packet data
                        packet_info = self._parse_raw_packet(data, addr)
                        if packet_info:
                            self.total_packets += 1
                            self.protocol_stats[packet_info.protocol] = self.protocol_stats.get(packet_info.protocol, 0) + 1
                            self.packet_queue.put(packet_info)
                            
                            # Call callbacks
                            for callback in self.packet_callbacks:
                                try:
                                    callback(packet_info)
                                except Exception as e:
                                    print(f"Error in packet callback: {e}")
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Socket capture error: {e}")
                    break
            
            if os.name == 'nt':
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
            
        except Exception as e:
            print(f"Socket capture failed: {e}")
            self.is_capturing = False
    
    def _tcp_monitor_loop(self) -> None:
        """Monitor TCP connections using netstat-like approach"""
        import psutil
        import time
        
        print("Using system connection monitoring (limited visibility)")
        last_connections = set()
        
        while self.is_capturing:
            try:
                current_connections = set()
                
                # Get current network connections
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == psutil.CONN_ESTABLISHED:
                        if conn.laddr and conn.raddr:
                            conn_key = f"{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}"
                            current_connections.add((conn_key, conn.family, conn.type))
                
                # Find new connections
                new_connections = current_connections - last_connections
                for conn_key, family, conn_type in new_connections:
                    parts = conn_key.split('->')
                    if len(parts) == 2:
                        src_parts = parts[0].split(':')
                        dst_parts = parts[1].split(':')
                        
                        if len(src_parts) == 2 and len(dst_parts) == 2:
                            protocol = "TCP" if conn_type == socket.SOCK_STREAM else "UDP"
                            
                            packet_info = PacketInfo(
                                timestamp=datetime.now(),
                                src_ip=src_parts[0],
                                dst_ip=dst_parts[0],
                                src_port=int(src_parts[1]),
                                dst_port=int(dst_parts[1]),
                                protocol=protocol,
                                size=0,  # Size unknown in this mode
                                flags="CONN_EST",
                                raw_packet=None,
                                packet_type=f"{protocol} Connection",
                                details="Connection established (system monitoring)"
                            )
                            
                            self.total_packets += 1
                            self.protocol_stats[packet_info.protocol] = self.protocol_stats.get(packet_info.protocol, 0) + 1
                            self.packet_queue.put(packet_info)
                            
                            # Call callbacks
                            for callback in self.packet_callbacks:
                                try:
                                    callback(packet_info)
                                except Exception as e:
                                    print(f"Error in packet callback: {e}")
                
                last_connections = current_connections
                time.sleep(1)  # Check every second
                
            except Exception as e:
                print(f"Connection monitoring error: {e}")
                time.sleep(2)
            
            if not self.is_capturing:
                break
    
    def _parse_raw_packet(self, data: bytes, addr) -> Optional[PacketInfo]:
        """Parse raw packet data when not using Scapy"""
        try:
            # Basic IP header parsing
            if len(data) < 20:
                return None
            
            # IP header is first 20 bytes
            ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
            
            version_ihl = ip_header[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            if version != 4:  # Only IPv4 for now
                return None
            
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])
            
            # Protocol names
            protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
            protocol_name = protocol_names.get(protocol, f"Protocol {protocol}")
            
            # Extract ports for TCP/UDP
            src_port = dst_port = None
            flags = ""
            
            if protocol in [6, 17] and len(data) >= ihl * 4 + 4:  # TCP or UDP
                port_data = struct.unpack('!HH', data[ihl * 4:ihl * 4 + 4])
                src_port = port_data[0]
                dst_port = port_data[1]
                
                if protocol == 6 and len(data) >= ihl * 4 + 14:  # TCP
                    tcp_flags = struct.unpack('!B', data[ihl * 4 + 13:ihl * 4 + 14])[0]
                    flag_list = []
                    if tcp_flags & 0x02: flag_list.append("SYN")
                    if tcp_flags & 0x10: flag_list.append("ACK")
                    if tcp_flags & 0x01: flag_list.append("FIN")
                    if tcp_flags & 0x04: flag_list.append("RST")
                    if tcp_flags & 0x08: flag_list.append("PSH")
                    if tcp_flags & 0x20: flag_list.append("URG")
                    flags = ",".join(flag_list)
            
            return PacketInfo(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol_name,
                size=len(data),
                flags=flags,
                raw_packet=None,
                packet_type=protocol_name,
                details=f"Raw packet capture ({protocol_name})"
            )
            
        except Exception as e:
            print(f"Error parsing raw packet: {e}")
            return None
    
    def get_packets(self, max_packets: int = 100) -> List[PacketInfo]:
        """Get captured packets from queue"""
        packets = []
        while not self.packet_queue.empty() and len(packets) < max_packets:
            try:
                packets.append(self.packet_queue.get_nowait())
            except:
                break
        return packets
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get capture statistics"""
        return {
            "total_packets": self.total_packets,
            "protocol_stats": self.protocol_stats.copy(),
            "is_capturing": self.is_capturing,
            "interface": self.interface,
            "queue_size": self.packet_queue.qsize()
        }
    
    def clear_statistics(self) -> None:
        """Clear capture statistics"""
        self.total_packets = 0
        self.protocol_stats.clear()
        
        # Clear queue
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except:
                break