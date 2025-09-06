"""
Utility functions and helper classes for the network scanner
"""

import socket
import struct
from typing import List, Dict, Optional, Tuple
from datetime import datetime

def get_service_name(port: int, protocol: str = "tcp") -> Optional[str]:
    """Get service name for a given port and protocol"""
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return None


def format_bytes(bytes_count: int) -> str:
    """Format bytes in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"


def ip_to_int(ip: str) -> int:
    """Convert IP address string to integer"""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(ip_int: int) -> str:
    """Convert integer to IP address string"""
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def is_private_ip(ip: str) -> bool:
    """Check if IP address is in private range"""
    try:
        ip_int = ip_to_int(ip)
        # Private IP ranges:
        # 10.0.0.0/8: 167772160 to 184549375
        # 172.16.0.0/12: 2886729728 to 2887778303
        # 192.168.0.0/16: 3232235520 to 3232301055
        return (167772160 <= ip_int <= 184549375 or
                2886729728 <= ip_int <= 2887778303 or
                3232235520 <= ip_int <= 3232301055)
    except:
        return False


def get_ip_class(ip: str) -> str:
    """Get IP address class (A, B, C, D, E)"""
    try:
        first_octet = int(ip.split('.')[0])
        if 1 <= first_octet <= 126:
            return "A"
        elif 128 <= first_octet <= 191:
            return "B"
        elif 192 <= first_octet <= 223:
            return "C"
        elif 224 <= first_octet <= 239:
            return "D (Multicast)"
        elif 240 <= first_octet <= 255:
            return "E (Experimental)"
        else:
            return "Unknown"
    except:
        return "Invalid"


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


class ColorScheme:
    """Color scheme for different packet types and protocols"""
    
    PROTOCOLS = {
        "TCP": "blue",
        "UDP": "green", 
        "ICMP": "yellow",
        "ARP": "magenta",
        "HTTP": "cyan",
        "HTTPS": "bright_cyan",
        "DNS": "bright_green",
        "SSH": "red",
        "FTP": "bright_red"
    }
    
    SEVERITY = {
        "info": "blue",
        "warning": "yellow",
        "critical": "red"
    }
    
    @classmethod
    def get_protocol_color(cls, protocol: str) -> str:
        """Get color for protocol"""
        return cls.PROTOCOLS.get(protocol.upper(), "white")
    
    @classmethod
    def get_severity_color(cls, severity: str) -> str:
        """Get color for severity level"""
        return cls.SEVERITY.get(severity.lower(), "white")


class BPFFilter:
    """Berkeley Packet Filter expression builder and validator"""
    
    COMMON_FILTERS = {
        "http": "tcp port 80",
        "https": "tcp port 443", 
        "dns": "udp port 53",
        "ssh": "tcp port 22",
        "ftp": "tcp port 21",
        "telnet": "tcp port 23",
        "smtp": "tcp port 25",
        "pop3": "tcp port 110",
        "imap": "tcp port 143",
        "tcp": "tcp",
        "udp": "udp",
        "icmp": "icmp",
        "arp": "arp"
    }
    
    @classmethod
    def get_common_filter(cls, name: str) -> Optional[str]:
        """Get common filter expression by name"""
        return cls.COMMON_FILTERS.get(name.lower())
    
    @classmethod
    def build_host_filter(cls, host: str) -> str:
        """Build filter for specific host"""
        return f"host {host}"
    
    @classmethod
    def build_port_filter(cls, port: int, protocol: str = "tcp") -> str:
        """Build filter for specific port and protocol"""
        return f"{protocol} port {port}"
    
    @classmethod
    def build_network_filter(cls, network: str) -> str:
        """Build filter for network range"""
        return f"net {network}"
    
    @classmethod
    def combine_filters(cls, filters: List[str], operator: str = "and") -> str:
        """Combine multiple filters with AND/OR operator"""
        if not filters:
            return ""
        if len(filters) == 1:
            return filters[0]
        return f" {operator} ".join(f"({f})" for f in filters)


class PacketExporter:
    """Export captured packets to various formats"""
    
    def __init__(self):
        self.supported_formats = ["csv", "json", "txt"]
    
    def export_to_csv(self, packets: List, filename: str) -> None:
        """Export packets to CSV format"""
        import csv
        
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'protocol', 'src_ip', 'dst_ip', 
                         'src_port', 'dst_port', 'size', 'flags']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for packet in packets:
                writer.writerow({
                    'timestamp': packet.timestamp.isoformat(),
                    'protocol': packet.protocol,
                    'src_ip': packet.src_ip,
                    'dst_ip': packet.dst_ip,
                    'src_port': packet.src_port,
                    'dst_port': packet.dst_port,
                    'size': packet.size,
                    'flags': packet.flags
                })
    
    def export_to_json(self, packets: List, filename: str) -> None:
        """Export packets to JSON format"""
        import json
        
        data = []
        for packet in packets:
            data.append({
                'timestamp': packet.timestamp.isoformat(),
                'protocol': packet.protocol,
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'src_port': packet.src_port,
                'dst_port': packet.dst_port,
                'size': packet.size,
                'flags': packet.flags
            })
        
        with open(filename, 'w') as jsonfile:
            json.dump(data, jsonfile, indent=2)
    
    def export_to_txt(self, packets: List, filename: str) -> None:
        """Export packets to plain text format"""
        with open(filename, 'w') as txtfile:
            txtfile.write("Network Packet Capture Log\n")
            txtfile.write(f"Generated: {datetime.now().isoformat()}\n")
            txtfile.write("=" * 80 + "\n\n")
            
            for i, packet in enumerate(packets, 1):
                txtfile.write(f"Packet #{i}\n")
                txtfile.write(f"  Timestamp: {packet.timestamp}\n")
                txtfile.write(f"  Protocol: {packet.protocol}\n")
                txtfile.write(f"  Source: {packet.src_ip}")
                if packet.src_port:
                    txtfile.write(f":{packet.src_port}")
                txtfile.write("\n")
                txtfile.write(f"  Destination: {packet.dst_ip}")
                if packet.dst_port:
                    txtfile.write(f":{packet.dst_port}")
                txtfile.write("\n")
                txtfile.write(f"  Size: {packet.size} bytes\n")
                if packet.flags:
                    txtfile.write(f"  Flags: {packet.flags}\n")
                txtfile.write("\n")


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def validate_port(port: str) -> bool:
    """Validate port number"""
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except ValueError:
        return False