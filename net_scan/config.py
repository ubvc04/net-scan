"""
Configuration settings for the network scanner
"""

import os
from typing import Dict, Any

# Application configuration
APP_CONFIG = {
    "name": "Network Scanner TUI",
    "version": "1.0.0",
    "description": "Terminal-based network packet capture and analysis tool",
    "author": "Network Scanner Team"
}

# Default capture settings
CAPTURE_CONFIG = {
    "max_packets_memory": 1000,
    "update_interval": 0.5,  # seconds
    "capture_timeout": 30,   # seconds
    "buffer_size": 65536,    # bytes
    "promisc_mode": True,
    "default_filter": ""
}

# Analysis configuration
ANALYSIS_CONFIG = {
    "port_scan_threshold": 10,       # connections per time window
    "port_scan_time_window": 60,     # seconds
    "dos_threshold": 100,            # packets per time window
    "dos_time_window": 10,           # seconds
    "connection_timeout": 300,       # seconds
    "max_connections_tracked": 10000
}

# UI configuration
UI_CONFIG = {
    "refresh_rate": 2,              # Hz
    "max_table_rows": 100,
    "table_auto_scroll": True,
    "color_scheme": "default",
    "show_packet_details": True,
    "show_statistics": True
}

# Logging configuration
LOG_CONFIG = {
    "level": "INFO",
    "file": "network_scanner.log",
    "max_size": 10 * 1024 * 1024,  # 10MB
    "backup_count": 5,
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
}

# Protocol port mappings
PROTOCOL_PORTS = {
    "HTTP": [80, 8080, 8000, 3000],
    "HTTPS": [443, 8443],
    "SSH": [22],
    "Telnet": [23],
    "FTP": [21, 20],
    "SMTP": [25, 587],
    "POP3": [110, 995],
    "IMAP": [143, 993],
    "DNS": [53],
    "DHCP": [67, 68],
    "SNMP": [161, 162],
    "LDAP": [389, 636],
    "RDP": [3389],
    "VNC": [5900, 5901, 5902],
    "MySQL": [3306],
    "PostgreSQL": [5432],
    "MongoDB": [27017],
    "Redis": [6379]
}

# Security analysis rules
SECURITY_RULES = {
    "suspicious_ports": [1337, 31337, 12345, 54321],
    "common_attack_ports": [135, 139, 445, 1433, 1521, 3389],
    "honeypot_indicators": ["unused_port_range"],
    "malware_ports": [6666, 6667, 9999]
}

# Export formats
EXPORT_FORMATS = {
    "csv": {
        "extension": ".csv",
        "description": "Comma-separated values"
    },
    "json": {
        "extension": ".json", 
        "description": "JavaScript Object Notation"
    },
    "txt": {
        "extension": ".txt",
        "description": "Plain text format"
    },
    "pcap": {
        "extension": ".pcap",
        "description": "Packet capture format (not implemented)"
    }
}

# Filter presets
FILTER_PRESETS = {
    "Web Traffic": "tcp port 80 or tcp port 443",
    "Email": "tcp port 25 or tcp port 110 or tcp port 143 or tcp port 587 or tcp port 993 or tcp port 995",
    "DNS": "udp port 53",
    "SSH": "tcp port 22",
    "Database": "tcp port 3306 or tcp port 5432 or tcp port 1433 or tcp port 1521",
    "File Transfer": "tcp port 21 or tcp port 22 or tcp port 445",
    "Broadcast": "broadcast",
    "Multicast": "multicast",
    "IPv6": "ip6",
    "Large Packets": "greater 1500",
    "Small Packets": "less 64"
}

def get_config(section: str) -> Dict[str, Any]:
    """Get configuration for a specific section"""
    configs = {
        "app": APP_CONFIG,
        "capture": CAPTURE_CONFIG,
        "analysis": ANALYSIS_CONFIG,
        "ui": UI_CONFIG,
        "log": LOG_CONFIG
    }
    return configs.get(section, {})

def get_protocol_ports(protocol: str) -> list:
    """Get list of ports for a protocol"""
    return PROTOCOL_PORTS.get(protocol.upper(), [])

def get_filter_preset(name: str) -> str:
    """Get filter expression for a preset"""
    return FILTER_PRESETS.get(name, "")

def is_suspicious_port(port: int) -> bool:
    """Check if port is considered suspicious"""
    return port in SECURITY_RULES["suspicious_ports"]

def is_attack_port(port: int) -> bool:
    """Check if port is commonly targeted in attacks"""
    return port in SECURITY_RULES["common_attack_ports"]