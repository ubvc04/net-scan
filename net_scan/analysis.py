"""
Packet analysis and filtering utilities
"""

import re
from typing import List, Dict, Any, Optional, Callable, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, Counter

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP

from .capture import PacketInfo


@dataclass
class AnalysisResult:
    """Container for analysis results"""
    timestamp: datetime
    analysis_type: str
    description: str
    severity: str  # "info", "warning", "critical"
    related_packets: List[PacketInfo]
    metadata: Dict[str, Any]


class PacketFilter:
    """Advanced packet filtering capabilities"""
    
    def __init__(self):
        self.filters: List[Callable[[PacketInfo], bool]] = []
    
    def add_protocol_filter(self, protocols: List[str]) -> None:
        """Filter by protocol types"""
        protocols_upper = [p.upper() for p in protocols]
        self.filters.append(lambda p: p.protocol.upper() in protocols_upper)
    
    def add_ip_filter(self, ips: List[str], match_src: bool = True, match_dst: bool = True) -> None:
        """Filter by source and/or destination IP addresses"""
        def ip_filter(packet: PacketInfo) -> bool:
            matches = []
            if match_src:
                matches.append(any(ip in packet.src_ip for ip in ips))
            if match_dst:
                matches.append(any(ip in packet.dst_ip for ip in ips))
            return any(matches)
        
        self.filters.append(ip_filter)
    
    def add_port_filter(self, ports: List[int], match_src: bool = True, match_dst: bool = True) -> None:
        """Filter by source and/or destination ports"""
        def port_filter(packet: PacketInfo) -> bool:
            matches = []
            if match_src and packet.src_port:
                matches.append(packet.src_port in ports)
            if match_dst and packet.dst_port:
                matches.append(packet.dst_port in ports)
            return any(matches)
        
        self.filters.append(port_filter)
    
    def add_size_filter(self, min_size: Optional[int] = None, max_size: Optional[int] = None) -> None:
        """Filter by packet size"""
        def size_filter(packet: PacketInfo) -> bool:
            if min_size is not None and packet.size < min_size:
                return False
            if max_size is not None and packet.size > max_size:
                return False
            return True
        
        self.filters.append(size_filter)
    
    def add_time_filter(self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> None:
        """Filter by timestamp range"""
        def time_filter(packet: PacketInfo) -> bool:
            if start_time is not None and packet.timestamp < start_time:
                return False
            if end_time is not None and packet.timestamp > end_time:
                return False
            return True
        
        self.filters.append(time_filter)
    
    def add_regex_filter(self, pattern: str, field: str = "all") -> None:
        """Filter using regex pattern on packet fields"""
        regex = re.compile(pattern, re.IGNORECASE)
        
        def regex_filter(packet: PacketInfo) -> bool:
            text_to_search = ""
            
            if field == "all" or field == "src_ip":
                text_to_search += packet.src_ip + " "
            if field == "all" or field == "dst_ip":
                text_to_search += packet.dst_ip + " "
            if field == "all" or field == "protocol":
                text_to_search += packet.protocol + " "
            if field == "all" or field == "flags":
                text_to_search += packet.flags + " "
            
            return bool(regex.search(text_to_search.strip()))
        
        self.filters.append(regex_filter)
    
    def apply_filters(self, packets: List[PacketInfo]) -> List[PacketInfo]:
        """Apply all filters to a list of packets"""
        if not self.filters:
            return packets
        
        filtered_packets = []
        for packet in packets:
            if all(filter_func(packet) for filter_func in self.filters):
                filtered_packets.append(packet)
        
        return filtered_packets
    
    def clear_filters(self) -> None:
        """Clear all filters"""
        self.filters.clear()


class PacketAnalyzer:
    """Advanced packet analysis and pattern detection"""
    
    def __init__(self):
        self.connection_tracker: Dict[str, Dict] = defaultdict(dict)
        self.port_scanner_detector = PortScanDetector()
        self.dos_detector = DoSDetector()
        self.protocol_analyzer = ProtocolAnalyzer()
    
    def analyze_packet(self, packet: PacketInfo) -> List[AnalysisResult]:
        """Analyze a single packet and return analysis results"""
        results = []
        
        # Track connections
        self._track_connection(packet)
        
        # Check for port scanning
        port_scan_result = self.port_scanner_detector.check_packet(packet)
        if port_scan_result:
            results.append(port_scan_result)
        
        # Check for DoS patterns
        dos_result = self.dos_detector.check_packet(packet)
        if dos_result:
            results.append(dos_result)
        
        # Protocol-specific analysis
        protocol_results = self.protocol_analyzer.analyze_packet(packet)
        results.extend(protocol_results)
        
        return results
    
    def _track_connection(self, packet: PacketInfo) -> None:
        """Track connection states and statistics"""
        if packet.protocol in ["TCP", "UDP"] and packet.src_port and packet.dst_port:
            connection_key = f"{packet.src_ip}:{packet.src_port}->{packet.dst_ip}:{packet.dst_port}"
            
            if connection_key not in self.connection_tracker:
                self.connection_tracker[connection_key] = {
                    "first_seen": packet.timestamp,
                    "last_seen": packet.timestamp,
                    "packet_count": 0,
                    "total_bytes": 0,
                    "protocol": packet.protocol
                }
            
            conn = self.connection_tracker[connection_key]
            conn["last_seen"] = packet.timestamp
            conn["packet_count"] += 1
            conn["total_bytes"] += packet.size
    
    def get_connection_summary(self) -> Dict[str, Any]:
        """Get summary of tracked connections"""
        active_connections = 0
        total_connections = len(self.connection_tracker)
        
        # Consider connections active if seen within last 30 seconds
        cutoff_time = datetime.now() - timedelta(seconds=30)
        
        for conn in self.connection_tracker.values():
            if conn["last_seen"] > cutoff_time:
                active_connections += 1
        
        return {
            "total_connections": total_connections,
            "active_connections": active_connections,
            "top_connections": self._get_top_connections()
        }
    
    def _get_top_connections(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top connections by packet count"""
        connections = []
        for conn_key, conn_data in self.connection_tracker.items():
            connections.append({
                "connection": conn_key,
                "packet_count": conn_data["packet_count"],
                "total_bytes": conn_data["total_bytes"],
                "protocol": conn_data["protocol"],
                "duration": (conn_data["last_seen"] - conn_data["first_seen"]).total_seconds()
            })
        
        return sorted(connections, key=lambda x: x["packet_count"], reverse=True)[:limit]


class PortScanDetector:
    """Detect port scanning activities"""
    
    def __init__(self, threshold: int = 10, time_window: int = 60):
        self.threshold = threshold
        self.time_window = time_window
        self.scan_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.target_ports: Dict[str, set] = defaultdict(set)
    
    def check_packet(self, packet: PacketInfo) -> Optional[AnalysisResult]:
        """Check if packet indicates port scanning"""
        if packet.protocol != "TCP" or not packet.dst_port:
            return None
        
        # Track connection attempts per source IP
        src_ip = packet.src_ip
        current_time = packet.timestamp
        
        # Clean old entries
        self.scan_attempts[src_ip] = [
            t for t in self.scan_attempts[src_ip]
            if (current_time - t).total_seconds() <= self.time_window
        ]
        
        # Add current attempt
        self.scan_attempts[src_ip].append(current_time)
        self.target_ports[src_ip].add(packet.dst_port)
        
        # Check if threshold exceeded
        if (len(self.scan_attempts[src_ip]) >= self.threshold and
            len(self.target_ports[src_ip]) >= self.threshold // 2):
            
            return AnalysisResult(
                timestamp=current_time,
                analysis_type="Port Scan Detection",
                description=f"Potential port scan from {src_ip} - {len(self.scan_attempts[src_ip])} attempts to {len(self.target_ports[src_ip])} ports",
                severity="warning",
                related_packets=[packet],
                metadata={
                    "source_ip": src_ip,
                    "attempt_count": len(self.scan_attempts[src_ip]),
                    "target_ports": list(self.target_ports[src_ip]),
                    "time_window": self.time_window
                }
            )
        
        return None


class DoSDetector:
    """Detect Denial of Service attack patterns"""
    
    def __init__(self, threshold: int = 100, time_window: int = 10):
        self.threshold = threshold
        self.time_window = time_window
        self.packet_counts: Dict[str, List[datetime]] = defaultdict(list)
    
    def check_packet(self, packet: PacketInfo) -> Optional[AnalysisResult]:
        """Check if packet indicates DoS activity"""
        src_ip = packet.src_ip
        current_time = packet.timestamp
        
        # Clean old entries
        self.packet_counts[src_ip] = [
            t for t in self.packet_counts[src_ip]
            if (current_time - t).total_seconds() <= self.time_window
        ]
        
        # Add current packet
        self.packet_counts[src_ip].append(current_time)
        
        # Check if threshold exceeded
        if len(self.packet_counts[src_ip]) >= self.threshold:
            return AnalysisResult(
                timestamp=current_time,
                analysis_type="DoS Detection",
                description=f"Potential DoS attack from {src_ip} - {len(self.packet_counts[src_ip])} packets in {self.time_window} seconds",
                severity="critical",
                related_packets=[packet],
                metadata={
                    "source_ip": src_ip,
                    "packet_count": len(self.packet_counts[src_ip]),
                    "time_window": self.time_window,
                    "rate": len(self.packet_counts[src_ip]) / self.time_window
                }
            )
        
        return None


class ProtocolAnalyzer:
    """Protocol-specific analysis"""
    
    def analyze_packet(self, packet: PacketInfo) -> List[AnalysisResult]:
        """Analyze packet based on its protocol"""
        results = []
        
        if packet.protocol == "TCP":
            results.extend(self._analyze_tcp(packet))
        elif packet.protocol == "UDP":
            results.extend(self._analyze_udp(packet))
        elif packet.protocol == "ICMP":
            results.extend(self._analyze_icmp(packet))
        elif packet.protocol == "ARP":
            results.extend(self._analyze_arp(packet))
        
        return results
    
    def _analyze_tcp(self, packet: PacketInfo) -> List[AnalysisResult]:
        """Analyze TCP-specific patterns"""
        results = []
        
        # Check for suspicious port combinations
        if packet.dst_port in [22, 23, 80, 443, 3389]:  # Common attack targets
            if "SYN" in packet.flags and "ACK" not in packet.flags:
                results.append(AnalysisResult(
                    timestamp=packet.timestamp,
                    analysis_type="TCP Analysis",
                    description=f"Connection attempt to common service port {packet.dst_port}",
                    severity="info",
                    related_packets=[packet],
                    metadata={"service_port": packet.dst_port, "flags": packet.flags}
                ))
        
        return results
    
    def _analyze_udp(self, packet: PacketInfo) -> List[AnalysisResult]:
        """Analyze UDP-specific patterns"""
        results = []
        
        # Check for DNS queries
        if packet.dst_port == 53:
            results.append(AnalysisResult(
                timestamp=packet.timestamp,
                analysis_type="UDP Analysis",
                description="DNS query detected",
                severity="info",
                related_packets=[packet],
                metadata={"service": "DNS", "port": 53}
            ))
        
        return results
    
    def _analyze_icmp(self, packet: PacketInfo) -> List[AnalysisResult]:
        """Analyze ICMP-specific patterns"""
        results = []
        
        # Basic ICMP analysis
        results.append(AnalysisResult(
            timestamp=packet.timestamp,
            analysis_type="ICMP Analysis",
            description=f"ICMP packet: {packet.flags}",
            severity="info",
            related_packets=[packet],
            metadata={"icmp_info": packet.flags}
        ))
        
        return results
    
    def _analyze_arp(self, packet: PacketInfo) -> List[AnalysisResult]:
        """Analyze ARP-specific patterns"""
        results = []
        
        # Basic ARP analysis
        results.append(AnalysisResult(
            timestamp=packet.timestamp,
            analysis_type="ARP Analysis",
            description=f"ARP packet: {packet.flags}",
            severity="info",
            related_packets=[packet],
            metadata={"arp_info": packet.flags}
        ))
        
        return results


class NetworkStatistics:
    """Generate comprehensive network statistics"""
    
    def __init__(self):
        self.reset()
    
    def reset(self) -> None:
        """Reset all statistics"""
        self.protocol_stats = Counter()
        self.size_stats = {"total_bytes": 0, "avg_size": 0, "min_size": float('inf'), "max_size": 0}
        self.ip_stats = {"src_ips": Counter(), "dst_ips": Counter()}
        self.port_stats = {"src_ports": Counter(), "dst_ports": Counter()}
        self.time_stats = {"first_packet": None, "last_packet": None}
        self.packet_count = 0
    
    def update(self, packet: PacketInfo) -> None:
        """Update statistics with a new packet"""
        self.packet_count += 1
        
        # Protocol statistics
        self.protocol_stats[packet.protocol] += 1
        
        # Size statistics
        self.size_stats["total_bytes"] += packet.size
        self.size_stats["avg_size"] = self.size_stats["total_bytes"] / self.packet_count
        self.size_stats["min_size"] = min(self.size_stats["min_size"], packet.size)
        self.size_stats["max_size"] = max(self.size_stats["max_size"], packet.size)
        
        # IP statistics
        self.ip_stats["src_ips"][packet.src_ip] += 1
        self.ip_stats["dst_ips"][packet.dst_ip] += 1
        
        # Port statistics
        if packet.src_port:
            self.port_stats["src_ports"][packet.src_port] += 1
        if packet.dst_port:
            self.port_stats["dst_ports"][packet.dst_port] += 1
        
        # Time statistics
        if self.time_stats["first_packet"] is None:
            self.time_stats["first_packet"] = packet.timestamp
        self.time_stats["last_packet"] = packet.timestamp
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive statistics summary"""
        duration = 0
        if (self.time_stats["first_packet"] and self.time_stats["last_packet"]):
            duration = (self.time_stats["last_packet"] - self.time_stats["first_packet"]).total_seconds()
        
        return {
            "packet_count": self.packet_count,
            "duration_seconds": duration,
            "packets_per_second": self.packet_count / max(duration, 1),
            "protocol_distribution": dict(self.protocol_stats.most_common()),
            "size_statistics": self.size_stats.copy(),
            "top_source_ips": dict(self.ip_stats["src_ips"].most_common(10)),
            "top_destination_ips": dict(self.ip_stats["dst_ips"].most_common(10)),
            "top_source_ports": dict(self.port_stats["src_ports"].most_common(10)),
            "top_destination_ports": dict(self.port_stats["dst_ports"].most_common(10))
        }