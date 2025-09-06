#!/usr/bin/env python3
"""
Test script for Network Scanner TUI
Validates functionality without requiring root privileges
"""

import sys
import os
import unittest
from unittest.mock import Mock, patch
from datetime import datetime

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from net_scan.capture import PacketInfo, NetworkInterface
    from net_scan.analysis import PacketFilter, PacketAnalyzer, NetworkStatistics
    from net_scan.utils import validate_ip_address, validate_port, format_bytes
    from net_scan.config import get_config, get_protocol_ports
except ImportError as e:
    print(f"Import error: {e}")
    print("Please run 'pip install -r requirements.txt' first")
    sys.exit(1)


class TestPacketInfo(unittest.TestCase):
    """Test PacketInfo data class"""
    
    def test_packet_info_creation(self):
        """Test creating PacketInfo instance"""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=1500,
            flags="SYN,ACK",
            raw_packet=Mock()
        )
        
        self.assertEqual(packet.src_ip, "192.168.1.1")
        self.assertEqual(packet.dst_ip, "192.168.1.2")
        self.assertEqual(packet.protocol, "TCP")
        self.assertIsNotNone(str(packet))


class TestNetworkInterface(unittest.TestCase):
    """Test NetworkInterface utilities"""
    
    def test_get_available_interfaces(self):
        """Test getting available interfaces"""
        interfaces = NetworkInterface.get_available_interfaces()
        self.assertIsInstance(interfaces, list)
        self.assertGreater(len(interfaces), 0)
    
    def test_get_default_interface(self):
        """Test getting default interface"""
        default = NetworkInterface.get_default_interface()
        self.assertIsInstance(default, (str, type(None)))


class TestPacketFilter(unittest.TestCase):
    """Test packet filtering functionality"""
    
    def setUp(self):
        self.filter = PacketFilter()
        self.sample_packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=1500,
            flags="SYN",
            raw_packet=Mock()
        )
    
    def test_protocol_filter(self):
        """Test protocol filtering"""
        self.filter.add_protocol_filter(["TCP"])
        result = self.filter.apply_filters([self.sample_packet])
        self.assertEqual(len(result), 1)
        
        self.filter.clear_filters()
        self.filter.add_protocol_filter(["UDP"])
        result = self.filter.apply_filters([self.sample_packet])
        self.assertEqual(len(result), 0)
    
    def test_ip_filter(self):
        """Test IP address filtering"""
        self.filter.add_ip_filter(["192.168.1.1"])
        result = self.filter.apply_filters([self.sample_packet])
        self.assertEqual(len(result), 1)
        
        self.filter.clear_filters()
        self.filter.add_ip_filter(["192.168.1.2"])
        result = self.filter.apply_filters([self.sample_packet])
        self.assertEqual(len(result), 0)
    
    def test_port_filter(self):
        """Test port filtering"""
        self.filter.add_port_filter([80])
        result = self.filter.apply_filters([self.sample_packet])
        self.assertEqual(len(result), 1)
        
        self.filter.clear_filters()
        self.filter.add_port_filter([443])
        result = self.filter.apply_filters([self.sample_packet])
        self.assertEqual(len(result), 0)


class TestPacketAnalyzer(unittest.TestCase):
    """Test packet analysis functionality"""
    
    def setUp(self):
        self.analyzer = PacketAnalyzer()
        self.sample_packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=1500,
            flags="SYN",
            raw_packet=Mock()
        )
    
    def test_analyze_packet(self):
        """Test packet analysis"""
        results = self.analyzer.analyze_packet(self.sample_packet)
        self.assertIsInstance(results, list)
    
    def test_connection_summary(self):
        """Test connection summary"""
        self.analyzer.analyze_packet(self.sample_packet)
        summary = self.analyzer.get_connection_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn("total_connections", summary)


class TestNetworkStatistics(unittest.TestCase):
    """Test network statistics functionality"""
    
    def setUp(self):
        self.stats = NetworkStatistics()
        self.sample_packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=1500,
            flags="SYN",
            raw_packet=Mock()
        )
    
    def test_update_statistics(self):
        """Test updating statistics"""
        self.stats.update(self.sample_packet)
        summary = self.stats.get_summary()
        
        self.assertEqual(summary["packet_count"], 1)
        self.assertIn("TCP", summary["protocol_distribution"])
        self.assertEqual(summary["size_statistics"]["total_bytes"], 1500)
    
    def test_reset_statistics(self):
        """Test resetting statistics"""
        self.stats.update(self.sample_packet)
        self.stats.reset()
        summary = self.stats.get_summary()
        
        self.assertEqual(summary["packet_count"], 0)
        self.assertEqual(summary["size_statistics"]["total_bytes"], 0)


class TestUtilities(unittest.TestCase):
    """Test utility functions"""
    
    def test_validate_ip_address(self):
        """Test IP address validation"""
        self.assertTrue(validate_ip_address("192.168.1.1"))
        self.assertTrue(validate_ip_address("10.0.0.1"))
        self.assertFalse(validate_ip_address("256.256.256.256"))
        self.assertFalse(validate_ip_address("not.an.ip"))
    
    def test_validate_port(self):
        """Test port validation"""
        self.assertTrue(validate_port("80"))
        self.assertTrue(validate_port("65535"))
        self.assertFalse(validate_port("65536"))
        self.assertFalse(validate_port("not_a_port"))
        self.assertFalse(validate_port("-1"))
    
    def test_format_bytes(self):
        """Test byte formatting"""
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(1048576), "1.0 MB")
        self.assertIn("B", format_bytes(500))


class TestConfiguration(unittest.TestCase):
    """Test configuration functionality"""
    
    def test_get_config(self):
        """Test getting configuration"""
        app_config = get_config("app")
        self.assertIsInstance(app_config, dict)
        self.assertIn("name", app_config)
    
    def test_get_protocol_ports(self):
        """Test getting protocol ports"""
        http_ports = get_protocol_ports("HTTP")
        self.assertIsInstance(http_ports, list)
        self.assertIn(80, http_ports)


def run_dependency_check():
    """Check if all required dependencies are available"""
    print("Checking dependencies...")
    
    required_modules = [
        "scapy",
        "rich", 
        "click",
        "textual",
        "psutil"
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError:
            print(f"✗ {module} (missing)")
            missing_modules.append(module)
    
    if missing_modules:
        print(f"\nMissing dependencies: {', '.join(missing_modules)}")
        print("Run: pip install -r requirements.txt")
        return False
    
    print("\n✓ All dependencies available")
    return True


def run_interface_check():
    """Check network interface availability"""
    print("\nChecking network interfaces...")
    
    try:
        interfaces = NetworkInterface.get_available_interfaces()
        default = NetworkInterface.get_default_interface()
        
        print(f"Available interfaces: {', '.join(interfaces)}")
        print(f"Default interface: {default}")
        
        if not interfaces:
            print("⚠️  No network interfaces found")
            return False
        
        print("✓ Network interfaces available")
        return True
        
    except Exception as e:
        print(f"✗ Error checking interfaces: {e}")
        return False


def main():
    """Main test function"""
    print("Network Scanner TUI - Test Suite")
    print("=" * 50)
    
    # Check dependencies
    deps_ok = run_dependency_check()
    if not deps_ok:
        print("\n❌ Dependency check failed")
        sys.exit(1)
    
    # Check interfaces
    interface_ok = run_interface_check()
    
    # Run unit tests
    print("\nRunning unit tests...")
    print("-" * 30)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    print("\n" + "=" * 50)
    print("Test Summary:")
    print(f"Dependencies: {'✓ OK' if deps_ok else '✗ FAILED'}")
    print(f"Interfaces: {'✓ OK' if interface_ok else '⚠️  WARNING'}")
    print(f"Unit Tests: {'✓ OK' if result.wasSuccessful() else '✗ FAILED'}")
    
    if result.wasSuccessful() and deps_ok:
        print("\n🎉 All tests passed! The application is ready to use.")
        print("\nTo run the application:")
        print("  sudo python main.py")
        print("  sudo python main.py --simple")
        print("  sudo python main.py --list-interfaces")
    else:
        print("\n❌ Some tests failed. Please check the output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()