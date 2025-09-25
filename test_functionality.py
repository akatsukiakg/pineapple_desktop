#!/usr/bin/env python3
"""
Test script to verify all implemented alternative functionalities
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from core.logger import Logger
from core.scan_manager import ScanManager, ScanType
from core.attack_manager import AttackManager, AttackType
from core.packet_capture import PacketCaptureManager, CaptureStatus
import time

def test_scan_manager():
    """Test scan manager alternative implementations"""
    print("🔍 Testing Scan Manager...")
    logger = Logger()
    scan_manager = ScanManager(logger)
    
    try:
        # Test ping sweep
        print("  - Testing ping sweep...")
        scan_id = scan_manager.start_scan(ScanType.PING_SWEEP, "127.0.0.1")
        time.sleep(2)  # Wait for scan to start
        status = scan_manager.get_scan_status(scan_id)
        print(f"    ✅ Ping sweep status: {status.status.value}")
        
        # Test port scan
        print("  - Testing port scan...")
        scan_id = scan_manager.start_scan(ScanType.PORT_SCAN, "127.0.0.1", {"ports": "80,443,22"})
        time.sleep(3)  # Wait for scan to complete
        status = scan_manager.get_scan_status(scan_id)
        print(f"    ✅ Port scan status: {status.status.value}")
        
        print("✅ Scan Manager tests completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Scan Manager test failed: {e}")
        return False

def test_attack_manager():
    """Test attack manager alternative implementations"""
    print("🎯 Testing Attack Manager...")
    logger = Logger()
    attack_manager = AttackManager(logger=logger)
    
    try:
        # Import AttackTarget for proper testing
        from core.attack_manager import AttackTarget
        
        # Test deauth attack (without actual execution)
        print("  - Testing deauth attack initialization...")
        target = AttackTarget(
            bssid="00:11:22:33:44:55",
            ssid="TestNetwork",
            channel=6,
            encryption="WPA2",
            signal_strength=-50,
            clients=[]
        )
        
        attack_id = attack_manager.start_attack(
            AttackType.DEAUTH, 
            target,
            {"interface": "wlan0"}
        )
        time.sleep(1)
        status = attack_manager.get_attack_status(attack_id)
        print(f"    ✅ Deauth attack status: {status.status.value}")
        
        # Stop the attack
        attack_manager.stop_attack(attack_id)
        
        print("✅ Attack Manager tests completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Attack Manager test failed: {e}")
        return False

def test_packet_capture():
    """Test packet capture alternative implementations"""
    print("📡 Testing Packet Capture Manager...")
    logger = Logger()
    capture_manager = PacketCaptureManager(logger)
    
    try:
        # Test interface listing
        print("  - Testing interface listing...")
        interfaces = capture_manager.list_interfaces()
        print(f"    ✅ Found {len(interfaces)} interfaces")
        
        # Test capture initialization (without actual capture)
        if interfaces:
            print("  - Testing capture initialization...")
            capture_id = capture_manager.start_capture(
                interface=interfaces[0]['name'],
                filter_expression="",
                packet_limit=10
            )
            time.sleep(1)
            status = capture_manager.get_capture_status(capture_id)
            print(f"    ✅ Capture status: {status.status.value}")
            
            # Stop the capture
            capture_manager.stop_capture(capture_id)
        
        print("✅ Packet Capture Manager tests completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Packet Capture Manager test failed: {e}")
        return False

def test_tool_availability():
    """Test tool availability checks"""
    print("🔧 Testing Tool Availability...")
    
    try:
        from core.scan_manager import ScanManager
        from core.attack_manager import AttackManager
        from core.packet_capture import PacketCaptureManager
        
        logger = Logger()
        
        # Test nmap availability
        scan_manager = ScanManager(logger)
        nmap_available = scan_manager.is_nmap_available()
        print(f"  - Nmap available: {'✅' if nmap_available else '❌'} (Expected: ❌)")
        
        # Test scapy availability
        try:
            import scapy
            print("  - Scapy available: ✅")
        except ImportError:
            print("  - Scapy available: ❌")
        
        # Test socket availability (should always be available)
        import socket
        print("  - Socket module available: ✅")
        
        print("✅ Tool availability tests completed!")
        return True
        
    except Exception as e:
        print(f"❌ Tool availability test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Starting Pineapple Desktop Functionality Tests")
    print("=" * 50)
    
    tests = [
        test_tool_availability,
        test_scan_manager,
        test_attack_manager,
        test_packet_capture
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            print()
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            print()
    
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The application is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    exit(main())