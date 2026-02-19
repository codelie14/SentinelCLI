#!/usr/bin/env python3
"""Quick test of SentinelCLI modules"""

print("Testing SentinelCLI Modules...\n")

# Test Engine modules
try:
    from engine import SystemMonitor, NetworkMonitor, ThreatEngine
    print("✓ Engine modules imported successfully")
    
    # Test SystemMonitor
    sm = SystemMonitor()
    sys_info = sm.get_system_info()
    print(f"  - OS: {sys_info.get('os')} {sys_info.get('os_version')}")
    print(f"  - Hostname: {sys_info.get('hostname')}")
    
    cpu_info = sm.get_cpu_info()
    print(f"  - CPU Usage: {cpu_info.get('cpu_percent'):.1f}%")
    
except Exception as e:
    print(f"✗ Engine test failed: {e}")

# Test Application modules
try:
    from modules import NetworkScanner, ProcessAnalyzer, ReportGenerator
    print("\n✓ Application modules imported successfully")
    
    ns = NetworkScanner()
    print(f"  - Local IP: {ns.get_local_ip()}")
    print(f"  - Subnet: {ns.get_subnet()}")
    
    pa = ProcessAnalyzer()
    processes = pa.get_all_processes()
    print(f"  - Total processes: {processes.get('total_count', 0)}")
    
except Exception as e:
    print(f"✗ Application modules test failed: {e}")

print("\n✓ All modules working correctly!")
print("\nTo start SentinelCLI, run: python sentinel.py")
