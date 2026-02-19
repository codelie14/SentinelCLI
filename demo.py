#!/usr/bin/env python3
"""SentinelCLI Demo - Shows key functionality"""

from engine import SystemMonitor, NetworkMonitor, ThreatEngine
from modules import ProcessAnalyzer, ReportGenerator

print("\n" + "="*60)
print("🛡️  SENTINELCLI - DEMO")
print("="*60)

# 1. System Information
print("\n[1] SYSTEM INFORMATION")
print("-" * 60)
sm = SystemMonitor()
sys_info = sm.get_system_info()
mem_info = sm.get_memory_info()
cpu_info = sm.get_cpu_info()

print(f"Hostname: {sys_info['hostname']}")
print(f"OS: {sys_info['os']} {sys_info['os_version']}")
print(f"CPU Usage: {cpu_info['cpu_percent']:.1f}%")
print(f"RAM Usage: {mem_info['ram_percent']:.1f}% ({mem_info['ram_used']/(1024**3):.2f}GB / {mem_info['ram_total']/(1024**3):.2f}GB)")

# 2. Network Information
print("\n[2] NETWORK ANALYSIS")
print("-" * 60)
nm = NetworkMonitor()
ports = nm.get_open_ports()
connections = nm.get_connections()
suspicious = nm.get_suspicious_connections()

print(f"Open Ports: {len(ports.get('open_ports', {}))}")
for port, info in list(ports.get('open_ports', {}).items())[:5]:
    print(f"  - Port {port}: {info['service']}")

print(f"\nActive Connections: {len(connections.get('connections', []))}")
print(f"Suspicious Connections: {len(suspicious.get('suspicious_connections', []))}")

# 3. Process Analysis
print("\n[3] PROCESS ANALYSIS")
print("-" * 60)
pa = ProcessAnalyzer()
all_procs = pa.get_all_processes()
high_res = pa.get_high_resource_processes()

print(f"Total Processes: {all_procs['total_count']}")
print(f"High Resource Processes: {high_res['count']}")

if high_res['high_resource_processes']:
    print("\nTop Resource Consumers:")
    for proc in high_res['high_resource_processes'][:3]:
        print(f"  - {proc['name']}: CPU {proc['cpu_percent']:.1f}%, RAM {proc['memory_percent']:.1f}%")

# 4. Security Score
print("\n[4] SECURITY ANALYSIS")
print("-" * 60)
te = ThreatEngine()
system_data = {**sys_info, **cpu_info, **mem_info}
network_data = {**ports, **suspicious}

threat_analysis = te.calculate_security_score(system_data, network_data)
score = threat_analysis['security_score']
level = threat_analysis['threat_level']

print(f"Security Score: {score}/100")
print(f"Threat Level: {level}")
print(f"Threats Detected: {threat_analysis['total_threats']}")

# 5. Recommendations
print("\n[5] SECURITY RECOMMENDATIONS")
print("-" * 60)
recommendations = te.generate_recommendations(threat_analysis)
for rec in recommendations[:5]:
    print(f"• {rec}")

# 6. Report Generation
print("\n[6] REPORT GENERATION")
print("-" * 60)
rg = ReportGenerator()
report_path = rg.generate_markdown_report(
    system_data, 
    network_data, 
    threat_analysis, 
    recommendations,
    "SentinelCLI_Demo_Report.md"
)
print(f"✓ Report generated: {report_path}")

print("\n" + "="*60)
print("Demo completed successfully!")
print("To start the interactive CLI: python sentinel.py")
print("="*60 + "\n")
