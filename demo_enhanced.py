#!/usr/bin/env python3
"""Enhanced SentinelCLI Demo - Showcases all advanced features"""

from engine import (
    SystemMonitor, NetworkMonitor, ThreatEngine,
    AnomalyDetector, AdvancedPortScanner, VulnerabilityAssessment,
    AdvancedLogger, AlertSystem
)
from modules import ReportGenerator

print("\n" + "="*70)
print("🛡️  SENTINELCLI - ENHANCED DEMO")
print("="*70)

# Initialize components
sm = SystemMonitor()
nm = NetworkMonitor()
te = ThreatEngine()
ad = AnomalyDetector()
aps = AdvancedPortScanner()
va = VulnerabilityAssessment()
rg = ReportGenerator()
logger = AdvancedLogger()
alert_sys = AlertSystem(logger)

# 1. System Information
print("\n[1] SYSTEM INFORMATION")
print("-" * 70)
sys_info = sm.get_system_info()
mem_info = sm.get_memory_info()
cpu_info = sm.get_cpu_info()
processes = sm.get_processes(limit=50)

print(f"Hostname: {sys_info['hostname']}")
print(f"OS: {sys_info['os']} {sys_info['os_version']}")
print(f"CPU Usage: {cpu_info['cpu_percent']:.1f}%")
print(f"RAM Usage: {mem_info['ram_percent']:.1f}%")
print(f"Total Processes: {processes['total_processes']}")

# Log events
logger.log_event('system_scan', 'system', {'processes': processes['total_processes']})

# 2. Anomaly Detection
print("\n[2] ANOMALY DETECTION")
print("-" * 70)
process_anomalies = ad.detect_process_anomalies(processes.get('processes', []))
resource_anomalies = ad.detect_resource_anomalies(
    cpu_info['cpu_percent'], 
    mem_info['ram_percent'], 
    list(sm.get_disk_info().get('disks', {}).values())[0]['percent'] if sm.get_disk_info().get('disks') else 0
)

print(f"Process Anomalies: {process_anomalies['count']}")
print(f"Resource Anomalies: {resource_anomalies['count']}")
print(f"Resource Risk Level: {resource_anomalies.get('overall_risk', 'UNKNOWN')}")

if process_anomalies.get('anomalies_detected'):
    print("\nAnomalous Processes:")
    for anom in process_anomalies['anomalies_detected'][:3]:
        print(f"  - {anom.get('type')}: {anom.get('severity')}")

# 3. Network and Port Analysis
print("\n[3] NETWORK & PORT ANALYSIS")
print("-" * 70)
ports = nm.get_open_ports()
connections = nm.get_connections()
suspicious = nm.get_suspicious_connections()

port_analysis = aps.analyze_open_ports(ports.get('open_ports', {}))
port_anomalies = aps.detect_port_anomalies(ports.get('open_ports', {}))

print(f"Open Ports: {len(ports.get('open_ports', {}))}")
print(f"High-Risk Ports: {len(port_analysis['port_analysis'].get('high_risk_ports', []))}")
print(f"Active Connections: {len(connections.get('connections', []))}")
print(f"Suspicious Connections: {len(suspicious.get('suspicious_connections', []))}")
print(f"Port Analysis Risk Score: {port_analysis['risk_score']}/100")

# 4. Vulnerability Assessment
print("\n[4] VULNERABILITY ASSESSMENT")
print("-" * 70)
vuln_scan = va.scan_vulnerabilities(sys_info, ports.get('open_ports', {}), processes.get('processes', []))

print(f"Total Vulnerabilities Found: {vuln_scan['vulnerability_count']}")
severity = vuln_scan['severity_breakdown']
print(f"  - CRITICAL: {severity.get('CRITICAL', 0)}")
print(f"  - HIGH: {severity.get('HIGH', 0)}")
print(f"  - MEDIUM: {severity.get('MEDIUM', 0)}")
print(f"  - LOW: {severity.get('LOW', 0)}")

# 5. Security Scoring
print("\n[5] SECURITY SCORING & THREAT ANALYSIS")
print("-" * 70)
system_data = {**sys_info, **cpu_info, **mem_info}
network_data = {**ports, **suspicious}

threat_analysis = te.calculate_security_score(system_data, network_data)
score = threat_analysis['security_score']
level = threat_analysis['threat_level']

if score >= 75:
    emoji = "🟢"
elif score >= 50:
    emoji = "🟡"
elif score >= 25:
    emoji = "🟠"
else:
    emoji = "🔴"

print(f"{emoji} Security Score: {score}/100")
print(f"Threat Level: {level}")
print(f"Threats Detected: {threat_analysis['total_threats']}")

# 6. Alert Generation
print("\n[6] ALERT SYSTEM")
print("-" * 70)
health_alerts = alert_sys.check_system_health(
    cpu_info['cpu_percent'], 
    mem_info['ram_percent'], 
    list(sm.get_disk_info().get('disks', {}).values())[0]['percent'] if sm.get_disk_info().get('disks') else 0
)
threat_alerts = alert_sys.check_security_threats(threat_analysis['total_threats'])

all_alerts = health_alerts + threat_alerts
print(f"Active Alerts: {len(all_alerts)}")

for alert in all_alerts:
    print(f"\n  [{alert['severity']}] {alert['title']}")
    print(f"  Description: {alert['description']}")

# 7. Recommendations
print("\n[7] SECURITY RECOMMENDATIONS")
print("-" * 70)
recommendations = te.generate_recommendations(threat_analysis)

print("\nTop Recommendations:")
for i, rec in enumerate(recommendations[:5], 1):
    print(f"{i}. {rec}")

# 8. Report Generation
print("\n[8] COMPREHENSIVE REPORT GENERATION")
print("-" * 70)

report_path = rg.generate_markdown_report(
    system_data,
    network_data,
    threat_analysis,
    recommendations,
    vulnerabilities=vuln_scan,
    anomalies=process_anomalies,
    filename="SentinelCLI_Enhanced_Demo_Report.md"
)

json_path = rg.export_json(
    {
        'system': system_data,
        'network': network_data,
        'threats': threat_analysis,
        'vulnerabilities': vuln_scan,
        'anomalies': process_anomalies
    },
    filename="SentinelCLI_Enhanced_Demo_Data.json"
)

print(f"✓ Markdown Report: {report_path}")
print(f"✓ JSON Data Export: {json_path}")

# 9. Logging Summary
print("\n[9] LOGGING & STATISTICS")
print("-" * 70)
stats = logger.get_statistics()
print(f"Total Events Logged: {stats['total_events']}")
print(f"Total Alerts Logged: {stats['total_alerts']}")
print(f"Total Security Events: {stats['total_security_events']}")

summary = logger.generate_summary_report()
print("\n" + summary)

print("\n" + "="*70)
print("Enhanced Demo completed successfully!")
print("="*70 + "\n")

print("Generated Files:")
print(f"  - {report_path}")
print(f"  - {json_path}")
print("\nTo check all generated reports, navigate to the 'reports/' directory")
