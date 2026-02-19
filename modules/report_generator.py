"""
Report Generator Module - Creates comprehensive security reports
"""

import json
from typing import Dict, Any, List
from datetime import datetime
import os


class ReportGenerator:
    """Generates security reports in multiple formats"""
    
    def __init__(self, reports_dir: str = 'reports'):
        self.reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)
    
    def generate_markdown_report(self, 
                                system_data: Dict[str, Any],
                                network_data: Dict[str, Any],
                                threat_analysis: Dict[str, Any],
                                recommendations: list,
                                vulnerabilities: Dict[str, Any] = None,
                                anomalies: Dict[str, Any] = None,
                                filename: str = None) -> str:
        """Generate a comprehensive markdown report"""
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"SentinelCLI_Report_{timestamp}.md"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        # Build report content
        report_content = self._build_report_markdown(
            system_data, network_data, threat_analysis, recommendations,
            vulnerabilities, anomalies
        )
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return filepath
    
    def _build_report_markdown(self,
                              system_data: Dict[str, Any],
                              network_data: Dict[str, Any],
                              threat_analysis: Dict[str, Any],
                              recommendations: list,
                              vulnerabilities: Dict[str, Any] = None,
                              anomalies: Dict[str, Any] = None) -> str:
        """Build detailed markdown report"""
        
        report = []
        report.append("# 🛡️ SentinelCLI Security Analysis Report\n")
        report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.append("**Tool:** SentinelCLI v1.0 - Cyber Defense Terminal Toolkit\n\n")
        
        # Table of Contents
        report.append("## Table of Contents\n")
        report.append("1. [Executive Summary](#executive-summary)\n")
        report.append("2. [System Information](#system-information)\n")
        report.append("3. [Security Assessment](#security-assessment)\n")
        report.append("4. [Network Analysis](#network-analysis)\n")
        report.append("5. [Vulnerability Assessment](#vulnerability-assessment)\n")
        report.append("6. [Anomaly Detection](#anomaly-detection)\n")
        report.append("7. [Recommendations](#recommendations)\n\n")
        
        # Executive Summary
        score = threat_analysis.get('security_score', 0)
        level = threat_analysis.get('threat_level', 'UNKNOWN')
        
        report.append("## Executive Summary\n")
        
        # Score visualization
        if score >= 75:
            emoji = "🟢"
        elif score >= 50:
            emoji = "🟡"
        elif score >= 25:
            emoji = "🟠"
        else:
            emoji = "🔴"
        
        report.append(f"{emoji} **Security Score:** {score}/100\n")
        report.append(f"**Threat Level:** {level}\n")
        report.append(f"**Threats Detected:** {threat_analysis.get('total_threats', 0)}\n\n")
        
        report.append(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # System Information
        report.append("## System Information\n")
        if system_data and 'error' not in system_data:
            report.append(f"| Property | Value |\n")
            report.append(f"|----------|-------|\n")
            report.append(f"| OS | {system_data.get('os')} {system_data.get('os_version')} |\n")
            report.append(f"| Hostname | {system_data.get('hostname')} |\n")
            report.append(f"| Processor | {system_data.get('processor')} |\n")
            report.append(f"| Platform | {system_data.get('platform')} |\n\n")
        
        # Hardware Resources
        report.append("## Hardware Resources\n")
        report.append("### CPU\n")
        report.append(f"- **Usage:** {system_data.get('cpu_percent', 0):.1f}%\n")
        report.append(f"- **Physical Cores:** {system_data.get('cpu_count_physical', 0)}\n")
        report.append(f"- **Logical Cores:** {system_data.get('cpu_count_logical', 0)}\n")
        report.append(f"- **Frequency:** {system_data.get('cpu_freq', 'N/A')} MHz\n\n")
        
        report.append("### Memory\n")
        ram_used = system_data.get('ram_used', 0)
        ram_total = system_data.get('ram_total', 0)
        ram_percent = system_data.get('ram_percent', 0)
        report.append(f"- **Usage:** {ram_percent:.1f}% ({self._format_bytes(ram_used)}/{self._format_bytes(ram_total)})\n")
        report.append(f"- **Swap Usage:** {system_data.get('swap_percent', 0):.1f}%\n\n")
        
        # Disk
        report.append("### Disk Space\n")
        report.append("| Device | Free | Used | Total | Usage % |\n")
        report.append("|--------|------|------|-------|----------|\n")
        
        for device, info in system_data.get('disks', {}).items():
            total = info['total'] / (1024**3)
            used = info['used'] / (1024**3)
            free = info['free'] / (1024**3)
            
            report.append(f"| {device} | {free:.2f}GB | {used:.2f}GB | {total:.2f}GB | {info['percent']:.1f}% |\n")
        
        report.append("\n")
        
        # Security Assessment
        report.append("## Security Assessment\n\n")
        report.append(f"**Overall Risk Score:** {threat_analysis.get('security_score', 0)}/100\n")
        report.append(f"**Threat Classification:** {threat_analysis.get('threat_level', 'UNKNOWN')}\n\n")
        
        # Detected Threats
        threats = threat_analysis.get('threats_detected', [])
        
        if threats:
            report.append(f"### Detected Threats ({len(threats)})\n\n")
            report.append("| Type | Severity | Details |\n")
            report.append("|------|----------|----------|\n")
            
            for threat in threats:
                threat_type = threat.get('type', 'Unknown')
                severity = threat.get('severity', 'Unknown')
                details = []
                
                if 'port' in threat:
                    details.append(f"Port: {threat.get('port')}")
                if 'remote_addr' in threat:
                    details.append(f"IP: {threat.get('remote_addr')}")
                if 'remote_port' in threat:
                    details.append(f"Remote Port: {threat.get('remote_port')}")
                
                detail_str = ', '.join(details) if details else 'N/A'
                report.append(f"| {threat_type} | {severity} | {detail_str} |\n")
        else:
            report.append("✓ **No threats detected**\n")
        
        report.append("\n")
        
        # Network Analysis
        report.append("## Network Analysis\n\n")
        
        open_ports = network_data.get('open_ports', {})
        suspicious = network_data.get('suspicious_connections', [])
        
        report.append(f"**Open Ports:** {len(open_ports)}\n")
        report.append(f"**Suspicious Connections:** {len(suspicious)}\n\n")
        
        if open_ports:
            report.append("### Open Ports\n\n")
            report.append("| Port | Service | Address | Type |\n")
            report.append("|------|---------|---------|------|\n")
            
            for port, info in sorted(open_ports.items()):
                report.append(f"| {port} | {info.get('service', 'Unknown')} | {info.get('address', 'N/A')} | {info.get('type', 'N/A')} |\n")
        
        if suspicious:
            report.append(f"\n### Suspicious Connections ({len(suspicious)})\n\n")
            report.append("| Remote IP | Remote Port | Reason |\n")
            report.append("|-----------|------------|--------|\n")
            
            for conn in suspicious:
                reasons = ', '.join(conn.get('reasons', ['Unknown']))
                report.append(f"| {conn.get('remote_addr', 'N/A')} | {conn.get('remote_port', 'N/A')} | {reasons} |\n")
        
        report.append("\n")
        
        # Vulnerability Assessment
        if vulnerabilities:
            report.append("## Vulnerability Assessment\n\n")
            report.append(f"**Total Vulnerabilities:** {vulnerabilities.get('vulnerability_count', 0)}\n\n")
            
            severity = vulnerabilities.get('severity_breakdown', {})
            report.append("### Severity Breakdown\n\n")
            report.append(f"- 🔴 **CRITICAL:** {severity.get('CRITICAL', 0)}\n")
            report.append(f"- 🟠 **HIGH:** {severity.get('HIGH', 0)}\n")
            report.append(f"- 🟡 **MEDIUM:** {severity.get('MEDIUM', 0)}\n")
            report.append(f"- 🟢 **LOW:** {severity.get('LOW', 0)}\n\n")
            
            if vulnerabilities.get('vulnerabilities'):
                report.append("### Identified Vulnerabilities\n\n")
                
                for vuln in vulnerabilities.get('vulnerabilities', []):
                    vuln_info = vuln.get('vulnerability', {})
                    report.append(f"#### {vuln_info.get('name')}\n\n")
                    report.append(f"- **CVE:** {vuln_info.get('cve')}\n")
                    report.append(f"- **Severity:** {vuln_info.get('severity')}\n")
                    report.append(f"- **Status:** {vuln.get('status')}\n")
                    report.append(f"- **Recommendation:** {vuln.get('recommendation')}\n\n")
        
        # Anomaly Detection
        if anomalies:
            report.append("## Anomaly Detection\n\n")
            report.append(f"**Total Anomalies:** {anomalies.get('count', 0)}\n\n")
            
            if anomalies.get('anomalies_detected'):
                report.append("### Detected Anomalies\n\n")
                report.append("| Type | Severity | Description |\n")
                report.append("|------|----------|-------------|\n")
                
                for anomaly in anomalies.get('anomalies_detected', [])[:10]:
                    report.append(f"| {anomaly.get('type', 'Unknown')} | {anomaly.get('severity', 'Unknown')} | {str(anomaly.get('description', 'N/A'))[:50]} |\n")
        
        # Recommendations
        report.append("## Recommendations\n\n")
        
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                report.append(f"{i}. {rec}\n")
        else:
            report.append("✓ No specific recommendations at this time.\n")
        
        # Footer
        report.append("\n---\n\n")
        report.append("*Report generated by SentinelCLI - Cyber Defense Terminal Toolkit*\n")
        report.append(f"*Report ID: {datetime.now().strftime('%Y%m%d%H%M%S')}*\n")
        report.append("*For more information, visit: https://github.com/codelie14/SentinelCLI*\n")
        
        return '\n'.join(report)
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable format"""
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024
        
        return f"{bytes_value:.2f} PB"
    
    def export_json(self, data: Dict[str, Any], filename: str = None) -> str:
        """Export comprehensive data as JSON"""
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"SentinelCLI_Data_{timestamp}.json"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        return filepath
    
    def export_csv_ports(self, open_ports: Dict[int, Any], filename: str = None) -> str:
        """Export open ports as CSV"""
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"SentinelCLI_Ports_{timestamp}.csv"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("Port,Service,Address,Type\n")
            for port, info in open_ports.items():
                f.write(f"{port},{info.get('service', 'Unknown')},{info.get('address', 'N/A')},{info.get('type', 'N/A')}\n")
        
        return filepath

