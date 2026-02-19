"""
Report Generator Module - Creates comprehensive security reports
"""

import json
from typing import Dict, Any
from datetime import datetime
import os


class ReportGenerator:
    """Generates security reports in Markdown format"""
    
    def __init__(self, reports_dir: str = 'reports'):
        self.reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)
    
    def generate_markdown_report(self, 
                                system_data: Dict[str, Any],
                                network_data: Dict[str, Any],
                                threat_analysis: Dict[str, Any],
                                recommendations: list,
                                filename: str = None) -> str:
        """Generate a comprehensive markdown report"""
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"SentinelCLI_Report_{timestamp}.md"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        # Build report content
        report_content = self._build_report_markdown(
            system_data, network_data, threat_analysis, recommendations
        )
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return filepath
    
    def _build_report_markdown(self,
                              system_data: Dict[str, Any],
                              network_data: Dict[str, Any],
                              threat_analysis: Dict[str, Any],
                              recommendations: list) -> str:
        """Build markdown report content"""
        
        report = []
        report.append("# 🛡️ SentinelCLI Security Report\n")
        report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Executive Summary
        score = threat_analysis.get('security_score', 0)
        level = threat_analysis.get('threat_level', 'UNKNOWN')
        
        report.append("## Executive Summary\n")
        report.append(f"- **Security Score:** {score}/100\n")
        report.append(f"- **Threat Level:** {level}\n")
        report.append(f"- **Threats Detected:** {threat_analysis.get('total_threats', 0)}\n\n")
        
        # System Information
        report.append("## System Information\n")
        if system_data and 'error' not in system_data:
            report.append(f"- **OS:** {system_data.get('os')}\n")
            report.append(f"- **Version:** {system_data.get('os_version')}\n")
            report.append(f"- **Hostname:** {system_data.get('hostname')}\n")
            report.append(f"- **Processor:** {system_data.get('processor')}\n\n")
        
        # Hardware Usage
        report.append("## Hardware Resources\n")
        report.append("### CPU\n")
        report.append(f"- **Usage:** {system_data.get('cpu_percent', 0):.1f}%\n")
        report.append(f"- **Physical Cores:** {system_data.get('cpu_count_physical', 0)}\n")
        report.append(f"- **Logical Cores:** {system_data.get('cpu_count_logical', 0)}\n\n")
        
        report.append("### Memory\n")
        ram_used = system_data.get('ram_used', 0)
        ram_total = system_data.get('ram_total', 0)
        ram_percent = system_data.get('ram_percent', 0)
        report.append(f"- **Usage:** {ram_percent:.1f}% ({self._format_bytes(ram_used)}/{self._format_bytes(ram_total)})\n\n")
        
        # Network Information
        report.append("## Network Status\n")
        report.append("### Open Ports\n")
        
        open_ports = network_data.get('open_ports', {})
        if open_ports:
            for port, info in sorted(open_ports.items()):
                report.append(f"- **Port {port}** ({info.get('service')}) - {info.get('address')}\n")
        else:
            report.append("- No open ports detected\n")
        
        report.append("\n### Network Connections\n")
        suspicious = network_data.get('suspicious_connections', [])
        
        if suspicious:
            report.append(f"⚠️ **{len(suspicious)} suspicious connection(s) detected:**\n\n")
            for conn in suspicious:
                report.append(f"- **{conn.get('remote_addr')}:{conn.get('remote_port')}**\n")
                for reason in conn.get('reasons', []):
                    report.append(f"  - {reason}\n")
        else:
            report.append("✓ No suspicious connections detected\n")
        
        report.append("\n")
        
        # Threat Analysis
        report.append("## Threat Analysis\n")
        threats = threat_analysis.get('threats_detected', [])
        
        if threats:
            report.append(f"### Detected Threats ({len(threats)})\n\n")
            for threat in threats:
                report.append(f"- **{threat.get('type')}** [{threat.get('severity', 'UNKNOWN')}]\n")
                report.append(f"  - Details: {threat}\n\n")
        else:
            report.append("✓ No threats detected\n\n")
        
        # Recommendations
        report.append("## Recommendations\n\n")
        for i, rec in enumerate(recommendations, 1):
            report.append(f"{i}. {rec}\n")
        
        report.append("\n---\n")
        report.append(f"*Report generated by SentinelCLI v1.0 on {datetime.now().isoformat()}*\n")
        
        return '\n'.join(report)
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable format"""
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024
        
        return f"{bytes_value:.2f} PB"
    
    def export_json(self, data: Dict[str, Any], filename: str = None) -> str:
        """Export data as JSON"""
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"SentinelCLI_Data_{timestamp}.json"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        return filepath
