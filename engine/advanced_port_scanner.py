"""
Advanced Port Scanner - Detailed port analysis and vulnerability detection
"""

from typing import Dict, List, Any
from datetime import datetime


class AdvancedPortScanner:
    """Advanced port scanning and service detection"""
    
    def __init__(self):
        # Comprehensive port database
        self.port_database = {
            # Web Services
            80: {'name': 'HTTP', 'service': 'Web Server', 'risk': 'MEDIUM', 'category': 'Web'},
            443: {'name': 'HTTPS', 'service': 'Secure Web', 'risk': 'LOW', 'category': 'Web'},
            
            # Remote Access
            22: {'name': 'SSH', 'service': 'Secure Shell', 'risk': 'MEDIUM', 'category': 'Remote'},
            3389: {'name': 'RDP', 'service': 'Remote Desktop', 'risk': 'HIGH', 'category': 'Remote'},
            5900: {'name': 'VNC', 'service': 'Virtual Network', 'risk': 'MEDIUM', 'category': 'Remote'},
            
            # File Services
            21: {'name': 'FTP', 'service': 'File Transfer', 'risk': 'HIGH', 'category': 'File'},
            445: {'name': 'SMB', 'service': 'File Sharing', 'risk': 'HIGH', 'category': 'File'},
            139: {'name': 'NetBIOS', 'service': 'Windows Sharing', 'risk': 'HIGH', 'category': 'File'},
            
            # Database Services
            3306: {'name': 'MySQL', 'service': 'Database', 'risk': 'HIGH', 'category': 'Database'},
            5432: {'name': 'PostgreSQL', 'service': 'Database', 'risk': 'HIGH', 'category': 'Database'},
            1433: {'name': 'MSSQL', 'service': 'Database', 'risk': 'HIGH', 'category': 'Database'},
            27017: {'name': 'MongoDB', 'service': 'NoSQL Database', 'risk': 'HIGH', 'category': 'Database'},
            6379: {'name': 'Redis', 'service': 'Cache DB', 'risk': 'HIGH', 'category': 'Database'},
            
            # Mail Services
            25: {'name': 'SMTP', 'service': 'Email', 'risk': 'MEDIUM', 'category': 'Mail'},
            110: {'name': 'POP3', 'service': 'Email', 'risk': 'MEDIUM', 'category': 'Mail'},
            143: {'name': 'IMAP', 'service': 'Email', 'risk': 'MEDIUM', 'category': 'Mail'},
            
            # DNS and Network
            53: {'name': 'DNS', 'service': 'Domain Name', 'risk': 'MEDIUM', 'category': 'Network'},
            67: {'name': 'DHCP', 'service': 'DHCP Server', 'risk': 'MEDIUM', 'category': 'Network'},
            
            # VPN and Proxy
            1194: {'name': 'OpenVPN', 'service': 'VPN', 'risk': 'LOW', 'category': 'VPN'},
            8080: {'name': 'HTTP-Alt', 'service': 'Proxy', 'risk': 'MEDIUM', 'category': 'Proxy'},
            
            # Monitoring Services
            161: {'name': 'SNMP', 'service': 'Monitoring', 'risk': 'MEDIUM', 'category': 'Monitor'},
        }
        
        # Known exploitable port ranges
        self.exploitable_ranges = [
            (1024, 65535),  # Ephemeral ports (less controlled)
            (8000, 9000),   # Development/testing
        ]
    
    def analyze_open_ports(self, open_ports: Dict[int, Dict[str, Any]]) -> Dict[str, Any]:
        """Perform detailed analysis of open ports"""
        
        analysis = {
            'critical_ports': [],
            'high_risk_ports': [],
            'medium_risk_ports': [],
            'low_risk_ports': [],
            'unknown_ports': [],
            'port_categories': {},
            'total_risk_score': 0,
            'recommendations': []
        }
        
        for port, info in open_ports.items():
            port_info = self.port_database.get(port)
            
            if port_info:
                risk_level = port_info['risk']
                category = port_info['category']
                
                # Categorize by risk
                port_detail = {
                    'port': port,
                    'service': port_info['service'],
                    'name': port_info['name'],
                    'risk': risk_level,
                    'address': info.get('address', 'Unknown')
                }
                
                if risk_level == 'HIGH':
                    analysis['high_risk_ports'].append(port_detail)
                    analysis['total_risk_score'] += 20
                elif risk_level == 'MEDIUM':
                    analysis['medium_risk_ports'].append(port_detail)
                    analysis['total_risk_score'] += 10
                elif risk_level == 'LOW':
                    analysis['low_risk_ports'].append(port_detail)
                    analysis['total_risk_score'] += 5
                
                # Count by category
                if category not in analysis['port_categories']:
                    analysis['port_categories'][category] = 0
                analysis['port_categories'][category] += 1
                
            else:
                # Unknown port
                analysis['unknown_ports'].append({
                    'port': port,
                    'address': info.get('address', 'Unknown'),
                    'type': info.get('type', 'Unknown')
                })
                analysis['total_risk_score'] += 5  # Unknown = potentially risky
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return {
            'port_analysis': analysis,
            'total_open_ports': len(open_ports),
            'risk_score': min(100, analysis['total_risk_score']),
            'timestamp': datetime.now().isoformat()
        }
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on port analysis"""
        
        recommendations = []
        
        if analysis['high_risk_ports']:
            recommendations.append(
                f"🔴 {len(analysis['high_risk_ports'])} high-risk port(s) open. Consider closing or restricting access:"
            )
            for port_info in analysis['high_risk_ports']:
                recommendations.append(
                    f"   - Port {port_info['port']} ({port_info['service']}): Restrict with firewall"
                )
        
        if analysis['unknown_ports']:
            recommendations.append(
                f"⚠️  {len(analysis['unknown_ports'])} unknown port(s) detected. Investigate these services."
            )
        
        if 'File' in analysis['port_categories']:
            recommendations.append(
                "📁 File sharing services detected. Ensure proper authentication and access controls."
            )
        
        if 'Database' in analysis['port_categories']:
            recommendations.append(
                "🗄️  Database ports exposed. Should only be accessible internally via VPN."
            )
        
        if not recommendations:
            recommendations.append("✓ No critical port exposure detected.")
        
        return recommendations
    
    def get_port_details(self, port: int) -> Dict[str, Any]:
        """Get detailed information about a specific port"""
        
        info = self.port_database.get(port, {})
        
        if not info:
            return {
                'port': port,
                'status': 'Unknown',
                'risk': 'UNKNOWN',
                'warning': 'Port not in standard database'
            }
        
        return {
            'port': port,
            'name': info['name'],
            'service': info['service'],
            'category': info['category'],
            'risk_level': info['risk'],
            'details': self._get_security_details(info)
        }
    
    def _get_security_details(self, port_info: Dict[str, Any]) -> str:
        """Get security details for a port"""
        
        service = port_info.get('service', 'Unknown')
        risk = port_info.get('risk', 'UNKNOWN')
        
        details = {
            'HIGH': f"{service} - This service has known vulnerabilities. Restrict access immediately.",
            'MEDIUM': f"{service} - Monitor this service for suspicious activity.",
            'LOW': f"{service} - Generally safe but ensure it's properly secured."
        }
        
        return details.get(risk, "Unknown security level.")
    
    def detect_port_anomalies(self, current_ports: Dict[int, Any],
                             previous_ports: Dict[int, Any] = None) -> Dict[str, Any]:
        """Detect new or unexpected port changes"""
        
        anomalies = {
            'new_ports': [],
            'closed_ports': [],
            'port_changes': []
        }
        
        if previous_ports:
            # Find new ports
            new = set(current_ports.keys()) - set(previous_ports.keys())
            for port in new:
                anomalies['new_ports'].append({
                    'port': port,
                    'service': self.port_database.get(port, {}).get('name', 'Unknown'),
                    'severity': 'MEDIUM'
                })
            
            # Find closed ports
            closed = set(previous_ports.keys()) - set(current_ports.keys())
            for port in closed:
                anomalies['closed_ports'].append({
                    'port': port,
                    'service': self.port_database.get(port, {}).get('name', 'Unknown')
                })
        
        return {
            'anomalies': anomalies,
            'anomaly_count': sum(len(v) if isinstance(v, list) else 0 
                                for v in anomalies.values()),
            'timestamp': datetime.now().isoformat()
        }
