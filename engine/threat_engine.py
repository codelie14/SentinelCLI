"""
Threat Detection Engine - Calculates security score and threat level
"""

from typing import Dict, Any, List
from enum import Enum
from datetime import datetime


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatEngine:
    """Analyzes security indicators and calculates threat scores"""
    
    def __init__(self):
        self.dangerous_ports = {
            22: 'SSH',      # Brute force target
            3389: 'RDP',    # Remote access
            445: 'SMB',     # File sharing
            21: 'FTP',      # Unencrypted file transfer
            3306: 'MySQL',  # Database access
            5432: 'PostgreSQL'  # Database access
        }
        
        self.suspicious_process_keywords = [
            'psexec', 'wmic', 'powershell', 'cmd', 'net', 'reg', 'taskkill',
            'mimikatz', 'meterpreter', 'reverse', 'beacon'
        ]
        
        self.threat_weights = {
            'dangerous_port_open': 15,
            'high_privileged_process': 10,
            'suspicious_connection': 12,
            'large_data_transfer': 8,
            'failed_login_attempt': 5,
            'process_spawning': 7,
            'unusual_activity': 10
        }
    
    def calculate_security_score(self, system_data: Dict[str, Any], 
                                network_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate overall security score based on system and network data
        Score: 0-100 (100 = most secure)
        """
        
        score = 100  # Start with perfect score
        threats_detected = []
        
        # Analyze open ports
        open_ports = network_data.get('open_ports', {})
        for port in open_ports.keys():
            if port in self.dangerous_ports:
                score -= self.threat_weights['dangerous_port_open']
                threats_detected.append({
                    'type': 'DANGEROUS_PORT',
                    'port': port,
                    'service': self.dangerous_ports.get(port, 'Unknown'),
                    'severity': 'HIGH'
                })
        
        # Analyze suspicious connections
        suspicious = network_data.get('suspicious_connections', [])
        score -= len(suspicious) * self.threat_weights['suspicious_connection']
        
        for conn in suspicious:
            threats_detected.append({
                'type': 'SUSPICIOUS_CONNECTION',
                'remote_addr': conn.get('remote_addr'),
                'remote_port': conn.get('remote_port'),
                'severity': 'MEDIUM'
            })
        
        # Analyze memory usage
        memory_percent = system_data.get('ram_percent', 0)
        if memory_percent > 90:
            score -= 10
            threats_detected.append({
                'type': 'HIGH_MEMORY_USAGE',
                'usage': memory_percent,
                'severity': 'MEDIUM'
            })
        
        # Analyze CPU usage
        cpu_percent = system_data.get('cpu_percent', 0)
        if cpu_percent > 80:
            score -= 5
            threats_detected.append({
                'type': 'HIGH_CPU_USAGE',
                'usage': cpu_percent,
                'severity': 'LOW'
            })
        
        # Ensure score stays within bounds
        score = max(0, min(100, score))
        
        return {
            'security_score': score,
            'threat_level': self._get_threat_level(score),
            'threats_detected': threats_detected,
            'total_threats': len(threats_detected),
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_threat_level(self, score: int) -> str:
        """Convert security score to threat level"""
        if score >= 75:
            return ThreatLevel.LOW.value
        elif score >= 50:
            return ThreatLevel.MEDIUM.value
        elif score >= 25:
            return ThreatLevel.HIGH.value
        else:
            return ThreatLevel.CRITICAL.value
    
    def analyze_process_risk(self, processes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze processes for suspicious behavior"""
        
        risky_processes = []
        
        for proc in processes:
            proc_name = proc.get('name', '').lower()
            risk_score = 0
            risk_factors = []
            
            # Check for suspicious keywords
            for keyword in self.suspicious_process_keywords:
                if keyword in proc_name:
                    risk_score += 20
                    risk_factors.append(f"Suspicious keyword: {keyword}")
            
            # Check for system processes with unusual behavior
            if proc_name in ['system', 'svchost', 'services']:
                memory = proc.get('memory_percent', 0)
                if memory > 50:
                    risk_score += 15
                    risk_factors.append("Unusual memory usage for system process")
            
            if risk_score > 0:
                risky_processes.append({
                    'pid': proc.get('pid'),
                    'name': proc.get('name'),
                    'risk_score': min(100, risk_score),
                    'risk_factors': risk_factors,
                    'memory_percent': proc.get('memory_percent'),
                    'cpu_percent': proc.get('cpu_percent')
                })
        
        return {
            'risky_processes': risky_processes,
            'risk_count': len(risky_processes),
            'timestamp': datetime.now().isoformat()
        }
    
    def generate_recommendations(self, threat_analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on threats"""
        
        recommendations = []
        threats = threat_analysis.get('threats_detected', [])
        
        if not threats:
            recommendations.append("✓ Your system appears secure. Continue monitoring regularly.")
            return recommendations
        
        # Analyze threat types and generate specific recommendations
        threat_types = {threat['type'] for threat in threats}
        
        if 'DANGEROUS_PORT_OPEN' in threat_types:
            recommendations.append("🔒 Close unnecessary open ports or restrict access with a firewall")
        
        if 'SUSPICIOUS_CONNECTION' in threat_types:
            recommendations.append("⚠️  Investigate suspicious remote connections")
        
        if 'HIGH_MEMORY_USAGE' in threat_types:
            recommendations.append("💾 Check for memory leaks or malicious processes")
        
        if 'HIGH_CPU_USAGE' in threat_types:
            recommendations.append("⚡ Monitor CPU usage - may indicate malware or resource hogging")
        
        # General recommendations
        recommendations.extend([
            "🔄 Keep your system and software up to date",
            "🛡️  Run regular antivirus/anti-malware scans",
            "🔐 Use strong, unique passwords",
            "📊 Monitor logs regularly for suspicious activity"
        ])
        
        return recommendations
