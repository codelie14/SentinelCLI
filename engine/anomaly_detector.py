"""
Anomaly Detection Module - Advanced threat detection and pattern analysis
"""

from typing import Dict, List, Any
from datetime import datetime
import json


class AnomalyDetector:
    """Detects anomalous behavior in system and network"""
    
    def __init__(self):
        self.baseline = {}
        self.anomalies = []
        
        # Known legitimate processes
        self.trusted_processes = {
            'svchost', 'services', 'lsass', 'csrss', 'winlogon',
            'explorer', 'dwm', 'System', 'Registry', 'smss'
        }
        
        # Risk keywords in process names
        self.risk_keywords = {
            'psexec': 'Lateral movement tool',
            'mimikatz': 'Credential theft',
            'meterpreter': 'Metasploit payload',
            'reverse': 'Reverse shell',
            'backdoor': 'Backdoor',
            'trojan': 'Trojan',
            'ransomware': 'File encryption',
            'worm': 'Self-propagating malware',
            'cryptominer': 'Unauthorized mining',
            'bot': 'Botnet activity'
        }
    
    def detect_process_anomalies(self, processes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect anomalous processes"""
        
        anomalies = []
        risk_score = 0
        
        for proc in processes:
            name = proc.get('name', '').lower()
            pid = proc.get('pid', 0)
            memory = proc.get('memory_percent', 0)
            cpu = proc.get('cpu_percent', 0)
            
            # Check risk keywords
            for keyword, description in self.risk_keywords.items():
                if keyword in name:
                    anomalies.append({
                        'type': 'RISKY_PROCESS',
                        'pid': pid,
                        'process': name,
                        'risk': description,
                        'severity': 'HIGH',
                        'timestamp': datetime.now().isoformat()
                    })
                    risk_score += 25
            
            # Check for unusual system process behavior
            if any(sys_proc in name for sys_proc in self.trusted_processes):
                if memory > 30 or cpu > 50:
                    anomalies.append({
                        'type': 'UNUSUAL_SYSTEM_PROCESS',
                        'pid': pid,
                        'process': name,
                        'memory': memory,
                        'cpu': cpu,
                        'severity': 'MEDIUM',
                        'timestamp': datetime.now().isoformat()
                    })
                    risk_score += 15
            
            # Check for processes with no name (potential rootkit)
            if not name or name.strip() == '':
                anomalies.append({
                    'type': 'UNNAMED_PROCESS',
                    'pid': pid,
                    'severity': 'CRITICAL',
                    'timestamp': datetime.now().isoformat()
                })
                risk_score += 50
        
        return {
            'anomalies_detected': anomalies,
            'count': len(anomalies),
            'risk_score': min(100, risk_score),
            'timestamp': datetime.now().isoformat()
        }
    
    def detect_network_anomalies(self, connections: List[Dict[str, Any]],
                                 suspicious_threshold: int = 50) -> Dict[str, Any]:
        """Detect anomalous network patterns"""
        
        anomalies = []
        
        # Count connections per remote IP
        ip_connections = {}
        for conn in connections:
            remote_ip = conn.get('remote_addr', 'Unknown')
            if remote_ip:
                ip_connections[remote_ip] = ip_connections.get(remote_ip, 0) + 1
        
        # Identify IPs with too many connections
        for ip, count in ip_connections.items():
            if count > suspicious_threshold:
                anomalies.append({
                    'type': 'EXCESSIVE_CONNECTIONS',
                    'remote_ip': ip,
                    'connection_count': count,
                    'severity': 'HIGH',
                    'description': f'IP has {count} connections (threshold: {suspicious_threshold})',
                    'timestamp': datetime.now().isoformat()
                })
        
        # Detect port scanning patterns
        ports_per_ip = {}
        for conn in connections:
            remote_ip = conn.get('remote_addr', 'Unknown')
            remote_port = conn.get('remote_port', 0)
            
            if remote_ip:
                if remote_ip not in ports_per_ip:
                    ports_per_ip[remote_ip] = []
                ports_per_ip[remote_ip].append(remote_port)
        
        for ip, ports in ports_per_ip.items():
            if len(set(ports)) >= 10:  # Many different ports to same IP
                anomalies.append({
                    'type': 'PORT_SCANNING',
                    'remote_ip': ip,
                    'unique_ports': len(set(ports)),
                    'severity': 'HIGH',
                    'description': f'Connecting to {len(set(ports))} different ports on {ip}',
                    'timestamp': datetime.now().isoformat()
                })
        
        return {
            'network_anomalies': anomalies,
            'count': len(anomalies),
            'timestamp': datetime.now().isoformat()
        }
    
    def detect_resource_anomalies(self, cpu_percent: float, 
                                  memory_percent: float,
                                  disk_percent: float) -> Dict[str, Any]:
        """Detect resource usage anomalies"""
        
        anomalies = []
        risk_level = 'LOW'
        
        # CPU anomalies
        if cpu_percent > 90:
            anomalies.append({
                'type': 'CRITICAL_CPU_USAGE',
                'value': cpu_percent,
                'severity': 'CRITICAL',
                'description': f'CPU usage at {cpu_percent:.1f}%'
            })
            risk_level = 'CRITICAL'
        elif cpu_percent > 75:
            anomalies.append({
                'type': 'HIGH_CPU_USAGE',
                'value': cpu_percent,
                'severity': 'HIGH',
                'description': f'CPU usage at {cpu_percent:.1f}%'
            })
            risk_level = 'HIGH'
        
        # Memory anomalies
        if memory_percent > 95:
            anomalies.append({
                'type': 'CRITICAL_MEMORY_USAGE',
                'value': memory_percent,
                'severity': 'CRITICAL',
                'description': f'Memory usage at {memory_percent:.1f}%'
            })
            risk_level = 'CRITICAL'
        elif memory_percent > 85:
            anomalies.append({
                'type': 'HIGH_MEMORY_USAGE',
                'value': memory_percent,
                'severity': 'HIGH',
                'description': f'Memory usage at {memory_percent:.1f}%'
            })
            if risk_level != 'CRITICAL':
                risk_level = 'HIGH'
        
        # Disk anomalies
        if disk_percent > 95:
            anomalies.append({
                'type': 'DISK_ALMOST_FULL',
                'value': disk_percent,
                'severity': 'HIGH',
                'description': f'Disk usage at {disk_percent:.1f}%'
            })
        
        return {
            'resource_anomalies': anomalies,
            'count': len(anomalies),
            'overall_risk': risk_level,
            'timestamp': datetime.now().isoformat()
        }
