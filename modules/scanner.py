"""
Network Scanner Module - Detects active devices on local network
"""

import socket
import subprocess
import platform
from typing import Dict, List, Any
from datetime import datetime


class NetworkScanner:
    """Scans local network for active devices"""
    
    def __init__(self):
        self.os_type = platform.system()
    
    def get_local_ip(self) -> str:
        """Get local machine IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def get_subnet(self) -> str:
        """Calculate subnet from local IP"""
        try:
            ip = self.get_local_ip()
            parts = ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "192.168.1.0/24"
    
    def ping_host(self, ip: str) -> bool:
        """Test if a host is reachable"""
        try:
            if self.os_type == 'Windows':
                result = subprocess.run(['ping', '-n', '1', '-w', '500', ip],
                                      capture_output=True, timeout=2)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '500', ip],
                                      capture_output=True, timeout=2)
            
            return result.returncode == 0
        except Exception:
            return False
    
    def scan_network(self, subnet: str = None, timeout: int = 5000) -> Dict[str, Any]:
        """Scan local network for active hosts"""
        
        if subnet is None:
            subnet = self.get_subnet()
        
        active_hosts = []
        
        try:
            # Parse subnet
            base_ip = subnet.split('/')[0].rsplit('.', 1)[0]
            
            for i in range(1, 255):
                ip = f"{base_ip}.{i}"
                if self.ping_host(ip):
                    # Try to resolve hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        hostname = "Unknown"
                    
                    active_hosts.append({
                        'ip': ip,
                        'hostname': hostname,
                        'reachable': True,
                        'timestamp': datetime.now().isoformat()
                    })
        
        except Exception as e:
            return {
                'error': str(e),
                'active_hosts': [],
                'timestamp': datetime.now().isoformat()
            }
        
        return {
            'subnet': subnet,
            'active_hosts': active_hosts,
            'host_count': len(active_hosts),
            'timestamp': datetime.now().isoformat()
        }
    
    def get_dns_info(self, hostname: str) -> Dict[str, Any]:
        """Get DNS information for a hostname"""
        try:
            ip = socket.gethostbyname(hostname)
            all_ips = socket.gethostbyname_ex(hostname)[2]
            
            return {
                'hostname': hostname,
                'primary_ip': ip,
                'all_ips': all_ips,
                'timestamp': datetime.now().isoformat()
            }
        except socket.gaierror:
            return {
                'hostname': hostname,
                'error': 'Hostname not found',
                'timestamp': datetime.now().isoformat()
            }
