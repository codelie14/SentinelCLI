"""
Network Monitoring Module - Analyzes network activity and connections
"""

import psutil
import socket
from typing import Dict, List, Any
from datetime import datetime


class NetworkMonitor:
    """Monitor network activity, connections, and open ports"""
    
    def __init__(self):
        self.known_ports = {
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS',
            3389: 'RDP',
            445: 'SMB',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB',
            6379: 'Redis',
            21: 'FTP',
            25: 'SMTP',
            53: 'DNS',
            123: 'NTP'
        }
    
    def get_network_interfaces(self) -> Dict[str, Any]:
        """Get network interfaces information"""
        try:
            interfaces = {}
            for iface_name, iface_addrs in psutil.net_if_addrs().items():
                interfaces[iface_name] = []
                for addr in iface_addrs:
                    interfaces[iface_name].append({
                        'family': addr.family.name,
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
            
            return {
                'interfaces': interfaces,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_network_stats(self) -> Dict[str, Any]:
        """Get network statistics"""
        try:
            stats = psutil.net_if_stats()
            iface_stats = {}
            
            for iface_name, iface_info in stats.items():
                iface_stats[iface_name] = {
                    'isup': iface_info.isup,
                    'duplex': iface_info.duplex.name if iface_info.duplex else None,
                    'speed': iface_info.speed,
                    'mtu': iface_info.mtu,
                    'bytes_sent': iface_info.bytes_sent,
                    'bytes_recv': iface_info.bytes_recv,
                    'packets_sent': iface_info.packets_sent,
                    'packets_recv': iface_info.packets_recv,
                    'errin': iface_info.errin,
                    'errout': iface_info.errout,
                    'dropin': iface_info.dropin,
                    'dropout': iface_info.dropout
                }
            
            return {
                'interfaces': iface_stats,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_open_ports(self, scan_common: bool = True) -> Dict[str, Any]:
        """Get list of open ports and listening services"""
        try:
            connections = psutil.net_connections()
            open_ports = {}
            
            for conn in connections:
                if conn.status == 'LISTEN' and conn.laddr.port > 0:
                    port = conn.laddr.port
                    if port not in open_ports:
                        service_name = self.known_ports.get(port, 'Unknown')
                        open_ports[port] = {
                            'service': service_name,
                            'address': conn.laddr.ip,
                            'status': conn.status,
                            'type': conn.type.name
                        }
            
            return {
                'open_ports': open_ports,
                'port_count': len(open_ports),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_connections(self, limit: int = 20) -> Dict[str, Any]:
        """Get active network connections"""
        try:
            connections = psutil.net_connections()
            active_connections = []
            
            for conn in connections:
                if conn.status in ['ESTABLISHED', 'LISTEN', 'TIME_WAIT']:
                    active_connections.append({
                        'local_addr': conn.laddr.ip if conn.laddr else None,
                        'local_port': conn.laddr.port if conn.laddr else None,
                        'remote_addr': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'status': conn.status,
                        'type': conn.type.name,
                        'pid': conn.pid
                    })
            
            return {
                'connections': active_connections[:limit],
                'total_connections': len(active_connections),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_suspicious_connections(self) -> Dict[str, Any]:
        """Detect potentially suspicious connections"""
        try:
            suspicious = []
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Check for suspicious indicators
                    is_suspicious = False
                    reasons = []
                    
                    # Unusual ports
                    if conn.raddr.port and conn.raddr.port > 49152:  # Ephemeral port range
                        is_suspicious = True
                        reasons.append(f"High port number: {conn.raddr.port}")
                    
                    # Port associated with common malware
                    malware_ports = [4444, 5555, 6666, 7777, 8888, 9999]
                    if conn.raddr.port in malware_ports:
                        is_suspicious = True
                        reasons.append(f"Known malware port: {conn.raddr.port}")
                    
                    if is_suspicious:
                        suspicious.append({
                            'remote_addr': conn.raddr.ip,
                            'remote_port': conn.raddr.port,
                            'local_port': conn.laddr.port if conn.laddr else None,
                            'type': conn.type.name,
                            'pid': conn.pid,
                            'reasons': reasons
                        })
            
            return {
                'suspicious_connections': suspicious,
                'count': len(suspicious),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
