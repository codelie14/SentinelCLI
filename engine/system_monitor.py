"""
System Monitoring Module - Gathers system information and metrics
"""

import psutil
import platform
from typing import Dict, List, Any
from datetime import datetime


class SystemMonitor:
    """Monitor system information: OS, CPU, RAM, disk, users, startup programs"""
    
    def __init__(self):
        self.last_update = None
        
    def get_system_info(self) -> Dict[str, Any]:
        """Get basic system information"""
        try:
            return {
                'os': platform.system(),
                'os_version': platform.release(),
                'hostname': platform.node(),
                'platform': platform.platform(),
                'processor': platform.processor(),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information and usage"""
        try:
            return {
                'cpu_count_physical': psutil.cpu_count(logical=False),
                'cpu_count_logical': psutil.cpu_count(logical=True),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'cpu_freq': psutil.cpu_freq().current if psutil.cpu_freq() else None,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_memory_info(self) -> Dict[str, Any]:
        """Get memory (RAM) information"""
        try:
            virtual_memory = psutil.virtual_memory()
            swap_memory = psutil.swap_memory()
            
            return {
                'ram_total': virtual_memory.total,
                'ram_available': virtual_memory.available,
                'ram_used': virtual_memory.used,
                'ram_percent': virtual_memory.percent,
                'swap_total': swap_memory.total,
                'swap_used': swap_memory.used,
                'swap_percent': swap_memory.percent,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_disk_info(self) -> Dict[str, Any]:
        """Get disk space information"""
        try:
            disks = {}
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks[partition.device] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent,
                        'mountpoint': partition.mountpoint
                    }
                except PermissionError:
                    continue
            
            return {
                'disks': disks,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_connected_users(self) -> Dict[str, Any]:
        """Get list of connected users"""
        try:
            users = psutil.users()
            user_list = [
                {
                    'name': user.name,
                    'terminal': user.terminal,
                    'host': user.host,
                    'started': datetime.fromtimestamp(user.started).isoformat()
                }
                for user in users
            ]
            
            return {
                'users': user_list,
                'count': len(user_list),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_processes(self, limit: int = 50) -> Dict[str, Any]:
        """Get list of running processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    processes.append(pinfo)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by memory usage and return top N
            processes.sort(key=lambda x: x.get('memory_percent', 0), reverse=True)
            
            return {
                'processes': processes[:limit],
                'total_processes': len(processes),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_boot_time(self) -> Dict[str, Any]:
        """Get system boot time"""
        try:
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            
            return {
                'boot_time': boot_time.isoformat(),
                'uptime_seconds': int(uptime.total_seconds()),
                'uptime_formatted': str(uptime),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
