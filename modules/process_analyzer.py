"""
Process Analyzer Module - Analyzes running processes for security threats
"""

import psutil
from typing import Dict, List, Any
from datetime import datetime


class ProcessAnalyzer:
    """Analyzes running processes for suspicious behavior and resource usage"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'cmd', 'powershell', 'psexec', 'wmic', 'net', 'reg', 'taskkill',
            'wget', 'curl', 'ftp', 'ssh', 'mimikatz', 'reverse'
        ]
        
        self.system_processes = [
            'svchost', 'system', 'services', 'winlogon', 'csrss', 'smss',
            'lsass', 'explorer', 'userinit', 'dwm'
        ]
    
    def get_all_processes(self) -> Dict[str, Any]:
        """Get list of all running processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'username': proc.info['username']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return {
                'processes': processes,
                'total_count': len(processes),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_high_resource_processes(self, cpu_threshold: float = 10.0,
                                   memory_threshold: float = 5.0) -> Dict[str, Any]:
        """Find processes consuming excessive resources"""
        
        try:
            high_resource = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    cpu = pinfo.get('cpu_percent', 0)
                    memory = pinfo.get('memory_percent', 0)
                    
                    if cpu >= cpu_threshold or memory >= memory_threshold:
                        high_resource.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'cpu_percent': round(cpu, 2),
                            'memory_percent': round(memory, 2),
                            'category': 'CPU-Heavy' if cpu >= cpu_threshold else 'Memory-Heavy'
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by resource usage
            high_resource.sort(key=lambda x: x['cpu_percent'] + x['memory_percent'],
                             reverse=True)
            
            return {
                'high_resource_processes': high_resource,
                'count': len(high_resource),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_suspicious_processes(self) -> Dict[str, Any]:
        """Identify potentially suspicious processes"""
        
        try:
            suspicious = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent']):
                try:
                    pinfo = proc.info
                    proc_name = pinfo['name'].lower() if pinfo['name'] else ''
                    cmdline = pinfo['cmdline'] if pinfo['cmdline'] else []
                    
                    is_suspicious = False
                    reasons = []
                    
                    # Check against suspicious keywords
                    for keyword in self.suspicious_keywords:
                        if keyword in proc_name:
                            is_suspicious = True
                            reasons.append(f"Suspicious process name: {keyword}")
                            break
                    
                    # Check command line arguments
                    if cmdline:
                        cmdline_str = ' '.join(cmdline).lower()
                        for keyword in ['reverse', 'shell', 'handler', 'exploit']:
                            if keyword in cmdline_str:
                                is_suspicious = True
                                reasons.append(f"Suspicious command argument: {keyword}")
                    
                    # Check for hidden process (uncommon on Windows)
                    if pinfo['name'].startswith('.'):
                        is_suspicious = True
                        reasons.append("Process name starts with dot (hidden)")
                    
                    if is_suspicious:
                        suspicious.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'cpu_percent': pinfo.get('cpu_percent', 0),
                            'reasons': reasons
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return {
                'suspicious_processes': suspicious,
                'count': len(suspicious),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_process_details(self, pid: int) -> Dict[str, Any]:
        """Get detailed information about a specific process"""
        
        try:
            proc = psutil.Process(pid)
            
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'status': proc.status(),
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'cpu_times': proc.cpu_times()._asdict(),
                'cpu_percent': proc.cpu_percent(),
                'memory_info': proc.memory_info()._asdict(),
                'memory_percent': proc.memory_percent(),
                'num_threads': proc.num_threads(),
                'connections': len(proc.connections()),
                'open_files': len(proc.open_files()),
                'exe': proc.exe(),
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else 'N/A',
                'timestamp': datetime.now().isoformat()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': str(e)}
