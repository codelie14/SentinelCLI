"""
Advanced Logging & Alerting Module - Structured logging and alert system
"""

import json
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path


class AdvancedLogger:
    """Advanced logging with structured data and alerts"""
    
    def __init__(self, logs_dir: str = 'logs'):
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(exist_ok=True)
        
        # Log files
        self.event_log = self.logs_dir / 'events.jsonl'
        self.alert_log = self.logs_dir / 'alerts.jsonl'
        self.security_log = self.logs_dir / 'security.jsonl'
        self.summary_log = self.logs_dir / 'summary.log'
        
        # Initialize statistics
        self.statistics = {
            'total_events': 0,
            'total_alerts': 0,
            'total_security_events': 0,
            'start_time': datetime.now().isoformat()
        }
    
    def log_event(self, event_type: str, category: str, 
                 details: Dict[str, Any], severity: str = 'INFO') -> None:
        """Log a generic event"""
        
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'category': category,
            'severity': severity,
            'details': details
        }
        
        # Append to JSONL file
        with open(self.event_log, 'a') as f:
            f.write(json.dumps(event) + '\n')
        
        self.statistics['total_events'] += 1
    
    def log_alert(self, alert_type: str, title: str, 
                 description: str, severity: str = 'MEDIUM',
                 remediation: str = None) -> None:
        """Log a security alert"""
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'title': title,
            'description': description,
            'severity': severity,
            'remediation': remediation,
            'acknowledged': False
        }
        
        # Append to alert log
        with open(self.alert_log, 'a') as f:
            f.write(json.dumps(alert) + '\n')
        
        self.statistics['total_alerts'] += 1
    
    def log_security_event(self, event_name: str, source: str,
                          data: Dict[str, Any], risk_level: str = 'MEDIUM') -> None:
        """Log security-related event"""
        
        sec_event = {
            'timestamp': datetime.now().isoformat(),
            'event': event_name,
            'source': source,
            'risk_level': risk_level,
            'data': data
        }
        
        with open(self.security_log, 'a') as f:
            f.write(json.dumps(sec_event) + '\n')
        
        self.statistics['total_security_events'] += 1
    
    def get_recent_alerts(self, count: int = 10, 
                         severity_filter: str = None) -> List[Dict[str, Any]]:
        """Retrieve recent alerts"""
        
        alerts = []
        
        try:
            with open(self.alert_log, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        if severity_filter is None or alert.get('severity') == severity_filter:
                            alerts.append(alert)
        except FileNotFoundError:
            return []
        
        # Return most recent
        return alerts[-count:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get logging statistics"""
        
        return {
            **self.statistics,
            'uptime_start': self.statistics['start_time']
        }
    
    def generate_summary_report(self) -> str:
        """Generate summary log report"""
        
        report_lines = []
        report_lines.append("=" * 70)
        report_lines.append("SENTINEL CLI - LOGGING & ALERT SUMMARY")
        report_lines.append("=" * 70)
        report_lines.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Session Start: {self.statistics['start_time']}")
        report_lines.append("")
        
        # Statistics
        report_lines.append("STATISTICS:")
        report_lines.append(f"  Total Events: {self.statistics['total_events']}")
        report_lines.append(f"  Total Alerts: {self.statistics['total_alerts']}")
        report_lines.append(f"  Security Events: {self.statistics['total_security_events']}")
        report_lines.append("")
        
        # Recent Alerts
        recent_alerts = self.get_recent_alerts(5)
        if recent_alerts:
            report_lines.append("RECENT ALERTS:")
            for alert in recent_alerts:
                report_lines.append(f"\n  [{alert.get('severity')}] {alert.get('title')}")
                report_lines.append(f"  Description: {alert.get('description')}")
                if alert.get('remediation'):
                    report_lines.append(f"  Remediation: {alert.get('remediation')}")
        else:
            report_lines.append("Recent Alerts: None")
        
        report_lines.append("\n" + "=" * 70)
        
        return "\n".join(report_lines)


class AlertSystem:
    """Real-time alert system"""
    
    def __init__(self, logger: AdvancedLogger = None):
        self.logger = logger
        self.alerts = []
        self.thresholds = {
            'cpu_critical': 90,
            'cpu_warning': 75,
            'memory_critical': 95,
            'memory_warning': 85,
            'disk_critical': 95,
            'connection_threshold': 100,
            'suspicious_process_threshold': 5
        }
    
    def check_system_health(self, cpu: float, memory: float, disk: float) -> List[Dict[str, Any]]:
        """Check system health and generate alerts"""
        
        alerts = []
        
        # CPU checks
        if cpu >= self.thresholds['cpu_critical']:
            alerts.append({
                'type': 'CRITICAL_CPU',
                'title': 'Critical CPU Usage',
                'description': f'CPU usage is at {cpu:.1f}%',
                'severity': 'CRITICAL',
                'remediation': 'Stop unnecessary applications. Check for resource-hungry processes.'
            })
        elif cpu >= self.thresholds['cpu_warning']:
            alerts.append({
                'type': 'HIGH_CPU',
                'title': 'High CPU Usage',
                'description': f'CPU usage is at {cpu:.1f}%',
                'severity': 'HIGH',
                'remediation': 'Monitor CPU usage. Consider restarting services if needed.'
            })
        
        # Memory checks
        if memory >= self.thresholds['memory_critical']:
            alerts.append({
                'type': 'CRITICAL_MEMORY',
                'title': 'Critical Memory Usage',
                'description': f'Memory usage is at {memory:.1f}%',
                'severity': 'CRITICAL',
                'remediation': 'Free up memory immediately. Consider adding more RAM.'
            })
        elif memory >= self.thresholds['memory_warning']:
            alerts.append({
                'type': 'HIGH_MEMORY',
                'title': 'High Memory Usage',
                'description': f'Memory usage is at {memory:.1f}%',
                'severity': 'HIGH',
                'remediation': 'Monitor memory usage. Close unnecessary applications.'
            })
        
        # Disk checks
        if disk >= self.thresholds['disk_critical']:
            alerts.append({
                'type': 'DISK_FULL',
                'title': 'Disk Nearly Full',
                'description': f'Disk usage is at {disk:.1f}%',
                'severity': 'HIGH',
                'remediation': 'Delete unnecessary files or expand disk space.'
            })
        
        # Log alerts if logger is available
        if self.logger:
            for alert in alerts:
                self.logger.log_alert(
                    alert_type=alert['type'],
                    title=alert['title'],
                    description=alert['description'],
                    severity=alert['severity'],
                    remediation=alert.get('remediation')
                )
        
        return alerts
    
    def check_security_threats(self, threat_count: int) -> List[Dict[str, Any]]:
        """Generate alerts based on threat count"""
        
        alerts = []
        
        if threat_count >= 10:
            alerts.append({
                'type': 'CRITICAL_THREATS',
                'title': 'Multiple Threats Detected',
                'description': f'{threat_count} security threats detected on system',
                'severity': 'CRITICAL',
                'remediation': 'Run full system scan. Review all detected threats.'
            })
        elif threat_count >= 5:
            alerts.append({
                'type': 'SECURITY_THREATS',
                'title': 'Security Threats Detected',
                'description': f'{threat_count} security threats detected on system',
                'severity': 'HIGH',
                'remediation': 'Review threats and take appropriate action.'
            })
        
        if self.logger:
            for alert in alerts:
                self.logger.log_alert(
                    alert_type=alert['type'],
                    title=alert['title'],
                    description=alert['description'],
                    severity=alert['severity'],
                    remediation=alert.get('remediation')
                )
        
        return alerts
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active alerts"""
        
        if self.logger:
            return self.logger.get_recent_alerts(count=50)
        return []
