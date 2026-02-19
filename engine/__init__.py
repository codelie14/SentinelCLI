"""
Engine module for SentinelCLI v1.2 - Core monitoring and analysis components
"""

from .system_monitor import SystemMonitor
from .network_monitor import NetworkMonitor
from .threat_engine import ThreatEngine
from .anomaly_detector import AnomalyDetector
from .advanced_port_scanner import AdvancedPortScanner
from .vulnerability_assessment import VulnerabilityAssessment
from .alert_system import AdvancedLogger, AlertSystem

# v1.2 — Offline features
from .baseline_manager import BaselineManager
from .file_scanner import FileScanner
from .windows_audit import WindowsAudit
from .forensic_timeline import ForensicTimeline
from .snapshot_manager import SnapshotManager

__all__ = [
    'SystemMonitor', 'NetworkMonitor', 'ThreatEngine',
    'AnomalyDetector', 'AdvancedPortScanner', 'VulnerabilityAssessment',
    'AdvancedLogger', 'AlertSystem',
    # v1.2
    'BaselineManager', 'FileScanner', 'WindowsAudit',
    'ForensicTimeline', 'SnapshotManager',
]
