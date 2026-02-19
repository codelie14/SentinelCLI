"""
Forensic Timeline - Records and queries system events with temporal correlation
"""

import json
import os
import threading
import time
import psutil
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional


TIMELINE_FILE = "logs/timeline.json"
MAX_EVENTS = 10000  # Cap to prevent unbounded growth


class ForensicTimeline:
    """Records system events and provides forensic timeline queries"""

    def __init__(self):
        os.makedirs("logs", exist_ok=True)
        self._events: List[Dict] = []
        self._lock = threading.Lock()
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitoring = False
        self._load_timeline()

    # ------------------------------------------------------------------ #
    #  Persistence                                                         #
    # ------------------------------------------------------------------ #

    def _load_timeline(self):
        if os.path.exists(TIMELINE_FILE):
            try:
                with open(TIMELINE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._events = data.get("events", [])[-MAX_EVENTS:]
            except Exception:
                self._events = []

    def _save_timeline(self):
        with open(TIMELINE_FILE, "w", encoding="utf-8") as f:
            json.dump({"events": self._events[-MAX_EVENTS:]}, f, indent=2, default=str)

    # ------------------------------------------------------------------ #
    #  Event recording                                                     #
    # ------------------------------------------------------------------ #

    def record_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        severity: str = "INFO",
    ) -> Dict[str, Any]:
        """Add a timestamped event to the timeline"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "details": details,
        }
        with self._lock:
            self._events.append(event)
            self._save_timeline()
        return event

    # ------------------------------------------------------------------ #
    #  Monitoring (background thread)                                      #
    # ------------------------------------------------------------------ #

    def _monitor_loop(self, interval: int):
        """Background monitoring loop"""
        prev_procs = {p.pid for p in psutil.process_iter()}
        prev_ports = set()
        try:
            prev_ports = {
                c.laddr.port
                for c in psutil.net_connections(kind="inet")
                if c.status == "LISTEN" and c.laddr
            }
        except (psutil.AccessDenied, PermissionError):
            pass

        while self._monitoring:
            try:
                # Detect new/ended processes
                curr_procs = {}
                for p in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        curr_procs[p.pid] = p.info
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                new_pids = set(curr_procs.keys()) - prev_procs
                gone_pids = prev_procs - set(curr_procs.keys())

                for pid in new_pids:
                    proc = curr_procs[pid]
                    self.record_event("PROCESS_STARTED", {
                        "pid": pid,
                        "name": proc.get("name"),
                        "exe": proc.get("exe"),
                    }, severity="INFO")

                for pid in gone_pids:
                    self.record_event("PROCESS_ENDED", {
                        "pid": pid,
                    }, severity="INFO")

                prev_procs = set(curr_procs.keys())

                # Detect new/closed listening ports
                curr_ports = set()
                try:
                    curr_ports = {
                        c.laddr.port
                        for c in psutil.net_connections(kind="inet")
                        if c.status == "LISTEN" and c.laddr
                    }
                except (psutil.AccessDenied, PermissionError):
                    pass

                for port in curr_ports - prev_ports:
                    self.record_event("PORT_OPENED", {"port": port}, severity="WARNING")
                for port in prev_ports - curr_ports:
                    self.record_event("PORT_CLOSED", {"port": port}, severity="INFO")
                prev_ports = curr_ports

            except Exception:
                pass

            time.sleep(interval)

    def start_monitoring(self, interval: int = 30):
        """Start background event recording"""
        if self._monitoring:
            return
        self._monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, args=(interval,), daemon=True
        )
        self._monitor_thread.start()
        self.record_event("MONITOR_STARTED", {"interval_seconds": interval}, severity="INFO")

    def stop_monitoring(self):
        """Stop background monitoring"""
        self._monitoring = False
        self.record_event("MONITOR_STOPPED", {}, severity="INFO")

    # ------------------------------------------------------------------ #
    #  Queries                                                             #
    # ------------------------------------------------------------------ #

    def get_timeline(self, hours: int = 24, event_type: Optional[str] = None) -> Dict[str, Any]:
        """Return events within the last N hours, optionally filtered by type"""
        cutoff = datetime.now() - timedelta(hours=hours)
        with self._lock:
            events = [
                e for e in self._events
                if datetime.fromisoformat(e["timestamp"]) >= cutoff
                and (event_type is None or e["event_type"] == event_type)
            ]

        severity_counts = {}
        type_counts = {}
        for e in events:
            sev = e.get("severity", "INFO")
            etype = e.get("event_type", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            type_counts[etype] = type_counts.get(etype, 0) + 1

        return {
            "hours_window": hours,
            "total_events": len(events),
            "events": events[-200:],  # Return last 200 for display
            "severity_breakdown": severity_counts,
            "event_type_counts": type_counts,
            "monitoring_active": self._monitoring,
            "timestamp": datetime.now().isoformat(),
        }

    def clear_timeline(self):
        """Clear all recorded events"""
        with self._lock:
            self._events = []
            self._save_timeline()
