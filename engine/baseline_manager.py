"""
Baseline Manager - Creates system baselines and detects drift
"""

import json
import os
import hashlib
import psutil
import platform
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional


BASELINES_DIR = "baselines"


class BaselineManager:
    """Creates and compares system baselines for intrusion detection"""

    def __init__(self):
        os.makedirs(BASELINES_DIR, exist_ok=True)
        self.baseline_file = os.path.join(BASELINES_DIR, "baseline.json")

    # ------------------------------------------------------------------ #
    #  Snapshot helpers                                                    #
    # ------------------------------------------------------------------ #

    def _snapshot_processes(self) -> List[Dict]:
        procs = []
        for p in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(procs, key=lambda x: x.get("pid", 0))

    def _snapshot_ports(self) -> List[Dict]:
        ports = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" and conn.laddr:
                    ports.append({
                        "port": conn.laddr.port,
                        "ip": conn.laddr.ip,
                        "pid": conn.pid,
                    })
        except (psutil.AccessDenied, PermissionError):
            pass
        return sorted(ports, key=lambda x: x.get("port", 0))

    def _snapshot_users(self) -> List[Dict]:
        users = []
        for u in psutil.users():
            users.append({
                "name": u.name,
                "terminal": u.terminal,
                "host": u.host,
            })
        return users

    def _snapshot_scheduled_tasks(self) -> List[str]:
        """List scheduled task names (Windows only)"""
        tasks = []
        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ["schtasks", "/query", "/fo", "LIST"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    if line.startswith("TaskName:"):
                        tasks.append(line.split(":", 1)[1].strip())
            except Exception:
                pass
        return tasks

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def create_baseline(self) -> Dict[str, Any]:
        """Save a fresh system baseline to disk"""
        baseline = {
            "timestamp": datetime.now().isoformat(),
            "os": platform.platform(),
            "hostname": platform.node(),
            "processes": self._snapshot_processes(),
            "ports": self._snapshot_ports(),
            "users": self._snapshot_users(),
            "scheduled_tasks": self._snapshot_scheduled_tasks(),
        }
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2, default=str)
        return baseline

    def load_baseline(self) -> Optional[Dict[str, Any]]:
        """Load the stored baseline, or None if not found"""
        if not os.path.exists(self.baseline_file):
            return None
        with open(self.baseline_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def compare_baseline(self) -> Dict[str, Any]:
        """Compare current state against the stored baseline"""
        baseline = self.load_baseline()
        if not baseline:
            return {"error": "No baseline found. Run 'baseline create' first."}

        current = {
            "processes": self._snapshot_processes(),
            "ports": self._snapshot_ports(),
            "users": self._snapshot_users(),
            "scheduled_tasks": self._snapshot_scheduled_tasks(),
        }

        changes = {}

        # --- Processes ---
        base_pids = {p["pid"]: p for p in baseline["processes"]}
        curr_pids = {p["pid"]: p for p in current["processes"]}
        new_procs = [
            p for pid, p in curr_pids.items() if pid not in base_pids
        ]
        gone_procs = [
            p for pid, p in base_pids.items() if pid not in curr_pids
        ]
        changes["new_processes"] = new_procs
        changes["gone_processes"] = gone_procs

        # --- Ports ---
        base_ports = {p["port"] for p in baseline["ports"]}
        curr_ports = {p["port"] for p in current["ports"]}
        changes["new_ports"] = [
            p for p in current["ports"] if p["port"] not in base_ports
        ]
        changes["closed_ports"] = [
            p for p in baseline["ports"] if p["port"] not in curr_ports
        ]

        # --- Users ---
        base_users = {u["name"] for u in baseline["users"]}
        curr_users = {u["name"] for u in current["users"]}
        changes["new_users"] = [
            u for u in current["users"] if u["name"] not in base_users
        ]
        changes["gone_users"] = [
            u for u in baseline["users"] if u["name"] not in curr_users
        ]

        # --- Scheduled Tasks ---
        base_tasks = set(baseline.get("scheduled_tasks", []))
        curr_tasks = set(current["scheduled_tasks"])
        changes["new_tasks"] = list(curr_tasks - base_tasks)
        changes["removed_tasks"] = list(base_tasks - curr_tasks)

        # --- Risk score ---
        risk = (
            len(new_procs) * 5
            + len(changes["new_ports"]) * 10
            + len(changes["new_users"]) * 20
            + len(changes["new_tasks"]) * 15
        )

        return {
            "baseline_timestamp": baseline["timestamp"],
            "compare_timestamp": datetime.now().isoformat(),
            "changes": changes,
            "total_changes": sum(len(v) for v in changes.values()),
            "risk_score": min(100, risk),
        }
