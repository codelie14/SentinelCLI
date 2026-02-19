"""
Snapshot Manager - Takes, stores, and diffs system snapshots
"""

import json
import os
import psutil
from datetime import datetime
from typing import Dict, Any, List, Optional


SNAPSHOTS_DIR = "snapshots"


class SnapshotManager:
    """Manages point-in-time system snapshots and drift comparison"""

    def __init__(self):
        os.makedirs(SNAPSHOTS_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _snapshot_data(self) -> Dict[str, Any]:
        """Collect a full system snapshot"""
        processes = []
        for p in psutil.process_iter(["pid", "name", "exe", "username", "cpu_percent", "memory_percent"]):
            try:
                processes.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        ports = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "LISTEN" and c.laddr:
                    ports.append({"port": c.laddr.port, "ip": c.laddr.ip, "pid": c.pid})
        except (psutil.AccessDenied, PermissionError):
            pass

        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()

        return {
            "processes": sorted(processes, key=lambda x: x.get("pid", 0)),
            "ports": sorted(ports, key=lambda x: x.get("port", 0)),
            "cpu_percent": cpu,
            "ram_percent": mem.percent,
            "ram_used_gb": round(mem.used / (1024 ** 3), 2),
        }

    def _snapshot_path(self, snapshot_id: str) -> str:
        return os.path.join(SNAPSHOTS_DIR, f"{snapshot_id}.json")

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def take_snapshot(self, label: str = "") -> Dict[str, Any]:
        """Take a snapshot and persist it. Returns snapshot metadata."""
        ts = datetime.now()
        snapshot_id = ts.strftime("%Y%m%d_%H%M%S")
        data = self._snapshot_data()
        snapshot = {
            "id": snapshot_id,
            "label": label or snapshot_id,
            "timestamp": ts.isoformat(),
            "data": data,
        }
        with open(self._snapshot_path(snapshot_id), "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, default=str)
        return {
            "id": snapshot_id,
            "label": label or snapshot_id,
            "timestamp": ts.isoformat(),
            "processes": len(data["processes"]),
            "ports": len(data["ports"]),
        }

    def list_snapshots(self) -> List[Dict[str, Any]]:
        """Return metadata for all saved snapshots"""
        snapshots = []
        for fname in sorted(os.listdir(SNAPSHOTS_DIR)):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(SNAPSHOTS_DIR, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    snap = json.load(f)
                snapshots.append({
                    "id": snap.get("id"),
                    "label": snap.get("label"),
                    "timestamp": snap.get("timestamp"),
                    "processes": len(snap.get("data", {}).get("processes", [])),
                    "ports": len(snap.get("data", {}).get("ports", [])),
                    "file": fpath,
                })
            except Exception:
                continue
        return snapshots

    def load_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        """Load a snapshot by ID"""
        path = self._snapshot_path(snapshot_id)
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def compare_snapshots(self, id1: str, id2: str) -> Dict[str, Any]:
        """Diff two snapshots. id2 is the 'newer' state."""
        snap1 = self.load_snapshot(id1)
        snap2 = self.load_snapshot(id2)

        if not snap1:
            return {"error": f"Snapshot not found: {id1}"}
        if not snap2:
            return {"error": f"Snapshot not found: {id2}"}

        d1 = snap1["data"]
        d2 = snap2["data"]

        # Process diff
        pids1 = {p["pid"]: p for p in d1.get("processes", [])}
        pids2 = {p["pid"]: p for p in d2.get("processes", [])}

        new_processes = [p for pid, p in pids2.items() if pid not in pids1]
        gone_processes = [p for pid, p in pids1.items() if pid not in pids2]

        # Port diff
        ports1 = {p["port"] for p in d1.get("ports", [])}
        ports2 = {p["port"] for p in d2.get("ports", [])}
        new_ports = [p for p in d2.get("ports", []) if p["port"] not in ports1]
        closed_ports = [p for p in d1.get("ports", []) if p["port"] not in ports2]

        # Resource delta
        cpu_delta = round(d2.get("cpu_percent", 0) - d1.get("cpu_percent", 0), 1)
        ram_delta = round(d2.get("ram_percent", 0) - d1.get("ram_percent", 0), 1)

        total_changes = len(new_processes) + len(gone_processes) + len(new_ports) + len(closed_ports)
        risk_score = min(100, len(new_processes) * 5 + len(new_ports) * 10)

        return {
            "snapshot_1": {"id": id1, "label": snap1.get("label"), "timestamp": snap1.get("timestamp")},
            "snapshot_2": {"id": id2, "label": snap2.get("label"), "timestamp": snap2.get("timestamp")},
            "diff": {
                "new_processes": new_processes,
                "gone_processes": gone_processes,
                "new_ports": new_ports,
                "closed_ports": closed_ports,
                "cpu_delta_percent": cpu_delta,
                "ram_delta_percent": ram_delta,
            },
            "total_changes": total_changes,
            "risk_score": risk_score,
            "timestamp": datetime.now().isoformat(),
        }

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a snapshot by ID"""
        path = self._snapshot_path(snapshot_id)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False
