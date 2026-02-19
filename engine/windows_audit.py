"""
Windows Security Audit - Scheduled tasks, registry run keys, network shares
"""

import platform
import subprocess
import os
from datetime import datetime
from typing import Dict, Any, List


IS_WINDOWS = platform.system() == "Windows"


class WindowsAudit:
    """Performs Windows-specific security audit checks"""

    def __init__(self):
        self.is_windows = IS_WINDOWS

    # ------------------------------------------------------------------ #
    #  Scheduled Tasks                                                     #
    # ------------------------------------------------------------------ #

    def audit_scheduled_tasks(self) -> Dict[str, Any]:
        """List all scheduled tasks; flag suspicious ones"""
        if not self.is_windows:
            return {"error": "Windows only", "tasks": [], "suspicious": []}

        tasks = []
        suspicious = []

        suspicious_keywords = [
            "powershell", "cmd", "wscript", "cscript", "mshta",
            "rundll32", "regsvr32", "certutil", "bitsadmin",
        ]

        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, timeout=20,
                encoding="utf-8", errors="ignore"
            )
            lines = result.stdout.splitlines()
            if len(lines) > 1:
                header = [h.strip('"') for h in lines[0].split(",")]
                for line in lines[1:]:
                    if not line.strip():
                        continue
                    parts = [p.strip('"') for p in line.split(",")]
                    if len(parts) < len(header):
                        continue
                    task = dict(zip(header, parts))
                    task_name = task.get("TaskName", "")
                    task_run = task.get("Task To Run", "").lower()
                    task_status = task.get("Status", "")

                    tasks.append({
                        "name": task_name,
                        "run": task.get("Task To Run", ""),
                        "status": task_status,
                        "next_run": task.get("Next Run Time", "N/A"),
                    })

                    # Detect suspicious tasks
                    risk_reasons = []
                    for kw in suspicious_keywords:
                        if kw in task_run:
                            risk_reasons.append(f"Runs: {kw}")
                    if risk_reasons:
                        suspicious.append({
                            "name": task_name,
                            "run": task.get("Task To Run", ""),
                            "reasons": risk_reasons,
                        })
        except Exception as e:
            return {"error": str(e), "tasks": [], "suspicious": []}

        return {
            "total_tasks": len(tasks),
            "tasks": tasks[:50],
            "suspicious": suspicious,
            "suspicious_count": len(suspicious),
            "timestamp": datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------ #
    #  Registry Run Keys                                                   #
    # ------------------------------------------------------------------ #

    def audit_registry_run_keys(self) -> Dict[str, Any]:
        """Read HKLM and HKCU Run/RunOnce keys"""
        if not self.is_windows:
            return {"error": "Windows only", "entries": [], "suspicious": []}

        import winreg

        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
        ]

        entries = []
        suspicious = []

        suspicious_indicators = [
            "temp\\", "tmp\\", "appdata\\roaming\\", "%temp%", "%tmp%",
            "powershell", "cmd.exe /c", "wscript", "cscript", "mshta",
        ]

        for hive, key_path, friendly_name in run_keys:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        entry = {
                            "key": friendly_name,
                            "name": name,
                            "value": value,
                        }
                        entries.append(entry)

                        val_lower = value.lower()
                        reasons = [
                            ind for ind in suspicious_indicators
                            if ind in val_lower
                        ]
                        if reasons:
                            suspicious.append({**entry, "reasons": reasons})

                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                continue

        return {
            "total_entries": len(entries),
            "entries": entries,
            "suspicious": suspicious,
            "suspicious_count": len(suspicious),
            "timestamp": datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------ #
    #  Network Shares                                                      #
    # ------------------------------------------------------------------ #

    def audit_network_shares(self) -> Dict[str, Any]:
        """List all network shares on the system"""
        shares = []
        suspicious = []

        if self.is_windows:
            try:
                result = subprocess.run(
                    ["net", "share"],
                    capture_output=True, text=True, timeout=10,
                    encoding="utf-8", errors="ignore"
                )
                lines = result.stdout.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or "---" in line or "Share name" in line or "completed" in line:
                        continue
                    parts = line.split()
                    if parts:
                        share_name = parts[0]
                        resource = parts[1] if len(parts) > 1 else "N/A"
                        remark = " ".join(parts[2:]) if len(parts) > 2 else ""
                        share = {
                            "name": share_name,
                            "resource": resource,
                            "remark": remark,
                        }
                        shares.append(share)
                        # Flag non-default shares as potentially suspicious
                        default_shares = {"ADMIN$", "C$", "D$", "IPC$", "SYSVOL", "NETLOGON"}
                        if share_name not in default_shares:
                            suspicious.append({
                                **share, "reason": "Non-default network share"
                            })
            except Exception as e:
                return {"error": str(e), "shares": [], "suspicious": []}
        else:
            # Linux: check /etc/exports or samba
            try:
                if os.path.exists("/etc/exports"):
                    with open("/etc/exports") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                shares.append({"name": line, "resource": "NFS", "remark": ""})
            except Exception:
                pass

        return {
            "total_shares": len(shares),
            "shares": shares,
            "suspicious": suspicious,
            "suspicious_count": len(suspicious),
            "timestamp": datetime.now().isoformat(),
        }

    def full_audit(self) -> Dict[str, Any]:
        """Run all audit checks and combine results"""
        tasks = self.audit_scheduled_tasks()
        registry = self.audit_registry_run_keys()
        shares = self.audit_network_shares()

        total_suspicious = (
            tasks.get("suspicious_count", 0)
            + registry.get("suspicious_count", 0)
            + shares.get("suspicious_count", 0)
        )

        return {
            "scheduled_tasks": tasks,
            "registry_run_keys": registry,
            "network_shares": shares,
            "total_suspicious_items": total_suspicious,
            "risk_level": (
                "CRITICAL" if total_suspicious >= 5 else
                "HIGH" if total_suspicious >= 3 else
                "MEDIUM" if total_suspicious >= 1 else
                "LOW"
            ),
            "timestamp": datetime.now().isoformat(),
        }
