"""
VirusTotal Integration - Check process/file hashes against VirusTotal API v3
"""

import hashlib
import os
import psutil
from datetime import datetime
from typing import Dict, Any, List, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalChecker:
    """Checks hashes against VirusTotal's public API"""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def check_hash(self, hash_value: str) -> Dict[str, Any]:
        """Query VirusTotal for a given MD5/SHA256 hash"""
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not installed. Run: pip install requests"}
        if not self.api_key:
            return {"error": "VirusTotal API key not configured. Use: config set virustotal_key <key>"}

        try:
            url = f"{VT_BASE_URL}/files/{hash_value}"
            r = requests.get(url, headers=self._headers(), timeout=15)
            if r.status_code == 404:
                return {
                    "hash": hash_value,
                    "found": False,
                    "message": "Hash not found in VirusTotal database",
                }
            if r.status_code == 401:
                return {"error": "Invalid VirusTotal API key"}
            if r.status_code == 429:
                return {"error": "VirusTotal rate limit exceeded (free tier: 4 lookups/min)"}

            r.raise_for_status()
            data = r.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            return {
                "hash": hash_value,
                "found": True,
                "name": attrs.get("meaningful_name", "Unknown"),
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total,
                "detection_ratio": f"{malicious}/{total}",
                "is_malicious": malicious > 0,
                "verdict": (
                    "MALICIOUS" if malicious > 3 else
                    "SUSPICIOUS" if malicious > 0 or suspicious > 3 else
                    "CLEAN"
                ),
                "last_analysis_date": attrs.get("last_analysis_date"),
            }
        except Exception as e:
            return {"error": str(e)}

    def _get_process_hash(self, exe_path: str) -> Optional[str]:
        """Compute SHA256 of a process executable"""
        try:
            sha256 = hashlib.sha256()
            with open(exe_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (PermissionError, OSError, FileNotFoundError):
            return None

    def check_running_processes(self, max_processes: int = 30) -> Dict[str, Any]:
        """Check hashes of running processes against VirusTotal"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}

        results = []
        seen_hashes = set()
        checked = 0

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            if checked >= max_processes:
                break
            try:
                exe = proc.info.get("exe")
                if not exe or not os.path.isfile(exe):
                    continue
                h = self._get_process_hash(exe)
                if not h or h in seen_hashes:
                    continue
                seen_hashes.add(h)
                checked += 1

                vt_result = self.check_hash(h)
                results.append({
                    "pid": proc.info.get("pid"),
                    "name": proc.info.get("name"),
                    "exe": exe,
                    "sha256": h,
                    "vt": vt_result,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        malicious = [r for r in results if r["vt"].get("is_malicious")]
        suspicious = [r for r in results if r["vt"].get("verdict") == "SUSPICIOUS"]

        return {
            "checked_processes": checked,
            "results": results,
            "malicious": malicious,
            "suspicious": suspicious,
            "malicious_count": len(malicious),
            "timestamp": datetime.now().isoformat(),
        }
