"""
File Scanner - Local malware detection via hashing and extension analysis
"""

import os
import hashlib
import stat
import platform
from datetime import datetime
from typing import Dict, Any, List, Optional


SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".psd1",
    ".dll", ".sys", ".drv", ".ocx", ".cpl", ".hta",
}

SAFE_DIRS = {
    "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
    "/usr/bin", "/bin", "/sbin", "/usr/sbin",
}

# Known malicious hashes (MD5) - small sample for demonstration
KNOWN_BAD_HASHES: set = set()


class FileScanner:
    """Scans directories for suspicious or malicious files"""

    def __init__(self):
        self.scan_results: List[Dict] = []

    # ------------------------------------------------------------------ #
    #  Hashing helpers                                                     #
    # ------------------------------------------------------------------ #

    def hash_file(self, filepath: str) -> Optional[Dict[str, str]]:
        """Return MD5 + SHA256 hashes of a file"""
        hashes = {"md5": None, "sha256": None}
        try:
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            hashes["md5"] = md5.hexdigest()
            hashes["sha256"] = sha256.hexdigest()
        except (PermissionError, OSError):
            pass
        return hashes

    # ------------------------------------------------------------------ #
    #  Detection strategies                                                #
    # ------------------------------------------------------------------ #

    def _is_suspicious_location(self, filepath: str) -> bool:
        """True if the file is in a location where executables are unusual"""
        normalized = os.path.normcase(filepath)
        for safe in SAFE_DIRS:
            if normalized.startswith(os.path.normcase(safe)):
                return False
        # Files in user dirs (Downloads, Desktop, Temp, AppData)
        suspicious_locations = [
            "downloads", "desktop", "temp", "tmp", "appdata", "roaming"
        ]
        return any(loc in normalized.lower() for loc in suspicious_locations)

    def _is_hidden(self, filepath: str) -> bool:
        """Check if file is hidden (Windows hidden attribute or Unix dot-file)"""
        try:
            if platform.system() == "Windows":
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
                return bool(attrs & 2)  # FILE_ATTRIBUTE_HIDDEN = 0x2
            else:
                return os.path.basename(filepath).startswith(".")
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def scan_directory(self, directory: str, max_files: int = 500) -> Dict[str, Any]:
        """
        Scan a directory recursively.
        Returns flagged files with hashes and risk reasons.
        """
        flagged: List[Dict] = []
        scanned = 0
        errors = 0

        if not os.path.isdir(directory):
            return {"error": f"Directory not found: {directory}"}

        for root, dirs, files in os.walk(directory):
            # Prune known safe system dirs
            dirs[:] = [d for d in dirs if not any(
                os.path.join(root, d).lower().startswith(s.lower())
                for s in SAFE_DIRS
            )]

            for fname in files:
                if scanned >= max_files:
                    break
                fpath = os.path.join(root, fname)
                scanned += 1
                risks: List[str] = []

                try:
                    ext = os.path.splitext(fname)[1].lower()
                    is_hidden = self._is_hidden(fpath)
                    in_bad_loc = self._is_suspicious_location(fpath)

                    if ext in SUSPICIOUS_EXTENSIONS:
                        risks.append(f"Suspicious extension: {ext}")
                    if is_hidden:
                        risks.append("Hidden file attribute")
                    if ext in SUSPICIOUS_EXTENSIONS and in_bad_loc:
                        risks.append("Executable in unusual location")

                    if risks:
                        hashes = self.hash_file(fpath)
                        is_known_bad = (
                            hashes.get("md5") in KNOWN_BAD_HASHES
                            or hashes.get("sha256") in KNOWN_BAD_HASHES
                        )
                        if is_known_bad:
                            risks.append("⚠️  KNOWN MALICIOUS HASH")

                        flagged.append({
                            "path": fpath,
                            "filename": fname,
                            "extension": ext,
                            "hidden": is_hidden,
                            "md5": hashes.get("md5"),
                            "sha256": hashes.get("sha256"),
                            "risks": risks,
                            "risk_score": len(risks) * 25 + (50 if is_known_bad else 0),
                            "known_bad": is_known_bad,
                        })
                except Exception:
                    errors += 1

        # Sort by risk score
        flagged.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "directory": directory,
            "scanned_files": scanned,
            "flagged_files": flagged,
            "flagged_count": len(flagged),
            "errors": errors,
            "timestamp": datetime.now().isoformat(),
        }

    def scan_user_directories(self) -> Dict[str, Any]:
        """Scan common user directories"""
        user_home = os.path.expanduser("~")
        targets = [
            os.path.join(user_home, d)
            for d in ["Downloads", "Desktop", "Documents", "AppData\\Local\\Temp"]
        ]
        targets = [t for t in targets if os.path.isdir(t)]

        all_flagged = []
        total_scanned = 0

        for target in targets:
            result = self.scan_directory(target, max_files=200)
            if "error" not in result:
                all_flagged.extend(result.get("flagged_files", []))
                total_scanned += result.get("scanned_files", 0)

        all_flagged.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "directories_scanned": targets,
            "total_scanned": total_scanned,
            "flagged_files": all_flagged[:50],
            "flagged_count": len(all_flagged),
            "timestamp": datetime.now().isoformat(),
        }
