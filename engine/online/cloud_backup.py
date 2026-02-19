"""
Cloud Backup - Upload security reports to remote HTTP/S3 endpoints
"""

import os
from datetime import datetime
from typing import Dict, Any, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class CloudBackup:
    """Uploads security reports to a configurable HTTP endpoint"""

    def __init__(self, endpoint_url: str = ""):
        self.endpoint_url = endpoint_url

    def upload_report(self, filepath: str, endpoint_url: str = None) -> Dict[str, Any]:
        """Upload a report file to the configured endpoint via HTTP POST"""
        if not REQUESTS_AVAILABLE:
            return {"error": "requests not installed"}

        url = endpoint_url or self.endpoint_url
        if not url:
            return {"error": "Cloud backup endpoint not configured. Use: config set cloud_endpoint <url>"}
        if not os.path.isfile(filepath):
            return {"error": f"File not found: {filepath}"}

        try:
            filename = os.path.basename(filepath)
            with open(filepath, "rb") as f:
                files = {"file": (filename, f, "text/markdown")}
                data = {
                    "source": "SentinelCLI-v1.2",
                    "timestamp": datetime.now().isoformat(),
                }
                r = requests.post(url, files=files, data=data, timeout=60)

            return {
                "success": r.status_code in (200, 201),
                "status_code": r.status_code,
                "filename": filename,
                "url": url,
                "response": r.text[:200] if r.text else "",
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {"error": str(e)}

    def upload_all_reports(self, reports_dir: str = "reports") -> Dict[str, Any]:
        """Upload all reports in the reports directory"""
        results = []
        if not os.path.isdir(reports_dir):
            return {"error": f"Reports directory not found: {reports_dir}"}

        for fname in sorted(os.listdir(reports_dir)):
            if fname.endswith((".md", ".json", ".enc")):
                fpath = os.path.join(reports_dir, fname)
                result = self.upload_report(fpath)
                results.append({"file": fname, **result})

        return {
            "total_uploaded": sum(1 for r in results if r.get("success")),
            "total_files": len(results),
            "results": results,
            "timestamp": datetime.now().isoformat(),
        }
