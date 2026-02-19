"""
Threat Intelligence Feed - AlienVault OTX integration for IP/port IOC matching
"""

from datetime import datetime
from typing import Dict, Any, List, Optional, Set

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

import psutil

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


class ThreatIntelFeed:
    """Fetches threat intelligence from AlienVault OTX and matches local IOCs"""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._known_bad_ips: Set[str] = set()
        self._known_bad_domains: Set[str] = set()

    def _headers(self) -> Dict[str, str]:
        return {"X-OTX-API-KEY": self.api_key, "Accept": "application/json"}

    def fetch_pulses(self, limit: int = 20) -> Dict[str, Any]:
        """Fetch recent threat pulses from OTX"""
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not installed"}
        if not self.api_key:
            return {"error": "OTX API key not configured. Use: config set otx_key <key>"}

        try:
            url = f"{OTX_BASE_URL}/pulses/subscribed?limit={limit}"
            r = requests.get(url, headers=self._headers(), timeout=20)
            r.raise_for_status()
            data = r.json()
            pulses = data.get("results", [])

            ioc_ips = set()
            ioc_domains = set()

            for pulse in pulses:
                for ind in pulse.get("indicators", []):
                    itype = ind.get("type", "")
                    ival = ind.get("indicator", "")
                    if itype in ("IPv4", "IPv6"):
                        ioc_ips.add(ival)
                    elif itype in ("domain", "hostname"):
                        ioc_domains.add(ival)

            # Cache for local matching
            self._known_bad_ips.update(ioc_ips)
            self._known_bad_domains.update(ioc_domains)

            return {
                "pulse_count": len(pulses),
                "pulses": [
                    {
                        "name": p.get("name"),
                        "author": p.get("author_name"),
                        "tlp": p.get("tlp"),
                        "tags": p.get("tags", [])[:5],
                        "indicator_count": len(p.get("indicators", [])),
                        "created": p.get("created"),
                    }
                    for p in pulses
                ],
                "ioc_ips_loaded": len(ioc_ips),
                "ioc_domains_loaded": len(ioc_domains),
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {"error": str(e)}

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check a specific IP against OTX"""
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not installed"}
        if not self.api_key:
            return {"error": "OTX API key not configured"}

        # Check local cache first
        if ip in self._known_bad_ips:
            return {"ip": ip, "malicious": True, "source": "local_cache"}

        try:
            url = f"{OTX_BASE_URL}/indicators/IPv4/{ip}/general"
            r = requests.get(url, headers=self._headers(), timeout=15)
            if r.status_code == 404:
                return {"ip": ip, "malicious": False, "pulse_count": 0}
            r.raise_for_status()
            data = r.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return {
                "ip": ip,
                "malicious": pulse_count > 0,
                "pulse_count": pulse_count,
                "country": data.get("country_name"),
                "asn": data.get("asn"),
            }
        except Exception as e:
            return {"error": str(e)}

    def scan_active_connections(self) -> Dict[str, Any]:
        """Check all active remote IPs against known bad IPs"""
        remote_ips = set()
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr and conn.raddr.ip not in ("127.0.0.1", "::1", ""):
                    remote_ips.add(conn.raddr.ip)
        except (psutil.AccessDenied, PermissionError):
            pass

        matched_bad = [ip for ip in remote_ips if ip in self._known_bad_ips]

        return {
            "remote_ips_checked": len(remote_ips),
            "known_bad_ips_in_db": len(self._known_bad_ips),
            "malicious_matches": matched_bad,
            "malicious_count": len(matched_bad),
            "remote_ips": list(remote_ips),
            "timestamp": datetime.now().isoformat(),
        }
