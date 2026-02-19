"""
Geo-Intelligence - IP geolocation and country-based risk assessment
"""

import psutil
from datetime import datetime
from typing import Dict, Any, List, Set

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


DEFAULT_HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "SY", "BY", "CU"}
PRIVATE_RANGES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                  "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                  "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                  "192.168.", "127.", "169.254.", "::1", "fe80:"]


def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_RANGES)


class GeoIntelligence:
    """Geolocate IPs and flag connections from high-risk countries"""

    def __init__(self, high_risk_countries: Set[str] = None):
        self.high_risk_countries = high_risk_countries or DEFAULT_HIGH_RISK_COUNTRIES
        self._cache: Dict[str, Dict] = {}

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Lookup geolocation for a single IP using ip-api.com (free, no key needed)"""
        if not REQUESTS_AVAILABLE:
            return {"error": "requests not installed"}
        if is_private_ip(ip):
            return {"ip": ip, "private": True, "country_code": "PRIVATE"}

        if ip in self._cache:
            return self._cache[ip]

        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,query",
                timeout=10
            )
            data = r.json()
            if data.get("status") != "success":
                return {"ip": ip, "error": "Lookup failed"}

            result = {
                "ip": ip,
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
                "high_risk": data.get("countryCode") in self.high_risk_countries,
            }
            self._cache[ip] = result
            return result
        except Exception as e:
            return {"ip": ip, "error": str(e)}

    def get_risky_connections(self) -> Dict[str, Any]:
        """Scan all active connections and flag those from high-risk countries"""
        remote_ips = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr and not is_private_ip(conn.raddr.ip):
                    ip = conn.raddr.ip
                    if ip not in remote_ips:
                        remote_ips[ip] = {"ip": ip, "port": conn.raddr.port, "pid": conn.pid}
        except (psutil.AccessDenied, PermissionError):
            pass

        geolocated = []
        risky = []

        for ip, conn_info in list(remote_ips.items())[:30]:  # Limit to 30 IPs
            geo = self.lookup_ip(ip)
            entry = {**conn_info, **geo}
            geolocated.append(entry)
            if geo.get("high_risk"):
                risky.append(entry)

        return {
            "total_remote_ips": len(remote_ips),
            "geolocated": geolocated,
            "risky_connections": risky,
            "risky_count": len(risky),
            "high_risk_countries": list(self.high_risk_countries),
            "timestamp": datetime.now().isoformat(),
        }

    def geoip_batch(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Geolocate a list of IPs"""
        return [self.lookup_ip(ip) for ip in ips if not is_private_ip(ip)]
