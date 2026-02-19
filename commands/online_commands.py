"""
Online commands: vtcheck, intel, geoip, api, notify, backup
All require mode == online.
"""
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from engine.online.virustotal import VirusTotalChecker
from engine.online.threat_intel import ThreatIntelFeed
from engine.online.geo_intel import GeoIntelligence
from engine.online.notifier import Notifier
from engine.online.cloud_backup import CloudBackup
from engine.online.rest_api import RestAPI


class OnlineCommands:
    def __init__(self, config):
        self.config = config
        self.console = Console()
        self._vt: VirusTotalChecker = None
        self._intel: ThreatIntelFeed = None
        self._geo: GeoIntelligence = None
        self._notifier: Notifier = None
        self._backup: CloudBackup = None
        self._api: RestAPI = None

    # ── Lazy-loaded clients ──────────────────────────────────────────
    def _get_vt(self):
        if not self._vt:
            self._vt = VirusTotalChecker(self.config.get("api_keys", "virustotal") or "")
        return self._vt

    def _get_intel(self):
        if not self._intel:
            self._intel = ThreatIntelFeed(self.config.get("api_keys", "otx") or "")
        return self._intel

    def _get_geo(self):
        if not self._geo:
            cc = self.config.get("geo_intel", "high_risk_countries") or []
            self._geo = GeoIntelligence(set(cc) if cc else None)
        return self._geo

    def _get_notifier(self):
        n = self.config.get("notifications", default={})
        return Notifier(
            slack_webhook=n.get("slack_webhook", ""),
            discord_webhook=n.get("discord_webhook", ""),
            smtp_host=n.get("smtp_host", ""),
            smtp_port=n.get("smtp_port", 587),
            smtp_user=n.get("smtp_user", ""),
            smtp_password=n.get("smtp_password", ""),
            email_to=n.get("email_to", ""),
            threshold=self.config.get("notifications_threshold") or "HIGH",
        )

    def _get_api(self):
        if not self._api:
            self._api = RestAPI(
                host=self.config.get("rest_api", "host") or "127.0.0.1",
                port=int(self.config.get("rest_api", "port") or 5000),
            )
        return self._api

    def _get_backup(self):
        return CloudBackup(self.config.get("cloud_backup", "endpoint_url") or "")

    # ── VIRUSTOTAL ───────────────────────────────────────────────────
    def cmd_vtcheck(self, args):
        """vtcheck [hash]  — check a hash or scan running processes"""
        vt = self._get_vt()

        if args and args.strip():
            h = args.strip()
            with Progress(SpinnerColumn(), TextColumn("[green]Querying VirusTotal..."), transient=True) as p:
                task = p.add_task("", total=None)
                result = vt.check_hash(h)
                p.stop_task(task)

            if "error" in result:
                self.console.print(f"[red]{result['error']}[/red]\n")
                return
            if not result.get("found"):
                self.console.print(f"[yellow]Hash not found in VirusTotal database[/yellow]\n")
                return

            verdict = result.get("verdict", "UNKNOWN")
            color = {"CLEAN": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "red"}.get(verdict, "white")
            self.console.print(Panel(
                f"[bold {color}]{verdict}[/bold {color}]\n"
                f"Detections: {result['detection_ratio']} engines\n"
                f"Name: {result.get('name', 'Unknown')}",
                title=f"VirusTotal: {h[:20]}...", border_style=color
            ))
        else:
            self.console.print("[cyan]🔍 Checking running process hashes against VirusTotal...[/cyan]")
            self.console.print("[dim](This may take time — free API: 4 lookups/min)[/dim]\n")
            with Progress(SpinnerColumn(), TextColumn("[green]{task.description}"), transient=True) as p:
                task = p.add_task("Scanning processes...", total=None)
                result = vt.check_running_processes(max_processes=10)
                p.stop_task(task)

            if "error" in result:
                self.console.print(f"[red]{result['error']}[/red]\n")
                return

            self.console.print(f"Checked: {result['checked_processes']} | Malicious: {result['malicious_count']}\n")
            malicious = result.get("malicious", [])
            if malicious:
                t = Table(title="⚠️  Malicious Process Detections", style="red")
                t.add_column("PID"); t.add_column("Name"); t.add_column("Ratio")
                for m in malicious:
                    t.add_row(str(m["pid"]), m["name"], m["vt"].get("detection_ratio", "?"))
                self.console.print(t)
            else:
                self.console.print("[green]✓ No malicious processes detected[/green]")
            self.console.print()

    # ── THREAT INTEL ─────────────────────────────────────────────────
    def cmd_intel(self, args):
        """intel fetch | scan  — OTX threat intelligence"""
        intel = self._get_intel()
        sub = (args or "fetch").strip().lower()

        if sub == "fetch":
            with Progress(SpinnerColumn(), TextColumn("[cyan]Fetching OTX threat pulses..."), transient=True) as p:
                t = p.add_task("", total=None)
                result = intel.fetch_pulses()
                p.stop_task(t)

            if "error" in result:
                self.console.print(f"[red]{result['error']}[/red]\n")
                return

            self.console.print(Panel(
                f"Pulses: {result['pulse_count']} | IPs loaded: {result['ioc_ips_loaded']} | Domains: {result['ioc_domains_loaded']}",
                title="AlienVault OTX Threat Intelligence", border_style="cyan"
            ))
            t2 = Table()
            t2.add_column("Pulse Name", style="cyan", max_width=40)
            t2.add_column("Author", style="green")
            t2.add_column("IOCs", style="yellow")
            t2.add_column("TLP", style="magenta")
            for pulse in result.get("pulses", [])[:15]:
                t2.add_row(pulse.get("name", "")[:40], pulse.get("author", ""),
                           str(pulse.get("indicator_count", 0)), pulse.get("tlp") or "green")
            self.console.print(t2)
            self.console.print()

        elif sub == "scan":
            result = intel.scan_active_connections()
            self.console.print(Panel(
                f"IPs checked: {result['remote_ips_checked']} | IOC DB size: {result['known_bad_ips_in_db']}\n"
                f"Matches: [bold red]{result['malicious_count']}[/bold red]",
                title="Active Connection IOC Scan", border_style="cyan"
            ))
            if result["malicious_matches"]:
                t = Table(title="⚠️  Malicious IPs Detected")
                t.add_column("IP", style="red")
                for ip in result["malicious_matches"]:
                    t.add_row(ip)
                self.console.print(t)
            else:
                self.console.print("[green]✓ No connections match known malicious IPs[/green]")
            self.console.print()
        else:
            self.console.print("[dim]Usage: intel <fetch|scan>[/dim]\n")

    # ── GEOIP ────────────────────────────────────────────────────────
    def cmd_geoip(self, args):
        """geoip [ip]  — geolocate an IP or scan all active connections"""
        geo = self._get_geo()
        if args and args.strip():
            ip = args.strip()
            result = geo.lookup_ip(ip)
            color = "red" if result.get("high_risk") else "green"
            self.console.print(Panel(
                f"Country: [{color}]{result.get('country', 'Unknown')} ({result.get('country_code', '?')})[/{color}]\n"
                f"City: {result.get('city', '?')} | ISP: {result.get('isp', '?')}\n"
                f"ASN: {result.get('asn', '?')} | High-Risk: [bold {color}]{result.get('high_risk', False)}[/bold {color}]",
                title=f"GeoIP: {ip}", border_style=color
            ))
        else:
            with Progress(SpinnerColumn(), TextColumn("[cyan]Geolocating active connections..."), transient=True) as p:
                t = p.add_task("", total=None)
                result = geo.get_risky_connections()
                p.stop_task(t)

            self.console.print(Panel(
                f"Remote IPs: {result['total_remote_ips']} | Geolocated: {len(result['geolocated'])} | "
                f"Risky: [bold red]{result['risky_count']}[/bold red]",
                title="Geo-Intelligence Scan", border_style="cyan"
            ))
            if result["geolocated"]:
                t2 = Table()
                t2.add_column("IP", style="cyan")
                t2.add_column("Country", style="green")
                t2.add_column("ISP", style="dim", max_width=30)
                t2.add_column("⚠️ Risk", style="red")
                for conn in result["geolocated"][:20]:
                    risk = "HIGH RISK" if conn.get("high_risk") else ""
                    t2.add_row(conn.get("ip", ""), conn.get("country", "Unknown"),
                               conn.get("isp", "?")[:30], risk)
                self.console.print(t2)
            self.console.print()

    # ── NOTIFY ───────────────────────────────────────────────────────
    def cmd_notify(self, args):
        """notify test | <level> <message>"""
        notifier = self._get_notifier()
        parts = (args or "").strip().split(maxsplit=2)
        sub = parts[0].lower() if parts else "test"

        if sub == "test":
            result = notifier.test_all_channels()
            self._display_notify_result(result)
        elif sub in ("info", "low", "medium", "high", "critical") and len(parts) >= 2:
            msg = " ".join(parts[1:])
            result = notifier.notify_threat(sub.upper(), "SentinelCLI Alert", msg)
            self._display_notify_result(result)
        else:
            self.console.print("[dim]Usage:\n  notify test\n  notify <info|low|medium|high|critical> <message>[/dim]\n")

    def _display_notify_result(self, result):
        if result.get("skipped"):
            self.console.print(f"[yellow]Notification skipped: {result['reason']}[/yellow]\n")
            return
        channels = result.get("channels_notified", [])
        if not channels:
            self.console.print("[yellow]No notification channels configured. Use 'config set slack_webhook/discord_webhook/smtp_host'[/yellow]\n")
            return
        for ch, res in result.get("results", {}).items():
            if res.get("success"):
                self.console.print(f"[green]✓ {ch} notification sent[/green]")
            else:
                self.console.print(f"[red]✗ {ch}: {res.get('error', 'Failed')}[/red]")
        self.console.print()

    # ── REST API ─────────────────────────────────────────────────────
    def cmd_api(self, args, data_sources=None):
        """api start | stop | status"""
        api = self._get_api()
        sub = (args or "").strip().lower()

        if sub == "start":
            if data_sources:
                for name, cb in data_sources.items():
                    api.register_data_source(name, cb)
            result = api.start()
            if "error" in result:
                self.console.print(f"[red]{result['error']}[/red]\n")
            else:
                self.console.print(f"[green]✓ REST API running at {api.url}[/green]")
                self.console.print(f"[dim]Endpoints: /api/status /api/threats /api/processes /api/ports[/dim]\n")
        elif sub == "stop":
            api.stop()
            self.console.print("[yellow]API server stopped[/yellow]\n")
        else:
            status = "🟢 Running" if api.is_running else "🔴 Stopped"
            self.console.print(Panel(
                f"Status: {status}\nURL: {api.url}",
                title="REST API", border_style="cyan"
            ))
            self.console.print("[dim]Usage: api <start|stop>[/dim]\n")

    # ── CLOUD BACKUP ─────────────────────────────────────────────────
    def cmd_backup(self, args):
        """backup [filepath]  — upload report(s) to cloud endpoint"""
        backup = self._get_backup()
        path = (args or "").strip()

        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
            if path:
                t = p.add_task(f"Uploading {path}...", total=None)
                result = backup.upload_report(path)
                p.stop_task(t)
                if result.get("success"):
                    self.console.print(f"[green]✓ Uploaded {result['filename']}[/green]\n")
                else:
                    self.console.print(f"[red]Upload failed: {result.get('error', result.get('status_code'))}[/red]\n")
            else:
                t = p.add_task("Uploading all reports...", total=None)
                result = backup.upload_all_reports()
                p.stop_task(t)
                self.console.print(
                    f"[green]✓ Uploaded {result['total_uploaded']}/{result['total_files']} reports[/green]\n"
                )
