"""
Offline commands: baseline, filescan, audit, timeline, snapshot, export (+ encryption)
"""
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import time

from engine.baseline_manager import BaselineManager
from engine.file_scanner import FileScanner
from engine.windows_audit import WindowsAudit
from engine.forensic_timeline import ForensicTimeline
from engine.snapshot_manager import SnapshotManager


class OfflineCommands:
    def __init__(self, report_generator):
        self.console = Console()
        self.baseline = BaselineManager()
        self.file_scanner = FileScanner()
        self.windows_audit = WindowsAudit()
        self.timeline = ForensicTimeline()
        self.snapshots = SnapshotManager()
        self.report_generator = report_generator

    # ── BASELINE ──────────────────────────────────────────────────────
    def cmd_baseline(self, args):
        """baseline create | compare | status"""
        sub = (args or "").strip().lower()

        if sub == "create":
            with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
                t = p.add_task("Creating baseline...", total=None)
                b = self.baseline.create_baseline()
                p.stop_task(t)
            self.console.print(f"\n[green]✓ Baseline created at {b['timestamp']}[/green]")
            self.console.print(f"  Processes: {len(b['processes'])} | Ports: {len(b['ports'])} | Users: {len(b['users'])}\n")

        elif sub == "compare":
            with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
                t = p.add_task("Comparing against baseline...", total=None)
                result = self.baseline.compare_baseline()
                p.stop_task(t)

            if "error" in result:
                self.console.print(f"[red]{result['error']}[/red]\n")
                return

            changes = result["changes"]
            self.console.print(Panel(
                f"Baseline: [dim]{result['baseline_timestamp']}[/dim]\n"
                f"Risk Score: [bold]{result['risk_score']}/100[/bold] | Changes: {result['total_changes']}",
                title="Baseline Comparison", border_style="cyan"
            ))
            self._show_change_table("🆕 New Processes", changes.get("new_processes", []), ["pid", "name"])
            self._show_change_table("🔌 New Open Ports", changes.get("new_ports", []), ["port", "ip", "pid"])
            self._show_change_table("🔒 Closed Ports", changes.get("closed_ports", []), ["port", "ip"])
            self._show_change_table("👤 New Users", changes.get("new_users", []), ["name", "host"])
            self._show_change_table("📋 New Scheduled Tasks", [{"task": t} for t in changes.get("new_tasks", [])], ["task"])
            self.console.print()

        else:
            b = self.baseline.load_baseline()
            if b:
                self.console.print(f"[cyan]Baseline exists:[/cyan] {b['timestamp']} | {len(b['processes'])} processes, {len(b['ports'])} ports\n")
            else:
                self.console.print("[yellow]No baseline found. Run: baseline create[/yellow]\n")
            self.console.print("[dim]Usage: baseline <create|compare>[/dim]\n")

    def _show_change_table(self, title, items, keys):
        if not items:
            return
        t = Table(title=title)
        for k in keys:
            t.add_column(k.capitalize(), style="yellow")
        for item in items[:20]:
            t.add_row(*[str(item.get(k, "N/A"))[:40] for k in keys])
        self.console.print(t)

    # ── FILESCAN ──────────────────────────────────────────────────────
    def cmd_filescan(self, args):
        """filescan [path]  — scan for suspicious files"""
        path = (args or "").strip()
        if not path:
            path = None  # trigger user dirs scan

        self.console.print("[cyan]🔍 Scanning for suspicious files...[/cyan]")
        if path:
            result = self.file_scanner.scan_directory(path)
        else:
            result = self.file_scanner.scan_user_directories()
            self.console.print(f"[dim]Scanning user directories: Downloads, Desktop, Documents, Temp[/dim]")

        if "error" in result:
            self.console.print(f"[red]{result['error']}[/red]\n")
            return

        flagged = result.get("flagged_files", [])
        self.console.print(f"\n[bold]Scanned:[/bold] {result.get('scanned_files', result.get('total_scanned', 0))} files | "
                           f"[bold red]Flagged: {len(flagged)}[/bold red]\n")

        if flagged:
            t = Table(title="Suspicious Files")
            t.add_column("File", style="red", max_width=40)
            t.add_column("Ext", style="yellow")
            t.add_column("Risk", style="orange1")
            t.add_column("MD5", style="dim", max_width=14)
            for f in flagged[:30]:
                t.add_row(
                    f.get("filename", "?"),
                    f.get("extension", ""),
                    " | ".join(f.get("risks", []))[:60],
                    (f.get("md5") or "")[:12] + "..."
                )
            self.console.print(t)
        else:
            self.console.print("[green]✓ No suspicious files found[/green]")
        self.console.print()

    # ── AUDIT ─────────────────────────────────────────────────────────
    def cmd_audit(self, args):
        """Full Windows security audit"""
        with Progress(SpinnerColumn(), BarColumn(bar_width=20), TextColumn("[cyan]{task.description}"), transient=True) as p:
            t = p.add_task("Auditing scheduled tasks...", total=3)
            audit = self.windows_audit.full_audit()
            p.update(t, advance=1, description="Auditing registry run keys...")
            time.sleep(0.1)
            p.update(t, advance=1, description="Auditing network shares...")
            time.sleep(0.1)
            p.update(t, advance=1)

        risk = audit.get("risk_level", "UNKNOWN")
        color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "orange1", "CRITICAL": "red"}.get(risk, "white")
        self.console.print(Panel(
            f"Risk Level: [{color}]{risk}[/{color}] | Suspicious Items: {audit.get('total_suspicious_items', 0)}",
            title="Windows Security Audit", border_style=color
        ))

        # Scheduled tasks
        tasks_data = audit.get("scheduled_tasks", {})
        if tasks_data.get("suspicious"):
            t2 = Table(title=f"⚠️  Suspicious Scheduled Tasks ({tasks_data['suspicious_count']})")
            t2.add_column("Task", style="red", max_width=50)
            t2.add_column("Runs", style="yellow", max_width=50)
            for item in tasks_data["suspicious"][:15]:
                t2.add_row(item.get("name", ""), item.get("run", "")[:50])
            self.console.print(t2)
        else:
            self.console.print("[green]✓ No suspicious scheduled tasks[/green]")

        # Registry
        reg_data = audit.get("registry_run_keys", {})
        if "error" in reg_data:
            self.console.print(f"[dim]Registry: {reg_data['error']}[/dim]")
        elif reg_data.get("suspicious"):
            t3 = Table(title=f"⚠️  Suspicious Registry Run Keys ({reg_data['suspicious_count']})")
            t3.add_column("Key", style="red")
            t3.add_column("Name", style="orange1")
            t3.add_column("Value", style="yellow", max_width=50)
            for item in reg_data["suspicious"][:10]:
                t3.add_row(item.get("key", ""), item.get("name", ""), item.get("value", "")[:50])
            self.console.print(t3)
        else:
            self.console.print("[green]✓ No suspicious registry run keys[/green]")

        # Shares
        share_data = audit.get("network_shares", {})
        if share_data.get("shares"):
            t4 = Table(title="Network Shares")
            t4.add_column("Name", style="cyan")
            t4.add_column("Resource", style="green")
            t4.add_column("Remark", style="dim")
            for s in share_data["shares"]:
                t4.add_row(s.get("name", ""), s.get("resource", ""), s.get("remark", ""))
            self.console.print(t4)
        self.console.print()

    # ── TIMELINE ──────────────────────────────────────────────────────
    def cmd_timeline(self, args):
        """timeline [hours] [start|stop|clear]"""
        parts = (args or "").strip().split()
        sub = parts[0].lower() if parts else ""

        if sub == "start":
            self.timeline.start_monitoring()
            self.console.print("[green]✓ Timeline monitoring started (background thread)[/green]\n")
        elif sub == "stop":
            self.timeline.stop_monitoring()
            self.console.print("[yellow]Timeline monitoring stopped[/yellow]\n")
        elif sub == "clear":
            self.timeline.clear_timeline()
            self.console.print("[yellow]Timeline cleared[/yellow]\n")
        else:
            hours = 24
            try:
                hours = int(sub) if sub.isdigit() else 24
            except Exception:
                pass

            data = self.timeline.get_timeline(hours=hours)
            self.console.print(Panel(
                f"Events: [bold]{data['total_events']}[/bold] | Window: {hours}h | "
                f"Monitoring: {'[green]ON[/green]' if data['monitoring_active'] else '[red]OFF[/red]'}",
                title="Forensic Timeline", border_style="cyan"
            ))
            events = data.get("events", [])[-40:]
            if events:
                t = Table()
                t.add_column("Time", style="dim", width=10)
                t.add_column("Type", style="cyan", width=18)
                t.add_column("Sev", style="yellow", width=8)
                t.add_column("Details", style="white")
                for ev in events:
                    ts = ev.get("timestamp", "")[-8:]
                    det = str(ev.get("details", {}))[:60]
                    sev = ev.get("severity", "INFO")
                    sev_color = {"WARNING": "yellow", "CRITICAL": "red", "INFO": "green"}.get(sev, "white")
                    t.add_row(ts, ev.get("event_type", ""), f"[{sev_color}]{sev}[/{sev_color}]", det)
                self.console.print(t)
            else:
                self.console.print(f"[dim]No events in last {hours}h. Run 'timeline start' to begin monitoring.[/dim]")
            self.console.print()

    # ── SNAPSHOT ──────────────────────────────────────────────────────
    def cmd_snapshot(self, args):
        """snapshot take [label] | list | diff <id1> <id2> | delete <id>"""
        parts = (args or "").strip().split(maxsplit=2)
        sub = parts[0].lower() if parts else ""

        if sub == "take":
            label = parts[1] if len(parts) > 1 else ""
            with Progress(SpinnerColumn(), TextColumn("[cyan]Taking snapshot..."), transient=True) as p:
                t = p.add_task("", total=None)
                meta = self.snapshots.take_snapshot(label)
                p.stop_task(t)
            self.console.print(f"[green]✓ Snapshot saved:[/green] [bold]{meta['id']}[/bold] ({meta['processes']} procs, {meta['ports']} ports)\n")

        elif sub == "list":
            snaps = self.snapshots.list_snapshots()
            if not snaps:
                self.console.print("[yellow]No snapshots found. Run: snapshot take[/yellow]\n")
                return
            t = Table(title="Saved Snapshots")
            t.add_column("ID", style="cyan")
            t.add_column("Label", style="green")
            t.add_column("Timestamp", style="dim")
            t.add_column("Procs", style="yellow")
            t.add_column("Ports", style="magenta")
            for s in snaps:
                t.add_row(s["id"], s["label"], s["timestamp"][:19], str(s["processes"]), str(s["ports"]))
            self.console.print(t)
            self.console.print()

        elif sub == "diff" and len(parts) >= 3:
            id1, id2 = parts[1], parts[2]
            diff = self.snapshots.compare_snapshots(id1, id2)
            if "error" in diff:
                self.console.print(f"[red]{diff['error']}[/red]\n")
                return
            d = diff["diff"]
            self.console.print(Panel(
                f"[dim]{diff['snapshot_1']['label']}[/dim] → [dim]{diff['snapshot_2']['label']}[/dim]\n"
                f"Changes: [bold]{diff['total_changes']}[/bold] | Risk: [bold]{diff['risk_score']}/100[/bold]\n"
                f"CPU Δ: {d['cpu_delta_percent']:+.1f}% | RAM Δ: {d['ram_delta_percent']:+.1f}%",
                title="Snapshot Diff", border_style="cyan"
            ))
            self._show_change_table("🆕 New Processes", d["new_processes"], ["pid", "name"])
            self._show_change_table("🔌 New Ports", d["new_ports"], ["port", "ip"])
            self._show_change_table("🔒 Closed Ports", d["closed_ports"], ["port", "ip"])
            self.console.print()

        elif sub == "delete" and len(parts) >= 2:
            ok = self.snapshots.delete_snapshot(parts[1])
            msg = f"[green]✓ Deleted {parts[1]}[/green]" if ok else f"[red]Snapshot {parts[1]} not found[/red]"
            self.console.print(msg + "\n")

        else:
            self.console.print(
                "[dim]Usage:\n"
                "  snapshot take [label]\n"
                "  snapshot list\n"
                "  snapshot diff <id1> <id2>\n"
                "  snapshot delete <id>[/dim]\n"
            )

    # ── EXPORT (with optional encryption) ────────────────────────────
    def cmd_export_encrypted(self, last_scan_data, threat_engine):
        """Export report with AES encryption"""
        if not last_scan_data:
            self.console.print("[yellow]Run 'threats' first.[/yellow]\n")
            return

        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            import base64, os as _os

            password = input("Encryption password: ").encode()
            salt = _os.urandom(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
            key = base64.urlsafe_b64encode(kdf.derive(password))
            f = Fernet(key)

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            plain_path = self.report_generator.generate_markdown_report(
                system_data=last_scan_data.get("system", {}),
                network_data=last_scan_data.get("network", {}),
                threat_analysis=last_scan_data.get("threats", {}),
                recommendations=threat_engine.generate_recommendations(last_scan_data.get("threats", {})),
                vulnerabilities=last_scan_data.get("vulnerabilities", {}),
                anomalies=last_scan_data.get("anomalies", {}),
                filename=f"SentinelCLI_Report_{ts}.md",
            )
            with open(plain_path, "rb") as pf:
                encrypted = f.encrypt(pf.read())

            enc_path = plain_path + ".enc"
            with open(enc_path, "wb") as ef:
                ef.write(salt + encrypted)

            self.console.print(f"[green]✓ Encrypted report: {enc_path}[/green]")
            self.console.print(f"[dim]  Salt is prepended to the file (first 16 bytes)[/dim]\n")
        except ImportError:
            self.console.print("[red]cryptography library not installed. Run: pip install cryptography[/red]\n")
        except Exception as e:
            self.console.print(f"[red]Encryption error: {e}[/red]\n")
