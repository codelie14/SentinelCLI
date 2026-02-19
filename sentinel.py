#!/usr/bin/env python3
"""
SentinelCLI v1.2 - Cyber Defense Terminal Toolkit
Offline & Online security monitoring modes
"""

import sys
import os
import time
from datetime import datetime
from typing import Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import WordCompleter

from config import SentinelConfig
from engine import SystemMonitor, NetworkMonitor, ThreatEngine, AnomalyDetector, VulnerabilityAssessment
from modules import NetworkScanner, ProcessAnalyzer, ReportGenerator
from commands import ConfigCommands, OfflineCommands, OnlineCommands


class SentinelCLI:
    def __init__(self):
        self.console = Console()
        self.config = SentinelConfig()
        self.mode_label = self.config.mode

        # Core engines
        self.system_monitor = SystemMonitor()
        self.network_monitor = NetworkMonitor()
        self.threat_engine = ThreatEngine()
        self.network_scanner = NetworkScanner()
        self.process_analyzer = ProcessAnalyzer()
        self.report_generator = ReportGenerator()
        self.anomaly_detector = AnomalyDetector()
        self.vulnerability_assessment = VulnerabilityAssessment()

        # Command groups
        self.cfg_cmds = ConfigCommands(self.config, self)
        self.offline_cmds = OfflineCommands(self.report_generator)
        self.online_cmds = OnlineCommands(self.config)

        os.makedirs("logs", exist_ok=True)
        self.history_file = FileHistory("logs/command_history.txt")
        self.last_scan_data = None

        # Command registry
        self.commands = {
            # Core
            "sysinfo": self._cmd_sysinfo,
            "users": self._cmd_users,
            "startup": self._cmd_startup,
            "scan": self._cmd_scan,
            "ports": self._cmd_ports,
            "connections": self._cmd_connections,
            "watch": self._cmd_watch,
            "threats": self._cmd_threats,
            "processes": self._cmd_processes,
            "score": self._cmd_score,
            "export": self._cmd_export,
            # Mode & Config
            "mode": self.cfg_cmds.cmd_mode,
            "config": self.cfg_cmds.cmd_config,
            # Offline
            "baseline": self.offline_cmds.cmd_baseline,
            "filescan": self.offline_cmds.cmd_filescan,
            "audit": self.offline_cmds.cmd_audit,
            "timeline": self.offline_cmds.cmd_timeline,
            "snapshot": self.offline_cmds.cmd_snapshot,
            # Online
            "vtcheck": self._online_guard(self.online_cmds.cmd_vtcheck),
            "intel": self._online_guard(self.online_cmds.cmd_intel),
            "geoip": self._online_guard(self.online_cmds.cmd_geoip),
            "notify": self._online_guard(self.online_cmds.cmd_notify),
            "backup": self._online_guard(self.online_cmds.cmd_backup),
            "api": self._api_cmd,
            # Util
            "help": self._cmd_help,
            "clear": lambda _: os.system("cls" if os.name == "nt" else "clear"),
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
        }

    def _online_guard(self, fn):
        """Wrap an online command so it errors gracefully in offline mode"""
        def wrapper(args):
            if not self.config.is_online:
                self.console.print(
                    "[red]This command requires ONLINE mode.[/red] "
                    "Switch with: [cyan]mode online[/cyan]\n"
                )
                return
            fn(args)
        return wrapper

    def _api_cmd(self, args):
        if not self.config.is_online:
            self.console.print("[red]API requires ONLINE mode.[/red] Use: [cyan]mode online[/cyan]\n")
            return
        data_sources = {
            "status": lambda: {"status": "running", "mode": self.mode_label,
                               "timestamp": datetime.now().isoformat()},
            "threats": lambda: self.last_scan_data.get("threats", {}) if self.last_scan_data else {},
            "processes": lambda: self.system_monitor.get_processes(limit=50),
            "ports": lambda: self.network_monitor.get_open_ports(),
            "connections": lambda: self.network_monitor.get_connections(),
        }
        self.online_cmds.cmd_api(args, data_sources=data_sources)

    # ─────────────────────────────────────────────────────────────────
    #  Helpers
    # ─────────────────────────────────────────────────────────────────

    def display_banner(self):
        banner = """
        ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
        ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
        ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
        ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
        ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
        ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
        🛡️  CYBER DEFENSE TERMINAL TOOLKIT v1.2
        Type 'help' for commands | 'mode online/offline' to switch mode
        """
        self.console.print(banner, style="cyan bold")
        mode_color = "cyan" if self.config.mode == "offline" else "green"
        self.console.print(
            f"  Mode: [{mode_color}]{self.config.mode.upper()}[/{mode_color}]\n",
            style="bold"
        )

    def animate_operation(self, name, duration=1.0):
        with Progress(SpinnerColumn(style="cyan"), TextColumn(f"[bold cyan]{name}"), transient=True) as p:
            t = p.add_task(name, total=None)
            time.sleep(duration)
            p.stop_task(t)

    def animate_progress(self, name, steps=10):
        with Progress(SpinnerColumn(style="green"), BarColumn(bar_width=20),
                      TextColumn("[bold green]{task.percentage:>3.0f}%"), TextColumn("•"),
                      TextColumn(f"[bold green]{name}"), transient=True) as p:
            t = p.add_task(name, total=steps)
            for _ in range(steps):
                time.sleep(0.1)
                p.update(t, advance=1)

    def run(self):
        self.display_banner()
        all_cmds = list(self.commands.keys())
        completer = WordCompleter(all_cmds, ignore_case=True)
        session = PromptSession(history=self.history_file, completer=completer)

        while True:
            try:
                prompt_label = f"[sentinel|{self.mode_label}]> "
                user_input = session.prompt(prompt_label).strip()
                if not user_input:
                    continue
                parts = user_input.split(maxsplit=1)
                cmd = parts[0].lower()
                args = parts[1] if len(parts) > 1 else None
                if cmd in self.commands:
                    self.commands[cmd](args)
                else:
                    self.console.print(f"[red]Unknown command: {cmd}[/red] — type 'help'\n")
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Interrupted. Type 'exit' to quit.[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")

    # ─────────────────────────────────────────────────────────────────
    #  Core commands (unchanged logic, kept in main class)
    # ─────────────────────────────────────────────────────────────────

    def _cmd_sysinfo(self, args):
        self.animate_operation("⚙️  Gathering system information...", 0.8)
        self.console.print("[bold cyan]═══════════ SYSTEM INFORMATION ═══════════[/bold cyan]\n")
        sys_info = self.system_monitor.get_system_info()
        boot_info = self.system_monitor.get_boot_time()
        t = Table(title="System Details", show_header=False, box=None)
        for key, value in sys_info.items():
            if key != "timestamp":
                t.add_row(f"[bold]{key.upper()}[/bold]", str(value))
        if "uptime_formatted" in boot_info:
            t.add_row("[bold]UPTIME[/bold]", boot_info["uptime_formatted"])
        self.console.print(t)

        cpu = self.system_monitor.get_cpu_info()
        mem = self.system_monitor.get_memory_info()
        self.console.print("\n[bold cyan]Resources[/bold cyan]\n")
        r = Table(show_header=False, box=None)
        r.add_row("[bold]CPU Usage[/bold]", f"{cpu.get('cpu_percent',0):.1f}%")
        r.add_row("[bold]Cores[/bold]", f"{cpu.get('cpu_count_physical',0)} physical / {cpu.get('cpu_count_logical',0)} logical")
        r.add_row("[bold]RAM Usage[/bold]", f"{mem.get('ram_percent',0):.1f}%")
        r.add_row("[bold]Swap[/bold]", f"{mem.get('swap_percent',0):.1f}%")
        self.console.print(r)

        disk = self.system_monitor.get_disk_info()
        dt = Table(title="Disk Partitions")
        dt.add_column("Device", style="cyan"); dt.add_column("Free", style="green")
        dt.add_column("Used", style="yellow"); dt.add_column("Total", style="magenta")
        dt.add_column("Usage %", style="red")
        for dev, info in disk.get("disks", {}).items():
            gb = lambda b: f"{b/1024**3:.2f}GB"
            dt.add_row(dev, gb(info["free"]), gb(info["used"]), gb(info["total"]), f"{info['percent']:.1f}%")
        self.console.print(dt)
        self.console.print()

    def _cmd_users(self, args):
        users_data = self.system_monitor.get_connected_users()
        t = Table(title="Active User Sessions")
        t.add_column("User", style="cyan"); t.add_column("Terminal", style="green")
        t.add_column("Host", style="yellow"); t.add_column("Started", style="magenta")
        for u in users_data.get("users", []):
            t.add_row(u["name"], u["terminal"] or "N/A", u["host"] or "N/A", u["started"][-8:])
        self.console.print(t)
        self.console.print()

    def _cmd_startup(self, args):
        self.animate_progress("📊 Scanning processes...", 8)
        procs = self.system_monitor.get_processes(limit=20)
        t = Table(title="Processes by Memory Usage")
        t.add_column("PID", style="cyan"); t.add_column("Name", style="green")
        t.add_column("CPU %", style="yellow"); t.add_column("Memory %", style="magenta")
        for p in procs.get("processes", []):
            t.add_row(str(p.get("pid","?")), p.get("name","?")[:30],
                      f"{p.get('cpu_percent',0):.1f}%", f"{p.get('memory_percent',0):.1f}%")
        self.console.print(t)
        self.console.print()

    def _cmd_scan(self, args):
        self.animate_progress("🔍 Scanning network...", 10)
        self.console.print()
        result = self.network_scanner.scan_network(args)
        if "error" in result:
            self.console.print(f"[red]{result['error']}[/red]"); return
        t = Table(title=f"Active Hosts on {result.get('subnet','Network')}")
        t.add_column("IP", style="cyan"); t.add_column("Hostname", style="green"); t.add_column("Status", style="yellow")
        for h in result.get("active_hosts", []):
            t.add_row(h["ip"], h["hostname"], "🟢 Online")
        self.console.print(t)
        self.console.print(f"\n[bold]Found {result.get('host_count',0)} active host(s)[/bold]\n")
        self.last_scan_data = result

    def _cmd_ports(self, args):
        self.animate_operation("🔌 Scanning open ports...", 1.2)
        ports_data = self.network_monitor.get_open_ports()
        open_ports = ports_data.get("open_ports", {})
        if not open_ports:
            self.console.print("[yellow]No open ports detected[/yellow]\n"); return
        t = Table(title="Open Ports and Services")
        t.add_column("Port", style="cyan"); t.add_column("Service", style="green")
        t.add_column("Address", style="yellow"); t.add_column("Type", style="magenta")
        for port, info in sorted(open_ports.items()):
            t.add_row(str(port), info.get("service","?"), info.get("address","?"), info.get("type","?"))
        self.console.print(t)
        self.console.print(f"\n[bold]Total: {ports_data.get('port_count',0)} open ports[/bold]\n")

    def _cmd_connections(self, args):
        self.animate_operation("📡 Analyzing connections...", 1.0)
        conns = self.network_monitor.get_connections()
        t = Table(title="Active Network Connections")
        t.add_column("Local IP", style="cyan"); t.add_column("Local Port", style="green")
        t.add_column("Remote IP", style="yellow"); t.add_column("Remote Port", style="magenta")
        t.add_column("Status", style="blue")
        for c in conns.get("connections", []):
            t.add_row(c.get("local_addr","?"), str(c.get("local_port","?")),
                      c.get("remote_addr","?"), str(c.get("remote_port","?")), c.get("status","?"))
        self.console.print(t)
        sus = self.network_monitor.get_suspicious_connections()
        suspicious = sus.get("suspicious_connections", [])
        if suspicious:
            self.console.print(f"\n[bold red]⚠️  {len(suspicious)} suspicious connection(s)[/bold red]\n")
        self.console.print()

    def _cmd_watch(self, args):
        self.console.print("[bold cyan]Real-time Monitor (Ctrl+C to stop)[/bold cyan]\n")
        try:
            for i in range(5):
                sys_d = self.system_monitor.get_cpu_info()
                mem_d = self.system_monitor.get_memory_info()
                conn_d = self.network_monitor.get_connections()
                self.console.print(f"[bold]Update #{i+1}[/bold] - {datetime.now().strftime('%H:%M:%S')}")
                s = Table(show_header=False, box=None)
                s.add_row("[cyan]CPU[/cyan]", f"{sys_d.get('cpu_percent',0):.1f}%")
                s.add_row("[cyan]RAM[/cyan]", f"{mem_d.get('ram_percent',0):.1f}%")
                s.add_row("[cyan]Connections[/cyan]", str(len(conn_d.get("connections",[]))))
                self.console.print(s)
                time.sleep(2)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Monitoring stopped[/yellow]\n")

    def _cmd_threats(self, args):
        with Progress(SpinnerColumn(style="red"), BarColumn(bar_width=25),
                      TextColumn("[bold red]{task.percentage:>3.0f}%"), TextColumn("•"),
                      TextColumn("[bold red]{task.description}"), transient=False) as p:
            task = p.add_task("Threat Analysis", total=5)
            p.update(task, description="1/5 System info...", advance=1); time.sleep(0.2)
            sys_info = {**self.system_monitor.get_system_info(), **self.system_monitor.get_cpu_info(),
                        **self.system_monitor.get_memory_info(), **self.system_monitor.get_disk_info()}
            p.update(task, description="2/5 Processes...", advance=1); time.sleep(0.2)
            procs = self.system_monitor.get_processes()
            p.update(task, description="3/5 Network...", advance=1); time.sleep(0.2)
            net_ports = self.network_monitor.get_open_ports()
            net_conns = self.network_monitor.get_connections()
            sus_conn = self.network_monitor.get_suspicious_connections()
            p.update(task, description="4/5 Anomalies...", advance=1); time.sleep(0.2)
            p.update(task, description="5/5 Scoring...", advance=1); time.sleep(0.3)

        net_data = {**net_ports, "connections": net_conns.get("connections",[]), **sus_conn}
        threat = self.threat_engine.calculate_security_score(sys_info, net_data)
        proc_list = procs.get("processes", [])
        pa = self.anomaly_detector.detect_process_anomalies(proc_list)
        na = self.anomaly_detector.detect_network_anomalies(net_data.get("connections",[]))
        ra = self.anomaly_detector.detect_resource_anomalies(
            sys_info.get("cpu_percent",0), sys_info.get("ram_percent",0),
            list(sys_info.get("disks",{}).values())[0].get("percent",0) if sys_info.get("disks") else 0)
        na.setdefault("risk_score", len(na.get("network_anomalies",[])) * 20)
        ra.setdefault("risk_score", len(ra.get("resource_anomalies",[])) * 10)
        all_anomalies = pa.get("anomalies_detected",[]) + na.get("network_anomalies",[]) + ra.get("resource_anomalies",[])
        anomalies = {"anomalies_detected": all_anomalies, "count": len(all_anomalies),
                     "risk_score": max(pa.get("risk_score",0), na.get("risk_score",0), ra.get("risk_score",0))}
        vulns = self.vulnerability_assessment.scan_vulnerabilities(sys_info, net_ports.get("open_ports",{}), proc_list)

        score = threat.get("security_score", 0)
        level = threat.get("threat_level", "UNKNOWN")
        color = "green" if score >= 75 else "yellow" if score >= 50 else "orange1" if score >= 25 else "red"
        self.console.print(Panel.fit(f"[{color} bold]{score}/100[/{color} bold]", title="SECURITY SCORE", border_style=color))
        self.console.print(Panel.fit(f"[{color} bold]{level}[/{color} bold]", title="THREAT LEVEL", border_style=color))

        threats = threat.get("threats_detected", [])
        if threats:
            self.console.print(f"\n[bold red]⚠️  {len(threats)} threats detected[/bold red]\n")
            tt = Table()
            tt.add_column("Type", style="red"); tt.add_column("Severity", style="orange1"); tt.add_column("Details", style="yellow")
            for th in threats:
                details = ", ".join(filter(None, [f"Port: {th.get('port')}" if "port" in th else "", f"IP: {th.get('remote_addr')}" if "remote_addr" in th else ""]))
                tt.add_row(th.get("type","?"), th.get("severity","?"), details or "N/A")
            self.console.print(tt)
        else:
            self.console.print("[green]✓ No threats detected[/green]")
        self.console.print()

        self.last_scan_data = {"system": sys_info, "network": net_data, "threats": threat,
                               "anomalies": anomalies, "vulnerabilities": vulns}

        # Auto-notify if online and threat is HIGH/CRITICAL
        if self.config.is_online and level in ("HIGH", "CRITICAL"):
            threats_str = ", ".join(th.get("type","?") for th in threats[:5])
            self.online_cmds._get_notifier().notify_threat(
                level, f"SentinelCLI: {level} Threat Detected",
                f"Score: {score}/100 | Threats: {threats_str}"
            )

    def _cmd_processes(self, args):
        self.animate_progress("🔎 Analyzing processes...", 6)
        high_res = self.process_analyzer.get_high_resource_processes()
        if high_res.get("high_resource_processes"):
            pt = Table(title="High Resource Processes")
            pt.add_column("PID", style="cyan"); pt.add_column("Name", style="green")
            pt.add_column("CPU %", style="yellow"); pt.add_column("Memory %", style="magenta")
            for p in high_res.get("high_resource_processes",[])[:10]:
                pt.add_row(str(p.get("pid","?")), p.get("name","?"),
                           f"{p.get('cpu_percent',0):.1f}%", f"{p.get('memory_percent',0):.1f}%")
            self.console.print(pt)
        sus = self.process_analyzer.analyze_suspicious_processes()
        if sus.get("suspicious_processes"):
            st = Table(title=f"⚠️  Suspicious Processes ({sus.get('risk_count',0)})")
            st.add_column("PID", style="red"); st.add_column("Name", style="orange1"); st.add_column("Risk", style="yellow")
            for p in sus.get("suspicious_processes",[]):
                st.add_row(str(p.get("pid","?")), p.get("name","?"), ", ".join(p.get("reasons",["?"]))[:50])
            self.console.print(st)
        else:
            self.console.print("[green]✓ No suspicious processes[/green]")
        self.console.print()

    def _cmd_score(self, args):
        if not self.last_scan_data:
            self.console.print("[yellow]Run 'threats' first.[/yellow]\n"); return
        t = self.last_scan_data.get("threats", {})
        self.console.print(Panel(
            f"[bold cyan]Score:[/bold cyan] {t.get('security_score',0)}/100\n"
            f"[bold cyan]Level:[/bold cyan] {t.get('threat_level','?')}",
            title="Security Summary", border_style="cyan"
        ))
        for rec in self.threat_engine.generate_recommendations(t):
            self.console.print(rec)
        self.console.print()

    def _cmd_export(self, args):
        if not self.last_scan_data:
            self.console.print("[yellow]Run 'threats' or 'scan' first.[/yellow]\n"); return

        # --encrypt flag
        if args and "--encrypt" in args:
            self.offline_cmds.cmd_export_encrypted(self.last_scan_data, self.threat_engine)
            return

        with Progress(SpinnerColumn(style="yellow"), BarColumn(bar_width=20),
                      TextColumn("[bold yellow]{task.percentage:>3.0f}%"), TextColumn("•"),
                      TextColumn("[bold yellow]{task.description}"), transient=True) as p:
            task = p.add_task("Generating report", total=4)
            for step in ["1/4 Collecting...", "2/4 Analyzing...", "3/4 Formatting...", "4/4 Saving..."]:
                p.update(task, description=step, advance=1); time.sleep(0.2)
            fn = f"SentinelCLI_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            fp = self.report_generator.generate_markdown_report(
                system_data=self.last_scan_data.get("system",{}),
                network_data=self.last_scan_data.get("network",{}),
                threat_analysis=self.last_scan_data.get("threats",{}),
                recommendations=self.threat_engine.generate_recommendations(self.last_scan_data.get("threats",{})),
                vulnerabilities=self.last_scan_data.get("vulnerabilities",{}),
                anomalies=self.last_scan_data.get("anomalies",{}),
                filename=fn,
            )
        self.console.print(f"\n[green]✓ Report: {fp}[/green]")
        self.console.print("[dim]Tip: use 'export --encrypt' for password-protected export[/dim]")
        self.console.print("[dim]     use 'backup' to upload to cloud[/dim]\n")

    def _cmd_help(self, args):
        mode_color = "cyan" if self.config.mode == "offline" else "green"
        self.console.print(f"\n[bold {mode_color}]═══════ SentinelCLI v1.2 — Mode: {self.config.mode.upper()} ═══════[/bold {mode_color}]\n")
        self.console.print("[bold]SYSTEM MONITORING[/bold]")
        self.console.print("  [cyan]sysinfo[/cyan]   — System info (OS, CPU, RAM, Disk)")
        self.console.print("  [cyan]users[/cyan]     — Connected users")
        self.console.print("  [cyan]startup[/cyan]   — Top resource processes")
        self.console.print("\n[bold]NETWORK[/bold]")
        self.console.print("  [cyan]scan[/cyan]      — Scan local network hosts")
        self.console.print("  [cyan]ports[/cyan]     — Open ports & services")
        self.console.print("  [cyan]connections[/cyan] — Active connections")
        self.console.print("\n[bold]SECURITY[/bold]")
        self.console.print("  [cyan]watch[/cyan]     — Real-time monitoring")
        self.console.print("  [cyan]threats[/cyan]   — Full threat analysis + score")
        self.console.print("  [cyan]processes[/cyan] — Suspicious process analysis")
        self.console.print("  [cyan]score[/cyan]     — Security score + recommendations")
        self.console.print("\n[bold]🔒 OFFLINE FEATURES[/bold]")
        self.console.print("  [cyan]baseline[/cyan]  <create|compare>")
        self.console.print("  [cyan]filescan[/cyan]  [path]")
        self.console.print("  [cyan]audit[/cyan]     — Windows scheduled tasks, registry, shares")
        self.console.print("  [cyan]timeline[/cyan]  [hours] | <start|stop|clear>")
        self.console.print("  [cyan]snapshot[/cyan]  <take|list|diff|delete>")
        self.console.print("\n[bold]🌐 ONLINE FEATURES[/bold] [dim](mode online required)[/dim]")
        self.console.print("  [cyan]vtcheck[/cyan]   [hash] — VirusTotal hash check")
        self.console.print("  [cyan]intel[/cyan]     <fetch|scan> — AlienVault OTX")
        self.console.print("  [cyan]geoip[/cyan]     [ip] — Geolocation of connections")
        self.console.print("  [cyan]notify[/cyan]    <test|level message>")
        self.console.print("  [cyan]api[/cyan]       <start|stop> — REST API :5000")
        self.console.print("  [cyan]backup[/cyan]    [filepath] — Cloud upload")
        self.console.print("\n[bold]REPORTS[/bold]")
        self.console.print("  [cyan]export[/cyan]    — Markdown report")
        self.console.print("  [cyan]export --encrypt[/cyan] — AES-encrypted report")
        self.console.print("\n[bold]CONFIG[/bold]")
        self.console.print("  [cyan]mode[/cyan]      <offline|online>")
        self.console.print("  [cyan]config[/cyan]    <show|set|get>")
        self.console.print("\n[bold]UTIL[/bold]")
        self.console.print("  [cyan]help  clear  exit[/cyan]")
        self.console.print()

    def _cmd_exit(self, args):
        self.console.print("\n[yellow]Goodbye![/yellow]\n")
        sys.exit(0)


def main():
    try:
        SentinelCLI().run()
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
