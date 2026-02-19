#!/usr/bin/env python3
"""
SentinelCLI - Cyber Defense Terminal Toolkit
Interactive security monitoring and analysis tool
"""

import sys
import os
from datetime import datetime
from typing import Dict, Any, List
import time

# Rich for terminal formatting
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, track
from rich.live import Live

# Prompt toolkit for interactive shell
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import WordCompleter

# Local imports
from engine import SystemMonitor, NetworkMonitor, ThreatEngine, AnomalyDetector, VulnerabilityAssessment
from modules import NetworkScanner, ProcessAnalyzer, ReportGenerator


class SentinelCLI:
    """Interactive SentinelCLI shell"""
    
    def __init__(self):
        self.console = Console()
        self.system_monitor = SystemMonitor()
        self.network_monitor = NetworkMonitor()
        self.threat_engine = ThreatEngine()
        self.network_scanner = NetworkScanner()
        self.process_analyzer = ProcessAnalyzer()
        self.report_generator = ReportGenerator()
        self.anomaly_detector = AnomalyDetector()
        self.vulnerability_assessment = VulnerabilityAssessment()
        
        # Create history file
        os.makedirs('logs', exist_ok=True)
        self.history_file = FileHistory('logs/command_history.txt')
        
        # Commands dictionary
        self.commands = {
            'sysinfo': self._cmd_sysinfo,
            'users': self._cmd_users,
            'startup': self._cmd_startup,
            'scan': self._cmd_scan,
            'ports': self._cmd_ports,
            'connections': self._cmd_connections,
            'watch': self._cmd_watch,
            'threats': self._cmd_threats,
            'processes': self._cmd_processes,
            'score': self._cmd_score,
            'export': self._cmd_export,
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
        }
        
        # Session data
        self.last_scan_data = None
    
    def display_banner(self):
        """Display ASCII art banner"""
        
        banner = """
        ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
        ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
        ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
        ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
        ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
        ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                                                        
        🛡️  CYBER DEFENSE TERMINAL TOOLKIT v1.0
        Mini SOC - Local Security Monitoring and Analysis
        Type 'help' for available commands
        """
        
        self.console.print(banner, style="cyan bold")
    
    def animate_operation(self, operation_name: str, duration: float = 1.0):
        """Animated operation with spinner"""
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]{task.description}"),
            transient=True
        ) as progress:
            task = progress.add_task(operation_name, total=None)
            time.sleep(duration)
            progress.stop_task(task)
    
    def animate_progress(self, operation_name: str, steps: int = 10):
        """Animated progress bar"""
        with Progress(
            SpinnerColumn(style="green"),
            BarColumn(bar_width=20),
            TextColumn("[bold green]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("[bold green]{task.description}"),
            transient=True
        ) as progress:
            task = progress.add_task(operation_name, total=steps)
            for _ in range(steps):
                time.sleep(0.1)
                progress.update(task, advance=1)
    
    def run(self):
        """Start the interactive shell"""
        
        self.display_banner()
        
        completer = WordCompleter(list(self.commands.keys()), ignore_case=True)
        session = PromptSession(history=self.history_file, completer=completer)
        
        while True:
            try:
                # Get user input
                user_input = session.prompt('[sentinel]> ')
                user_input = user_input.strip()
                
                if not user_input:
                    continue
                
                # Parse command
                parts = user_input.split(maxsplit=1)
                command = parts[0].lower()
                args = parts[1] if len(parts) > 1 else None
                
                # Execute command
                if command in self.commands:
                    self.commands[command](args)
                else:
                    self.console.print(f"[red]Unknown command: {command}[/red]")
                    self.console.print("Type 'help' for available commands")
                
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Interrupted. Type 'exit' to quit.[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")
    
    # System Monitoring Commands
    
    def _cmd_sysinfo(self, args):
        """Display system information"""
        
        self.animate_operation("[cyan]⚙️  Gathering system information...", 0.8)
        
        self.console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")
        self.console.print("[bold cyan]       SYSTEM INFORMATION[/bold cyan]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]\n")
        
        # Basic system info
        sys_info = self.system_monitor.get_system_info()
        boot_info = self.system_monitor.get_boot_time()
        
        table = Table(title="System Details", show_header=False, box=None)
        
        for key, value in sys_info.items():
            if key != 'timestamp':
                table.add_row(f"[bold]{key.upper()}[/bold]", str(value))
        
        if 'uptime_formatted' in boot_info:
            table.add_row("[bold]UPTIME[/bold]", boot_info['uptime_formatted'])
        
        self.console.print(table)
        
        # CPU and Memory info
        self.console.print("\n[bold cyan]Resources[/bold cyan]\n")
        
        cpu_info = self.system_monitor.get_cpu_info()
        mem_info = self.system_monitor.get_memory_info()
        
        cpu_table = Table(show_header=False, box=None)
        cpu_table.add_row("[bold]CPU Usage[/bold]", f"{cpu_info.get('cpu_percent', 0):.1f}%")
        cpu_table.add_row("[bold]Physical Cores[/bold]", str(cpu_info.get('cpu_count_physical', 0)))
        cpu_table.add_row("[bold]Logical Cores[/bold]", str(cpu_info.get('cpu_count_logical', 0)))
        
        mem_table = Table(show_header=False, box=None)
        ram_used = mem_info.get('ram_used', 0)
        ram_total = mem_info.get('ram_total', 0)
        mem_table.add_row("[bold]RAM Usage[/bold]", f"{mem_info.get('ram_percent', 0):.1f}%")
        mem_table.add_row("[bold]Used / Total[/bold]", f"{ram_used/1024/1024/1024:.2f}GB / {ram_total/1024/1024/1024:.2f}GB")
        mem_table.add_row("[bold]Swap Usage[/bold]", f"{mem_info.get('swap_percent', 0):.1f}%")
        
        self.console.print(cpu_table)
        self.console.print(mem_table)
        
        # Disk info
        self.console.print("\n[bold cyan]Disk Space[/bold cyan]\n")
        
        disk_info = self.system_monitor.get_disk_info()
        disk_table = Table(title="Disk Partitions")
        disk_table.add_column("Device", style="cyan")
        disk_table.add_column("Free", style="green")
        disk_table.add_column("Used", style="yellow")
        disk_table.add_column("Total", style="magenta")
        disk_table.add_column("Usage %", style="red")
        
        for device, info in disk_info.get('disks', {}).items():
            total = info['total'] / (1024**3)
            used = info['used'] / (1024**3)
            free = info['free'] / (1024**3)
            
            disk_table.add_row(
                device,
                f"{free:.2f}GB",
                f"{used:.2f}GB",
                f"{total:.2f}GB",
                f"{info['percent']:.1f}%"
            )
        
        self.console.print(disk_table)
        self.console.print()
    
    def _cmd_users(self, args):
        """Display connected users"""
        
        self.console.print("[bold cyan]Connected Users[/bold cyan]\n")
        
        users_data = self.system_monitor.get_connected_users()
        
        table = Table(title="Active User Sessions")
        table.add_column("User", style="cyan")
        table.add_column("Terminal", style="green")
        table.add_column("Host", style="yellow")
        table.add_column("Started", style="magenta")
        
        for user in users_data.get('users', []):
            table.add_row(
                user['name'],
                user['terminal'] or "N/A",
                user['host'] or "N/A",
                user['started'][-8:]  # Show time only
            )
        
        self.console.print(table)
        self.console.print()
    
    def _cmd_startup(self, args):
        """Display startup processes"""
        
        self.animate_progress("[cyan]📊 Scanning processes...", 8)
        
        self.console.print("[bold cyan]Top Resource-Consuming Processes[/bold cyan]\n")
        
        processes = self.system_monitor.get_processes(limit=20)
        
        table = Table(title="Processes by Memory Usage")
        table.add_column("PID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("CPU %", style="yellow")
        table.add_column("Memory %", style="magenta")
        
        for proc in processes.get('processes', []):
            table.add_row(
                str(proc.get('pid', 'N/A')),
                proc.get('name', 'N/A')[:30],
                f"{proc.get('cpu_percent', 0):.1f}%",
                f"{proc.get('memory_percent', 0):.1f}%"
            )
        
        self.console.print(table)
        self.console.print()
    
    # Network Commands
    
    def _cmd_scan(self, args):
        """Scan local network for active hosts"""
        
        self.animate_progress("[cyan]🔍 Scanning network...", 10)
        self.console.print()
        
        subnet = args if args else None
        scan_result = self.network_scanner.scan_network(subnet)
        
        if 'error' in scan_result:
            self.console.print(f"[red]Error: {scan_result['error']}[/red]")
            return
        
        table = Table(title=f"Active Hosts on {scan_result.get('subnet', 'Network')}")
        table.add_column("IP Address", style="cyan")
        table.add_column("Hostname", style="green")
        table.add_column("Status", style="yellow")
        
        for host in scan_result.get('active_hosts', []):
            table.add_row(
                host['ip'],
                host['hostname'],
                "🟢 Online"
            )
        
        self.console.print(table)
        self.console.print(f"\n[bold]Found {scan_result.get('host_count', 0)} active host(s)[/bold]\n")
        
        # Store for later use
        self.last_scan_data = scan_result
    
    def _cmd_ports(self, args):
        """Display open ports and listening services"""
        
        self.animate_operation("[cyan]🔌 Scanning for open ports...", 1.2)
        
        ports_data = self.network_monitor.get_open_ports()
        open_ports = ports_data.get('open_ports', {})
        
        if not open_ports:
            self.console.print("[yellow]No open ports detected[/yellow]\n")
            return
        
        table = Table(title="Open Ports and Services")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="green")
        table.add_column("Address", style="yellow")
        table.add_column("Type", style="magenta")
        
        for port, info in sorted(open_ports.items()):
            table.add_row(
                str(port),
                info.get('service', 'Unknown'),
                info.get('address', 'N/A'),
                info.get('type', 'N/A')
            )
        
        self.console.print(table)
        self.console.print(f"\n[bold]Total open ports: {ports_data.get('port_count', 0)}[/bold]\n")
    
    def _cmd_connections(self, args):
        """Display active network connections"""
        
        self.animate_operation("[cyan]📡 Analyzing network connections...", 1.0)
        
        connections = self.network_monitor.get_connections()
        
        table = Table(title="Active Network Connections")
        table.add_column("Local IP", style="cyan")
        table.add_column("Local Port", style="green")
        table.add_column("Remote IP", style="yellow")
        table.add_column("Remote Port", style="magenta")
        table.add_column("Status", style="blue")
        
        for conn in connections.get('connections', []):
            table.add_row(
                conn.get('local_addr', 'N/A'),
                str(conn.get('local_port', 'N/A')),
                conn.get('remote_addr', 'N/A'),
                str(conn.get('remote_port', 'N/A')),
                conn.get('status', 'N/A')
            )
        
        self.console.print(table)
        
        # Check for suspicious connections
        suspicious_data = self.network_monitor.get_suspicious_connections()
        suspicious = suspicious_data.get('suspicious_connections', [])
        
        if suspicious:
            self.console.print(f"\n[bold red]⚠️  {len(suspicious)} suspicious connection(s) detected![/bold red]\n")
            
            sus_table = Table(title="Suspicious Connections", style="red")
            sus_table.add_column("Remote IP", style="red")
            sus_table.add_column("Port", style="red")
            sus_table.add_column("Reason", style="yellow")
            
            for sus_conn in suspicious:
                for reason in sus_conn.get('reasons', []):
                    sus_table.add_row(
                        sus_conn.get('remote_addr', 'N/A'),
                        str(sus_conn.get('remote_port', 'N/A')),
                        reason
                    )
            
            self.console.print(sus_table)
        
        self.console.print()
    
    # Security Analysis Commands
    
    def _cmd_watch(self, args):
        """Monitor real-time security threats"""
        
        self.console.print("[bold cyan]Real-time Security Monitoring (Press Ctrl+C to stop)[/bold cyan]\n")
        
        try:
            for i in range(5):  # Monitor for 5 iterations
                # Get current data
                sys_data = self.system_monitor.get_cpu_info()
                mem_data = self.system_monitor.get_memory_info()
                conn_data = self.network_monitor.get_connections()
                
                self.console.print(f"\n[bold]Update #{i+1}[/bold] - {datetime.now().strftime('%H:%M:%S')}")
                
                # Display current status
                status_table = Table(show_header=False, box=None)
                status_table.add_row("[bold cyan]CPU Usage[/bold cyan]", f"{sys_data.get('cpu_percent', 0):.1f}%")
                status_table.add_row("[bold cyan]Memory Usage[/bold cyan]", f"{mem_data.get('ram_percent', 0):.1f}%")
                status_table.add_row("[bold cyan]Active Connections[/bold cyan]", 
                                    str(len(conn_data.get('connections', []))))
                
                self.console.print(status_table)
                
                # Check for anomalies
                if sys_data.get('cpu_percent', 0) > 80:
                    self.console.print("[red]⚠️  HIGH CPU USAGE DETECTED[/red]")
                
                if mem_data.get('ram_percent', 0) > 90:
                    self.console.print("[red]⚠️  HIGH MEMORY USAGE DETECTED[/red]")
                
                if len(conn_data.get('connections', [])) > 50:
                    self.console.print("[yellow]⚠️  UNUSUAL NUMBER OF CONNECTIONS[/yellow]")
                
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Monitoring stopped[/yellow]\n")
    
    def _cmd_threats(self, args):
        """Analyze threats and compute security score"""
        
        # Animated progress analysis
        with Progress(
            SpinnerColumn(style="red"),
            BarColumn(bar_width=25),
            TextColumn("[bold red]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("[bold red]{task.description}"),
            transient=False
        ) as progress:
            task = progress.add_task("[red]Threat Analysis", total=5)
            
            # Gather all data
            progress.update(task, description="[red]1/5: Gathering system info...", advance=1)
            time.sleep(0.2)
            sys_info = self.system_monitor.get_system_info()
            cpu_info = self.system_monitor.get_cpu_info()
            mem_info = self.system_monitor.get_memory_info()
            disk_info = self.system_monitor.get_disk_info()
            
            progress.update(task, description="[red]2/5: Scanning processes...", advance=1)
            time.sleep(0.2)
            processes = self.system_monitor.get_processes()
            
            progress.update(task, description="[red]3/5: Analyzing network...", advance=1)
            time.sleep(0.2)
            net_ports = self.network_monitor.get_open_ports()
            net_connections = self.network_monitor.get_connections()
            suspicious_conn = self.network_monitor.get_suspicious_connections()
            
            progress.update(task, description="[red]4/5: Detecting anomalies...", advance=1)
            time.sleep(0.2)
            
            progress.update(task, description="[red]5/5: Calculating score...", advance=1)
            time.sleep(0.3)
        
        # Combine system data
        system_data = {**sys_info, **cpu_info, **mem_info, **disk_info}
        network_data = {**net_ports, **{'connections': net_connections.get('connections', [])}, **suspicious_conn}
        
        # Calculate threats
        threat_analysis = self.threat_engine.calculate_security_score(system_data, network_data)
        
        # Run advanced analysis modules
        process_list = processes.get('processes', [])
        
        # Anomaly Detection
        process_anomalies = self.anomaly_detector.detect_process_anomalies(process_list)
        network_anomalies = self.anomaly_detector.detect_network_anomalies(
            network_data.get('connections', [])
        )
        resource_anomalies = self.anomaly_detector.detect_resource_anomalies(
            cpu_info.get('cpu_percent', 0),
            mem_info.get('ram_percent', 0),
            list(disk_info.get('disks', {}).values())[0].get('percent', 0) if disk_info.get('disks') else 0
        )
        
        # Add risk_score to network_anomalies if missing
        if 'risk_score' not in network_anomalies:
            network_anomalies['risk_score'] = len(network_anomalies.get('network_anomalies', [])) * 20
        
        # Add risk_score to resource_anomalies if missing
        if 'risk_score' not in resource_anomalies:
            resource_anomalies['risk_score'] = len(resource_anomalies.get('resource_anomalies', [])) * 10
        
        # Combine all anomalies
        all_anomalies = (
            process_anomalies.get('anomalies_detected', []) +
            network_anomalies.get('network_anomalies', []) +
            resource_anomalies.get('resource_anomalies', [])
        )
        
        anomalies = {
            'anomalies_detected': all_anomalies,
            'count': len(all_anomalies),
            'risk_score': max(
                process_anomalies.get('risk_score', 0),
                network_anomalies.get('risk_score', 0),
                resource_anomalies.get('risk_score', 0)
            ),
            'timestamp': datetime.now().isoformat()
        }
        
        # Vulnerability Assessment
        vulnerabilities = self.vulnerability_assessment.scan_vulnerabilities(
            system_data, net_ports.get('open_ports', {}), process_list
        )
        
        # Display results with color coding
        score = threat_analysis.get('security_score', 0)
        level = threat_analysis.get('threat_level', 'UNKNOWN')
        
        if score >= 75:
            score_color = 'green'
            level_color = 'green'
        elif score >= 50:
            score_color = 'yellow'
            level_color = 'yellow'
        elif score >= 25:
            score_color = 'orange1'
            level_color = 'orange1'
        else:
            score_color = 'red'
            level_color = 'red'
        
        self.console.print(Panel.fit(
            f"[{score_color} bold]{score}/100[/{score_color} bold]",
            title="[bold]SECURITY SCORE[/bold]",
            border_style=score_color
        ))
        
        self.console.print(Panel.fit(
            f"[{level_color} bold]{level}[/{level_color} bold]",
            title="[bold]THREAT LEVEL[/bold]",
            border_style=level_color
        ))
        
        # Display detected threats
        threats = threat_analysis.get('threats_detected', [])
        
        if threats:
            self.console.print(f"\n[bold red]⚠️  {len(threats)} Threat(s) Detected:[/bold red]\n")
            
            threats_table = Table()
            threats_table.add_column("Type", style="red")
            threats_table.add_column("Severity", style="orange1")
            threats_table.add_column("Details", style="yellow")
            
            for threat in threats:
                details = []
                if 'port' in threat:
                    details.append(f"Port: {threat.get('port')}")
                if 'remote_addr' in threat:
                    details.append(f"IP: {threat.get('remote_addr')}")
                
                threats_table.add_row(
                    threat.get('type', 'Unknown'),
                    threat.get('severity', 'Unknown'),
                    ', '.join(details) if details else 'N/A'
                )
            
            self.console.print(threats_table)
        else:
            self.console.print("[green]✓ No threats detected[/green]")
        
        self.console.print()
        
        # Store for report generation
        self.last_scan_data = {
            'system': system_data,
            'network': network_data,
            'threats': threat_analysis,
            'anomalies': anomalies,
            'vulnerabilities': vulnerabilities
        }
    
    def _cmd_processes(self, args):
        """Analyze running processes"""
        
        self.animate_progress("[cyan]🔎 Analyzing running processes...", 6)
        
        # High resource processes
        high_res = self.process_analyzer.get_high_resource_processes()
        
        if high_res.get('high_resource_processes'):
            self.console.print("[bold yellow]High Resource Usage:[/bold yellow]\n")
            
            proc_table = Table()
            proc_table.add_column("PID", style="cyan")
            proc_table.add_column("Process Name", style="green")
            proc_table.add_column("CPU %", style="yellow")
            proc_table.add_column("Memory %", style="magenta")
            
            for proc in high_res.get('high_resource_processes', [])[:10]:
                proc_table.add_row(
                    str(proc.get('pid', 'N/A')),
                    proc.get('name', 'N/A'),
                    f"{proc.get('cpu_percent', 0):.1f}%",
                    f"{proc.get('memory_percent', 0):.1f}%"
                )
            
            self.console.print(proc_table)
        
        # Suspicious processes
        suspicious = self.process_analyzer.analyze_suspicious_processes()
        
        if suspicious.get('suspicious_processes'):
            self.console.print(f"\n[bold red]⚠️  Suspicious Processes Detected ({suspicious.get('risk_count', 0)}):[/bold red]\n")
            
            sus_table = Table()
            sus_table.add_column("PID", style="red")
            sus_table.add_column("Process Name", style="orange1")
            sus_table.add_column("Risk", style="yellow")
            
            for proc in suspicious.get('suspicious_processes', []):
                sus_table.add_row(
                    str(proc.get('pid', 'N/A')),
                    proc.get('name', 'N/A'),
                    ', '.join(proc.get('reasons', ['Unknown']))[:50]
                )
            
            self.console.print(sus_table)
        else:
            self.console.print("[green]✓ No suspicious processes detected[/green]")
        
        self.console.print()
    
    def _cmd_score(self, args):
        """Display detailed threat score"""
        
        if not self.last_scan_data:
            self.console.print("[yellow]Please run 'threats' command first to analyze your system[/yellow]\n")
            return
        
        threat_analysis = self.last_scan_data.get('threats', {})
        score = threat_analysis.get('security_score', 0)
        level = threat_analysis.get('threat_level', 'UNKNOWN')
        
        self.console.print(Panel(
            f"[bold cyan]Score: [/bold cyan][bold]{score}/100[/bold]\n"
            f"[bold cyan]Level: [/bold cyan][bold]{level}[/bold]",
            title="Security Analysis Summary",
            border_style="cyan"
        ))
        
        # Generate recommendations
        recommendations = self.threat_engine.generate_recommendations(threat_analysis)
        
        self.console.print("\n[bold cyan]Recommendations:[/bold cyan]\n")
        for rec in recommendations:
            self.console.print(rec)
        
        self.console.print()
    
    def _cmd_export(self, args):
        """Export security report"""
        
        if not self.last_scan_data:
            self.console.print("[yellow]Please run analysis commands first (try 'threats' or 'scan')[/yellow]\n")
            return
        
        # Prepare data for report
        system_data = self.last_scan_data.get('system', {})
        network_data = self.last_scan_data.get('network', {})
        threat_analysis = self.last_scan_data.get('threats', {})
        anomalies = self.last_scan_data.get('anomalies', {})
        vulnerabilities = self.last_scan_data.get('vulnerabilities', {})
        
        recommendations = self.threat_engine.generate_recommendations(threat_analysis)
        
        # Animated report generation
        with Progress(
            SpinnerColumn(style="yellow"),
            BarColumn(bar_width=20),
            TextColumn("[bold yellow]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("[bold yellow]{task.description}"),
            transient=True
        ) as progress:
            task = progress.add_task("[yellow]Generating report", total=4)
            
            progress.update(task, description="[yellow]1/4: Collecting data...", advance=1)
            time.sleep(0.2)
            
            progress.update(task, description="[yellow]2/4: Analyzing threats...", advance=1)
            time.sleep(0.2)
            
            progress.update(task, description="[yellow]3/4: Formatting report...", advance=1)
            time.sleep(0.2)
            
            # Generate report
            filename = f"SentinelCLI_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            filepath = self.report_generator.generate_markdown_report(
                system_data=system_data,
                network_data=network_data,
                threat_analysis=threat_analysis,
                recommendations=recommendations,
                vulnerabilities=vulnerabilities,
                anomalies=anomalies,
                filename=filename
            )
            
            progress.update(task, description="[yellow]4/4: Saving file...", advance=1)
            time.sleep(0.2)
        
        self.console.print(f"\n[green]✓ Report generated: {filepath}[/green]\n")
    
    # Utility Commands
    
    def _cmd_help(self, args):
        """Display help information"""
        
        help_text = """
[bold cyan]═════════════════════════════════════════════════[/bold cyan]
[bold cyan]  SentinelCLI - Available Commands[/bold cyan]
[bold cyan]═════════════════════════════════════════════════[/bold cyan]

[bold]SYSTEM MONITORING:[/bold]
  [cyan]sysinfo[/cyan]     - Display system information (OS, CPU, RAM, Disk)
  [cyan]users[/cyan]       - Show connected users
  [cyan]startup[/cyan]     - Display top resource-consuming processes

[bold]NETWORK ANALYSIS:[/bold]
  [cyan]scan[/cyan]        - Scan local network for active hosts
  [cyan]ports[/cyan]       - List open ports and services
  [cyan]connections[/cyan] - Show active network connections

[bold]SECURITY MONITORING:[/bold]
  [cyan]watch[/cyan]       - Real-time security monitoring
  [cyan]threats[/cyan]     - Analyze threats and calculate security score
  [cyan]processes[/cyan]   - Analyze running processes

[bold]REPORTS:[/bold]
  [cyan]score[/cyan]       - Display security score with recommendations
  [cyan]export[/cyan]      - Generate and save security report as Markdown

[bold]OTHER:[/bold]
  [cyan]help[/cyan]        - Display this help message
  [cyan]clear[/cyan]       - Clear the screen
  [cyan]exit/quit[/cyan]   - Exit SentinelCLI

[bold cyan]═════════════════════════════════════════════════[/bold cyan]
        """
        self.console.print(help_text)
    
    def _cmd_clear(self, args):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def _cmd_exit(self, args):
        """Exit the program"""
        self.console.print("\n[yellow]Goodbye![/yellow]\n")
        sys.exit(0)


def main():
    """Main entry point"""
    
    try:
        cli = SentinelCLI()
        cli.run()
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
