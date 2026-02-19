"""
Config & Mode commands - mode online/offline, config set/get/show
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel


class ConfigCommands:
    def __init__(self, config, sentinel_ref):
        self.config = config
        self.sentinel = sentinel_ref
        self.console = Console()

    # -----------------------------------------------------------------
    def cmd_mode(self, args):
        """Switch between offline and online mode"""
        if not args:
            mode = self.config.mode
            color = "cyan" if mode == "offline" else "green"
            self.console.print(Panel(
                f"[bold {color}]{mode.upper()}[/bold {color}]",
                title="Current Mode", border_style=color
            ))
            self.console.print("[dim]Usage: mode <offline|online>[/dim]\n")
            return

        target = args.strip().lower()
        if target not in ("offline", "online"):
            self.console.print("[red]Mode must be 'offline' or 'online'[/red]\n")
            return

        self.config.mode = target
        color = "cyan" if target == "offline" else "green"
        self.console.print(f"[bold {color}]✓ Switched to {target.upper()} mode[/bold {color}]")
        self.console.print(f"[dim]Prompt updated to [sentinel|{target}]>[/dim]\n")
        # Update the sentinel's prompt label
        self.sentinel.mode_label = target

    # -----------------------------------------------------------------
    def cmd_config(self, args):
        """Get/set configuration values"""
        if not args:
            self._show_config()
            return

        parts = args.strip().split(maxsplit=2)
        subcmd = parts[0].lower()

        if subcmd == "show":
            self._show_config()

        elif subcmd == "set" and len(parts) == 3:
            key, value = parts[1], parts[2]
            self._set_key(key, value)

        elif subcmd == "get" and len(parts) == 2:
            key = parts[1]
            val = self._resolve_key(key)
            self.console.print(f"[cyan]{key}[/cyan] = [bold]{val}[/bold]\n")

        else:
            self.console.print(
                "[yellow]Usage:[/yellow]\n"
                "  config show\n"
                "  config set <key> <value>\n"
                "  config get <key>\n\n"
                "[dim]Keys: virustotal_key, otx_key, slack_webhook, discord_webhook,\n"
                "       smtp_host, smtp_port, smtp_user, smtp_pass, email_to,\n"
                "       api_host, api_port, cloud_endpoint, notify_threshold,\n"
                "       high_risk_countries[/dim]\n"
            )

    # -----------------------------------------------------------------
    def _resolve_key(self, key):
        mapping = {
            "virustotal_key": ("api_keys", "virustotal"),
            "otx_key": ("api_keys", "otx"),
            "slack_webhook": ("notifications", "slack_webhook"),
            "discord_webhook": ("notifications", "discord_webhook"),
            "smtp_host": ("notifications", "smtp_host"),
            "smtp_port": ("notifications", "smtp_port"),
            "smtp_user": ("notifications", "smtp_user"),
            "smtp_pass": ("notifications", "smtp_password"),
            "email_to": ("notifications", "email_to"),
            "api_host": ("rest_api", "host"),
            "api_port": ("rest_api", "port"),
            "cloud_endpoint": ("cloud_backup", "endpoint_url"),
            "notify_threshold": ("notifications_threshold",),
        }
        path = mapping.get(key)
        if not path:
            return None
        return self.config.get(*path)

    def _set_key(self, key, value):
        mapping = {
            "virustotal_key": ("api_keys", "virustotal"),
            "otx_key": ("api_keys", "otx"),
            "slack_webhook": ("notifications", "slack_webhook"),
            "discord_webhook": ("notifications", "discord_webhook"),
            "smtp_host": ("notifications", "smtp_host"),
            "smtp_port": ("notifications", "smtp_port"),
            "smtp_user": ("notifications", "smtp_user"),
            "smtp_pass": ("notifications", "smtp_password"),
            "email_to": ("notifications", "email_to"),
            "api_host": ("rest_api", "host"),
            "api_port": ("rest_api", "port"),
            "cloud_endpoint": ("cloud_backup", "endpoint_url"),
            "notify_threshold": ("notifications_threshold",),
        }
        path = mapping.get(key)
        if not path:
            self.console.print(f"[red]Unknown config key: {key}[/red]\n")
            return
        # Convert port to int
        if "port" in key:
            try:
                value = int(value)
            except ValueError:
                pass
        self.config.set(*path, value)
        self.console.print(f"[green]✓ {key} updated[/green]\n")

    def _show_config(self):
        t = Table(title="SentinelCLI Configuration", show_header=True)
        t.add_column("Key", style="cyan")
        t.add_column("Value", style="green")

        def mask(v):
            return "***" + str(v)[-4:] if v and len(str(v)) > 6 else (v or "[not set]")

        t.add_row("mode", self.config.mode)
        t.add_row("virustotal_key", mask(self.config.get("api_keys", "virustotal")))
        t.add_row("otx_key", mask(self.config.get("api_keys", "otx")))
        t.add_row("slack_webhook", mask(self.config.get("notifications", "slack_webhook")))
        t.add_row("discord_webhook", mask(self.config.get("notifications", "discord_webhook")))
        t.add_row("smtp_host", self.config.get("notifications", "smtp_host") or "[not set]")
        t.add_row("email_to", self.config.get("notifications", "email_to") or "[not set]")
        t.add_row("api_host", str(self.config.get("rest_api", "host")))
        t.add_row("api_port", str(self.config.get("rest_api", "port")))
        t.add_row("cloud_endpoint", self.config.get("cloud_backup", "endpoint_url") or "[not set]")
        t.add_row("notify_threshold", str(self.config.get("notifications_threshold") or "HIGH"))
        self.console.print(t)
        self.console.print()
