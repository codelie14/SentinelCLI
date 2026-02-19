"""
Notifier - Send alerts via Slack, Discord, Teams, and Email
"""

import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Any, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


LEVEL_COLORS = {
    "INFO": 0x3498DB,      # blue
    "LOW": 0x2ECC71,       # green
    "MEDIUM": 0xF39C12,    # orange
    "HIGH": 0xE74C3C,      # red
    "CRITICAL": 0x8B0000,  # dark red
}


class Notifier:
    """Dispatches alerts to Slack, Discord, Teams, and Email"""

    def __init__(
        self,
        slack_webhook: str = "",
        discord_webhook: str = "",
        smtp_host: str = "",
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_password: str = "",
        email_to: str = "",
        threshold: str = "HIGH",
    ):
        self.slack_webhook = slack_webhook
        self.discord_webhook = discord_webhook
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.email_to = email_to
        self.threshold = threshold

    # ------------------------------------------------------------------ #
    #  Threshold check                                                     #
    # ------------------------------------------------------------------ #

    def _should_notify(self, level: str) -> bool:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            return order.index(level) >= order.index(self.threshold)
        except ValueError:
            return True

    # ------------------------------------------------------------------ #
    #  Slack                                                               #
    # ------------------------------------------------------------------ #

    def send_slack(self, message: str, level: str = "INFO") -> Dict[str, Any]:
        """Send a message to Slack via incoming webhook"""
        if not REQUESTS_AVAILABLE:
            return {"error": "requests not installed"}
        if not self.slack_webhook:
            return {"error": "Slack webhook not configured"}

        emoji = {"INFO": "ℹ️", "LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨"}.get(level, "🛡️")
        payload = {
            "text": f"{emoji} *SentinelCLI Alert [{level}]*",
            "attachments": [{
                "color": "#" + format(LEVEL_COLORS.get(level, 0x3498DB), "06x"),
                "text": message,
                "footer": f"SentinelCLI v1.2 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            }]
        }
        try:
            r = requests.post(self.slack_webhook, json=payload, timeout=10)
            return {"success": r.status_code == 200, "status_code": r.status_code}
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------ #
    #  Discord                                                             #
    # ------------------------------------------------------------------ #

    def send_discord(self, message: str, level: str = "INFO") -> Dict[str, Any]:
        """Send an embed to Discord via webhook"""
        if not REQUESTS_AVAILABLE:
            return {"error": "requests not installed"}
        if not self.discord_webhook:
            return {"error": "Discord webhook not configured"}

        emoji = {"INFO": "ℹ️", "LOW": "✅", "MEDIUM": "⚠️", "HIGH": "🔴", "CRITICAL": "🚨"}.get(level, "🛡️")
        payload = {
            "username": "SentinelCLI",
            "embeds": [{
                "title": f"{emoji} SentinelCLI Alert [{level}]",
                "description": message,
                "color": LEVEL_COLORS.get(level, 0x3498DB),
                "footer": {"text": f"SentinelCLI v1.2 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"},
            }]
        }
        try:
            r = requests.post(self.discord_webhook, json=payload, timeout=10)
            return {"success": r.status_code in (200, 204), "status_code": r.status_code}
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------ #
    #  Email                                                               #
    # ------------------------------------------------------------------ #

    def send_email(self, subject: str, body: str) -> Dict[str, Any]:
        """Send an email alert via SMTP"""
        if not self.smtp_host or not self.email_to:
            return {"error": "SMTP not configured"}

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[SentinelCLI] {subject}"
            msg["From"] = self.smtp_user
            msg["To"] = self.email_to
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.smtp_user, self.email_to, msg.as_string())
            return {"success": True}
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------ #
    #  Unified notify                                                      #
    # ------------------------------------------------------------------ #

    def notify_threat(self, level: str, title: str, details: str) -> Dict[str, Any]:
        """Send alert to all configured channels if level >= threshold"""
        if not self._should_notify(level):
            return {"skipped": True, "reason": f"Level {level} below threshold {self.threshold}"}

        message = f"**{title}**\n{details}"
        results = {}

        if self.slack_webhook:
            results["slack"] = self.send_slack(message, level)
        if self.discord_webhook:
            results["discord"] = self.send_discord(message, level)
        if self.smtp_host and self.email_to:
            results["email"] = self.send_email(f"[{level}] {title}", f"{title}\n\n{details}")

        return {
            "level": level,
            "channels_notified": list(results.keys()),
            "results": results,
            "timestamp": datetime.now().isoformat(),
        }

    def test_all_channels(self) -> Dict[str, Any]:
        """Send a test message to all configured channels"""
        return self.notify_threat(
            level="INFO",
            title="SentinelCLI Test Notification",
            details="This is a test notification from SentinelCLI v1.2. All systems operational.",
        )
