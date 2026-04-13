"""
notifier.py — Notification Engine
Sends summaries to Slack and/or Discord webhooks.
"""

import json
import datetime
from typing import List, Dict, Optional

import requests

from utils import log, Colors


class Notifier:
    def __init__(self, args):
        self.slack_url   = getattr(args, "notify_slack",   None)
        self.discord_url = getattr(args, "notify_discord", None)
        self.target      = getattr(args, "target", "unknown")

    def send_summary(self, targets: List[Dict], exploits: List[Dict]):
        if not self.slack_url and not self.discord_url:
            return

        highs    = [t for t in targets if t["score"] >= 80]
        criticals = [e for e in exploits if e.get("severity") == "CRITICAL"]
        high_vulns= [e for e in exploits if e.get("severity") == "HIGH"]

        message = self._build_message(highs, criticals, high_vulns)

        if self.slack_url:
            self._send_slack(message)
        if self.discord_url:
            self._send_discord(message)

    def _build_message(self, highs, criticals, high_vulns) -> str:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        lines = [
            f"🔥 *BugHunter Pro — Scan Complete*",
            f"🎯 Target: `{self.target}`",
            f"🕐 Time: {ts}",
            f"",
            f"📊 *Results Summary:*",
            f"  • High-value targets: {len(highs)}",
            f"  • Critical findings: {len(criticals)}",
            f"  • High severity findings: {len(high_vulns)}",
        ]

        if criticals:
            lines += ["", "🔴 *CRITICAL Findings:*"]
            for e in criticals[:5]:
                lines.append(f"  • [{e['type']}] {e['url']}")

        if highs:
            lines += ["", "🟠 *Top Targets:*"]
            for t in highs[:5]:
                lines.append(f"  • [{t['score']}] {t['url']}")

        return "\n".join(lines)

    def _send_slack(self, message: str):
        try:
            payload = {"text": message, "mrkdwn": True}
            r = requests.post(self.slack_url, json=payload, timeout=10)
            if r.status_code == 200:
                log("[notify] ✅ Slack notification sent", Colors.GREEN)
            else:
                log(f"[notify] Slack error: {r.status_code}", Colors.YELLOW)
        except Exception as e:
            log(f"[notify] Slack failed: {e}", Colors.YELLOW)

    def _send_discord(self, message: str):
        try:
            payload = {"content": message}
            r = requests.post(self.discord_url, json=payload, timeout=10)
            if r.status_code in (200, 204):
                log("[notify] ✅ Discord notification sent", Colors.GREEN)
            else:
                log(f"[notify] Discord error: {r.status_code}", Colors.YELLOW)
        except Exception as e:
            log(f"[notify] Discord failed: {e}", Colors.YELLOW)
