"""
burp_integration.py — Burp Suite Integration
Exports high-value targets to burp_targets.txt.
Optionally proxies requests through Burp (127.0.0.1:8080).
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from utils import log, Colors


class BurpIntegration:
    def __init__(self, output: Path,
                 host: str = "127.0.0.1", port: int = 8080):
        self.output  = output
        self.proxy   = {"http": f"http://{host}:{port}",
                        "https": f"http://{host}:{port}"}
        self.burp_up = self._check_burp()

    def _check_burp(self) -> bool:
        try:
            r = requests.get("http://burpsuite/",
                             proxies=self.proxy, timeout=2, verify=False)
            log("[burp] ✅ Burp Suite proxy detected and active", Colors.GREEN)
            return True
        except Exception:
            log("[burp] Burp proxy not running — export only mode", Colors.YELLOW)
            return False

    def export(self, high_value_targets: List[Dict]):
        """Write burp_targets.txt with high-value URLs for manual testing."""
        out = self.output / "burp_targets.txt"

        with open(out, "w") as f:
            f.write("# BugHunter Pro — Burp Suite Targets\n")
            f.write(f"# Generated: {datetime.now()}\n")
            f.write("# Import: Burp > Target > Site Map > Load target list\n\n")

            f.write("[HIGH PRIORITY]\n")
            for t in high_value_targets:
                if t["score"] >= 80:
                    tags = ", ".join(t.get("tags", []))
                    f.write(f"{t['url']}  # score={t['score']} tags=[{tags}]\n")

            f.write("\n[MEDIUM PRIORITY]\n")
            for t in high_value_targets:
                if 60 <= t["score"] < 80:
                    tags = ", ".join(t.get("tags", []))
                    f.write(f"{t['url']}  # score={t['score']} tags=[{tags}]\n")

        log(f"[burp] burp_targets.txt written ({len(high_value_targets)} targets)", Colors.GREEN)

        # If Burp is running, send high-priority targets through proxy
        if self.burp_up:
            self._send_through_proxy([t for t in high_value_targets if t["score"] >= 80])

    def _send_through_proxy(self, targets: List[Dict]):
        """Send requests through Burp proxy so they appear in Burp history."""
        log(f"[burp] Sending {len(targets)} requests through Burp proxy...", Colors.CYAN)

        for t in targets:
            try:
                requests.get(
                    t["url"],
                    proxies=self.proxy,
                    verify=False,
                    timeout=10,
                    headers={"User-Agent": "BugHunterPro/1.0 (Authorized Testing)"}
                )
                log(f"[burp] ↳ Sent: {t['url']}", Colors.CYAN)
            except Exception as e:
                log(f"[burp] ↳ Failed: {t['url']} — {e}", Colors.YELLOW)
