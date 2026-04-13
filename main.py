"""
main.py — BugHunter Pro  v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pipeline Orchestrator — 17 stages

LEGAL NOTICE:
  Use ONLY on targets you have explicit written permission to test.
  Unauthorized scanning is illegal. This tool is for authorized
  bug bounty programs and security research only.
"""

import argparse
import sys
import os
import json
from datetime import datetime
from pathlib import Path

from utils import banner, log, Colors, ensure_dirs, validate_domain
from recon import ReconEngine
from intelligence import IntelligenceEngine
from learning_engine import LearningEngine
from fuzzing_engine import FuzzingEngine
from burp_integration import BurpIntegration
from exploit_engine import ExploitEngine
from payloads_engine import PayloadsEngine
from notifier import Notifier
from report_engine import ReportEngine


# ─────────────────────────────────────────────
#  Pipeline Orchestrator
# ─────────────────────────────────────────────

class BugHunterPro:
    def __init__(self, args):
        self.args   = args
        self.target = args.target
        self.scope  = self._load_scope(args.scope) if args.scope else [args.target]
        self.output = Path(args.output)

        ensure_dirs(self.output)

        self.recon      = ReconEngine(
            self.scope, self.output,
            shodan_key=getattr(args, "shodan_key", ""),
            threads=args.threads
        )
        self.intel      = IntelligenceEngine(self.output)
        self.learner    = LearningEngine(self.output / "knowledge" / "knowledge_base.json")
        self.fuzzer     = FuzzingEngine(self.output)
        self.burp       = BurpIntegration(
            self.output,
            host=args.burp_host,
            port=args.burp_port
        )
        self.exploiter  = ExploitEngine(self.output)
        self.payloads   = PayloadsEngine(self.output)
        self.notifier   = Notifier(args)
        self.reporter   = ReportEngine(self.output, self.target)

    # ── helpers ─────────────────────────────
    def _load_scope(self, scope_file: str) -> list:
        with open(scope_file) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]

    def _stage(self, name: str):
        log(f"\n{'─'*60}", color=Colors.CYAN)
        log(f"  STAGE: {name}", color=Colors.BOLD)
        log(f"{'─'*60}", color=Colors.CYAN)

    # ── MAIN RUN ────────────────────────────
    def run(self):
        banner()
        log(f"[*] Target  : {self.target}", Colors.CYAN)
        log(f"[*] Scope   : {len(self.scope)} domain(s)", Colors.CYAN)
        log(f"[*] Output  : {self.output}", Colors.CYAN)
        log(f"[*] Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Colors.CYAN)
        log(f"[*] Version : v2.0 — {self._count_checks()} check types", Colors.CYAN)

        # ── 1. Recon — Subdomain Discovery ────
        self._stage("1 / 17 — Subdomain Discovery (subfinder + amass + crt.sh + dnsx + Wayback)")
        subdomains = self.recon.discover_subdomains()
        log(f"[+] Found {len(subdomains)} subdomains", Colors.GREEN)

        # ── 2. Monitor changes ────────────────
        self._stage("2 / 17 — Asset Monitoring (diff)")
        new_assets = self.recon.monitor_changes(subdomains)
        log(f"[+] {len(new_assets)} NEW assets detected", Colors.YELLOW)

        # ── 3. Wayback endpoints ──────────────
        self._stage("3 / 17 — Wayback Machine Historical Endpoints")
        wayback_urls = []
        for domain in self.scope:
            wayback_urls.extend(self.recon.wayback_endpoints(domain))
        log(f"[+] {len(wayback_urls)} historical URLs from Wayback", Colors.GREEN)

        # ── 4. Alive check ────────────────────
        self._stage("4 / 17 — Alive Check (httpx)")
        alive = self.recon.alive_check(subdomains)
        log(f"[+] {len(alive)} alive hosts", Colors.GREEN)

        # ── 5. Port scan ──────────────────────
        self._stage("5 / 17 — Smart Port Scan (nmap — 40 ports)")
        port_data = self.recon.port_scan(alive)

        # ── 6. Vuln scan ──────────────────────
        self._stage("6 / 17 — Vulnerability Scan (nuclei — all severities)")
        if not getattr(self.args, "no_nuclei", False):
            nuclei_findings = self.recon.nuclei_scan(alive)
        else:
            nuclei_findings = []
            log("[*] Nuclei scan skipped (--no-nuclei)", Colors.YELLOW)

        # ── 7. Screenshots ────────────────────
        self._stage("7 / 17 — Screenshots (gowitness / eyewitness)")
        if not getattr(self.args, "no_screenshots", False):
            self.recon.screenshot(alive)
        else:
            log("[*] Screenshots skipped (--no-screenshots)", Colors.YELLOW)

        # ── 8. Tech detection ─────────────────
        self._stage("8 / 17 — Technology Detection (25 signatures)")
        tech_map = self.recon.detect_tech(alive)

        # ── 9. JS endpoint extraction ─────────
        self._stage("9 / 17 — JavaScript Endpoint Extraction")
        js_endpoints = self.recon.extract_js_endpoints(alive)
        log(f"[+] {len(js_endpoints)} endpoints found in JS files", Colors.GREEN)

        # ── 10. Intelligence analysis ──────────
        self._stage("10 / 17 — Intelligence Analysis & Risk Scoring")
        scored = self.intel.analyze(alive, port_data, nuclei_findings, tech_map, new_assets)
        high_value = [t for t in scored if t["score"] >= 60]
        log(f"[+] {len(high_value)} HIGH-VALUE targets (score ≥ 60)", Colors.RED)

        # ── 11. Learning engine ────────────────
        self._stage("11 / 17 — Learning Engine Update")
        self.learner.update(scored)
        pattern_hits = self.learner.match_patterns(scored)
        log(f"[+] {len(pattern_hits)} pattern matches from previous bugs", Colors.MAGENTA)
        self.learner.print_stats()

        # ── 12. Prioritization ────────────────
        self._stage("12 / 17 — Target Prioritization")
        prioritized = self.intel.prioritize(scored, pattern_hits)
        self._write_prioritized(prioritized)

        # ── 13. Payload & scenario engine ──────
        self._stage("13 / 17 — Payload & Scenario Engine")
        self.payloads.generate(prioritized, tech_map)

        # ── 14. Fuzzing ───────────────────────
        self._stage("14 / 17 — Smart Fuzzing (ffuf + SecLists)")
        if not getattr(self.args, "no_fuzzing", False):
            min_score = getattr(self.args, "min_score", 60)
            fuzz_targets = [t for t in prioritized if t["score"] >= min_score and
                            any(tag in t.get("tags", []) for tag in ["API", "ADMIN", "DEV"])]
            self.fuzzer.run(fuzz_targets, tech_map)
        else:
            log("[*] Fuzzing skipped (--no-fuzzing)", Colors.YELLOW)

        # ── 15. Burp integration ──────────────
        self._stage("15 / 17 — Burp Suite Integration")
        self.burp.export(high_value)

        # ── 16. Safe exploit checks ───────────
        self._stage("16 / 17 — Safe Exploit Checks v2.0 (24 check types)")
        if not getattr(self.args, "no_exploit", False):
            exploit_results = self.exploiter.run(prioritized, tech_map)
            # ✅ FIX: Record confirmed vulns in learning engine
            for result in exploit_results:
                sev = result.get("severity", "")
                if sev in ("CRITICAL", "HIGH"):
                    self.learner.record_vuln(
                        result.get("type", "Unknown"),
                        result.get("url", ""),
                        sev
                    )
        else:
            exploit_results = []
            log("[*] Exploit checks skipped (--no-exploit)", Colors.YELLOW)

        # ── 17. HTML Report ───────────────────
        self._stage("17 / 17 — Generating HTML Report")
        report_path = self.reporter.generate(exploit_results, prioritized, pattern_hits)

        # ── Final report ──────────────────────
        self._final_report(prioritized, exploit_results, pattern_hits)
        self.notifier.send_summary(prioritized, exploit_results)

        log(f"\n[✓] HTML Report: {report_path}", Colors.CYAN)

    # ── writers ─────────────────────────────
    def _write_prioritized(self, targets: list):
        path = self.output / "prioritized_targets.txt"
        with open(path, "w") as f:
            f.write("# BugHunter Pro v2.0 — Prioritized Targets\n")
            f.write(f"# Generated: {datetime.now()}\n\n")
            for t in targets:
                tags = " ".join(f"[{tag}]" for tag in t.get("tags", []))
                f.write(f"[{t['score']:>3}] {t['url']:<50} {tags}\n")
        log(f"[+] prioritized_targets.txt written ({len(targets)} targets)", Colors.GREEN)

    def _final_report(self, targets, exploits, patterns):
        log(f"\n{'═'*60}", Colors.BOLD)
        log("  🔥 FINAL REPORT — BugHunter Pro v2.0", Colors.BOLD)
        log(f"{'═'*60}", Colors.BOLD)

        highs = [t for t in targets if t["score"] >= 80]
        meds  = [t for t in targets if 60 <= t["score"] < 80]

        log(f"\n  🔥 HIGH VALUE TARGETS   : {len(highs)}", Colors.RED)
        for t in highs[:5]:
            log(f"     ↳ [{t['score']}] {t['url']}", Colors.RED)

        log(f"\n  ⚡ READY FOR FUZZING     : {len(meds)}", Colors.YELLOW)

        # Count by severity
        sev_counts = {}
        for e in exploits:
            sev = e.get("severity", "INFO")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        log(f"\n  💣 VULNERABILITIES FOUND : {len(exploits)}", Colors.MAGENTA)
        for sev, count in sorted(sev_counts.items(),
                                  key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x[0])
                                  if x[0] in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99):
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                    "LOW": "🟢", "INFO": "⚪"}.get(sev, "⚪")
            log(f"     ↳ {icon} {sev}: {count}", Colors.MAGENTA)

        log(f"\n  🧠 PATTERN MATCHES       : {len(patterns)}", Colors.CYAN)

        out_files = [
            "report.html",
            "prioritized_targets.txt",
            "recommendations.txt",
            "fuzzing_results.txt",
            "burp_targets.txt",
            "exploit_results.txt",
            "exploit_results.json",
            "payloads.txt",
            "scenarios.txt",
            "attack_suggestions.txt",
            "js_endpoints.txt",
            "wayback_urls.txt",
        ]
        log(f"\n  📁 OUTPUT FILES:", Colors.CYAN)
        for f in out_files:
            p = self.output / f
            if p.exists():
                size = p.stat().st_size
                log(f"     ↳ {p}  ({size:,} bytes)", Colors.CYAN)

        log(f"\n[✓] Done — {datetime.now().strftime('%H:%M:%S')}\n", Colors.GREEN)

    @staticmethod
    def _count_checks():
        return 24  # exploit_engine v2.0 check types


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="BugHunter Pro v2.0 — Advanced Bug Bounty Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t example.com
  python main.py -t example.com -s scope.txt -o ./results
  python main.py -t example.com --threads 20 --min-score 70
  python main.py -t example.com --shodan-key YOUR_KEY
  python main.py -t example.com --notify-slack https://hooks.slack.com/...
  python main.py -t example.com --no-screenshots --no-nuclei --no-fuzzing
        """,
    )
    # Core
    parser.add_argument("-t", "--target",       required=True,  help="Primary target domain")
    parser.add_argument("-s", "--scope",        default=None,   help="Scope file (one domain per line)")
    parser.add_argument("-o", "--output",       default="outputs", help="Output directory (default: outputs/)")
    parser.add_argument("--threads",            type=int, default=10, help="Thread count (default: 10)")
    parser.add_argument("--min-score",          type=int, default=60, help="Min score for fuzzing (default: 60)")

    # Skip flags
    parser.add_argument("--no-screenshots",    action="store_true", help="Skip screenshots")
    parser.add_argument("--no-nuclei",         action="store_true", help="Skip Nuclei scan")
    parser.add_argument("--no-fuzzing",        action="store_true", help="Skip ffuf fuzzing")
    parser.add_argument("--no-exploit",        action="store_true", help="Skip exploit checks")

    # Integrations
    parser.add_argument("--burp-host",         default="127.0.0.1",  help="Burp proxy host")
    parser.add_argument("--burp-port",         type=int, default=8080, help="Burp proxy port")
    parser.add_argument("--shodan-key",        default="",    help="Shodan API key (optional)")

    # Notifications
    parser.add_argument("--notify-slack",      default=None,  help="Slack webhook URL")
    parser.add_argument("--notify-discord",    default=None,  help="Discord webhook URL")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if not validate_domain(args.target):
        log(f"[!] Invalid domain: {args.target}", Colors.RED)
        sys.exit(1)

    hunter = BugHunterPro(args)
    try:
        hunter.run()
    except KeyboardInterrupt:
        log("\n[!] Interrupted by user", Colors.YELLOW)
        sys.exit(0)
