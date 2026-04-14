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

    def _stage(self, stage_num: int, name: str, total_tasks: int = 1):
        """Initialize a new stage with a Progress Bar."""
        from utils import ProgressBar
        if hasattr(self, 'pb') and self.pb:
            self.pb.complete()
        
        self.pb = ProgressBar(stage_num, name, total_tasks, total_stages=17)
        return self.pb

    # ── MAIN RUN ────────────────────────────
    def run(self):
        banner()
        log(f"[*] Target  : {self.target}", Colors.CYAN)
        log(f"[*] Scope   : {len(self.scope)} domain(s)", Colors.CYAN)
        log(f"[*] Target: {self.target}", Colors.CYAN)
        log(f"[*] Scope:  {len(self.scope)} domains", Colors.CYAN)
        log(f"[*] Output: {self.output}\n", Colors.CYAN)

        # ── 1. Subdomain discovery ────────────
        pb = self._stage(1, "Subdomain Discovery", len(self.scope))
        subdomains = self.recon.discover_subdomains()
        pb.complete(f"Found {len(subdomains)} subdomains")

        # ── 2. Monitor changes ────────────────
        pb = self._stage(2, "Asset Change Detection", 1)
        new_assets = self.recon.monitor_changes(subdomains)
        pb.complete("Analyzed historical data")

        # ── 3. Wildcard & Noise filtering ──────
        from intelligence_filter import FilterPipeline
        filter_pipeline = FilterPipeline(self.output)
        
        pb = self._stage(3, "Wildcard & Noise Filtering", len(subdomains))
        filter_stats, filtered_subs = filter_pipeline.run(subdomains, pb=pb)
        pb.complete("Filtering complete")

        # ── 4. Alive check ────────────────────
        pb = self._stage(4, "Alive Check (HTTP Probing)", len(filtered_subs))
        alive = self.recon.alive_check(filtered_subs, pb=pb)
        pb.complete(f"{len(alive)} hosts alive")

        # ── 5. Tech detection ─────────────────
        pb = self._stage(5, "Technology Detection", len(alive))
        tech_map = self.recon.detect_tech(alive, pb=pb)
        pb.complete("Fingerprinting finished")

        # ── 6. Quality Scoring & Ranking ────────
        pb = self._stage(6, "Quality Scoring & Ranking", len(alive))
        ranked_targets = filter_pipeline.score_and_rank(alive, tech_map, pb=pb)
        filter_pipeline.generate_report(filter_stats, ranked_targets)
        top_urls = [t["url"] for t in ranked_targets if t["label"] in ("HIGH VALUE", "MEDIUM VALUE")]
        if not top_urls:
            log("[!] No high/medium value targets. Falling back to all alive.", Colors.YELLOW)
            top_urls = alive
        else:
            log(f"[+] Reduced {len(alive)} alive targets down to {len(top_urls)} meaningful assets", Colors.GREEN)
        alive = top_urls
        pb.complete("Ranking finished")

        # ── 7. Wayback endpoints ──────────────
        pb = self._stage(7, "Wayback Machine Historical Endpoints", len(self.scope))
        wayback_urls = []
        for domain in self.scope:
            wayback_urls.extend(self.recon.wayback_endpoints(domain))
            pb.update(1, status=f"Fetched {domain}")
        pb.complete(f"Collected {len(wayback_urls)} URLs")

        # ── 8. Port scan ──────────────────────
        pb = self._stage(8, "Smart Port Scan (nmap)", len(alive))
        port_data = self.recon.port_scan(alive, pb=pb)
        pb.complete("Port scan complete")

        # ── 9. Vuln scan ──────────────────────
        pb = self._stage(9, "Vulnerability Scan (nuclei)", len(alive))
        if not getattr(self.args, "no_nuclei", False):
            pb.update(0, status="Starting nuclei engine...")
            nuclei_findings = self.recon.nuclei_scan(alive)
            pb.update(len(alive), status="Nuclei scan complete")
            
            # --- NEW: CVE Mapping & Exploit Intelligence ---
            log("\n[*] Initializing CVE Mapping & Exploit Intelligence Engine...", Colors.CYAN)
            from cve_mapper import CVEMapper
            cve_mapper = CVEMapper(self.output)
            cve_mapped_findings = cve_mapper.process(nuclei_findings)
        else:
            nuclei_findings = []
            log("[*] Nuclei scan skipped (--no-nuclei)", Colors.YELLOW)
        pb.complete("Vuln scan complete")

        # ── 10. Screenshots ────────────────────
        pb = self._stage(10, "Screenshots (gowitness/eyewitness)", 1)
        if not getattr(self.args, "no_screenshots", False):
            pb.update(0, status="Capturing screenshots...")
            self.recon.screenshot(alive)
        else:
            log("[*] Screenshots skipped (--no-screenshots)", Colors.YELLOW)
        pb.complete("Screenshots captured")

        # ── 11. JS endpoint extraction ─────────
        pb = self._stage(11, "JS Endpoint Extraction", len(alive))
        js_endpoints = self.recon.extract_js_endpoints(alive, pb=pb)
        pb.complete(f"Found {len(js_endpoints)} endpoints")

        # ── 12. Intelligence analysis ──────────
        pb = self._stage(12, "Intelligence Analysis & Risk Scoring", 1)
        scored = self.intel.analyze(alive, port_data, nuclei_findings, tech_map, [])
        high_value = [t for t in scored if t["score"] >= 60]
        pb.complete("Analysis complete")

        # ── 13. Learning engine ────────────────
        pb = self._stage(13, "Learning Engine Update", 1)
        self.learner.update(scored)
        pattern_hits = self.learner.match_patterns(scored)
        pb.complete("Patterns updated")

        # ── 14. Prioritization ────────────────
        pb = self._stage(14, "Target Prioritization", 1)
        prioritized = self.intel.prioritize(scored, pattern_hits)
        self._write_prioritized(prioritized)
        pb.complete("Prioritization complete")

        # ── 15. Payload & scenario engine ──────
        pb = self._stage(15, "Payload & Scenario Engine", len(prioritized))
        self.payloads.generate(prioritized, tech_map)
        pb.complete("Payloads generated")

        # ── 16. Smart Fuzzing ─────────────────
        pb = self._stage(16, "Smart Fuzzing (ffuf)", len(prioritized))
        if not getattr(self.args, "no_fuzzing", False):
            min_score = getattr(self.args, "min_score", 60)
            fuzz_targets = [t for t in prioritized if t["score"] >= min_score and
                            any(tag in t.get("tags", []) for tag in ["API", "ADMIN", "DEV"])]
            self.fuzzer.run(fuzz_targets, tech_map, pb=pb)
        else:
            log("[*] Fuzzing skipped (--no-fuzzing)", Colors.YELLOW)
        pb.complete("Fuzzing complete")

        # ── 17. Burp, Exploit & Report ──────────
        pb = self._stage(17, "Burp, Exploit & Report", 1)
        self.burp.export(high_value)
        
        exploit_results = []
        if not getattr(self.args, "no_exploit", False):
            exploit_results = self.exploiter.run(prioritized, tech_map, pb=pb)
            # Record confirmed vulns in learning engine
            for result in exploit_results:
                sev = result.get("severity", "")
                if sev in ("CRITICAL", "HIGH"):
                    self.learner.record_vuln(
                        result.get("type", "Unknown"),
                        result.get("url", ""),
                        sev
                    )
        else:
            log("[*] Exploit checks skipped (--no-exploit)", Colors.YELLOW)
        
        report_path = self.reporter.generate(exploit_results, prioritized, pattern_hits)
        pb.complete(f"Analysis complete. Report: {report_path}")

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
