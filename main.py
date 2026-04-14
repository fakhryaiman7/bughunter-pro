"""
main.py — BugHunter Pro v2.0 (Orchestration Engine)
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime

from utils import banner, log, Colors, ensure_dirs, validate_domain, ProgressBar
from core import PipelineContext, validate_module
from recon import ReconEngine
from intelligence_filter import FilterPipeline
from cve_mapper import CVEMapper
from fuzzing_engine import FuzzingEngine
from exploit_engine import ExploitEngine
from notifier import Notifier
from report_engine import ReportEngine

class BugHunterPro:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.output = Path(args.output)
        ensure_dirs(self.output)

        # 1. Initialize Context
        scope = self._load_scope(args.scope) if args.scope else [args.target]
        self.context = PipelineContext(args.target, scope, self.output, args)
        
        # 2. Initialize Engines
        self.recon = ReconEngine(self.output)
        self.filter = FilterPipeline(self.output)
        self.cve = CVEMapper(self.output)
        self.fuzzer = FuzzingEngine(self.output)
        self.exploiter = ExploitEngine(self.output)
        self.notifier = Notifier(args)
        self.reporter = ReportEngine(self.output, args.target)

        # 3. Validate Module Contracts (Fail Fast)
        self._validate_contracts()

    def _load_scope(self, scope_file: str) -> list:
        try:
            with open(scope_file) as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception:
            return []

    def _validate_contracts(self):
        """Strict validation of module signatures."""
        modules = [self.recon, self.filter, self.cve, self.fuzzer, self.exploiter]
        for mod in modules:
            validate_module(mod)

    def _get_pb(self, stage: int, name: str, tasks: int):
        return ProgressBar(stage, name, tasks)

    def run(self):
        banner()
        log(f"[*] Engine    : BugHunter Pro v2.0 (Production Grade)", Colors.CYAN)
        log(f"[*] Target    : {self.context.target}", Colors.CYAN)
        log(f"[*] Scope     : {len(self.context.scope)} domain(s)", Colors.CYAN)
        log(f"[*] Workspace : {self.output}\n", Colors.CYAN)

        try:
            # ── 1. Subdomain Discovery ────────────
            pb = self._get_pb(1, "Subdomain Discovery", len(self.context.scope))
            subdomains = self.recon.run_discovery(None, self.context, pb)
            pb.complete(f"Found {len(subdomains)} subdomains")

            # ── 2. Asset Monitoring ───────────────
            pb = self._get_pb(2, "Asset Monitoring", 1)
            assets = self.recon.track_assets(subdomains, self.context, pb)
            pb.complete("History audit finished")

            # ── 3. Intelligence Filtering ──────────
            pb = self._get_pb(3, "Intelligence Filtering", len(subdomains))
            stats, filtered_subs = self.filter.run(subdomains, self.context, pb)
            pb.complete(f"Filtered {len(filtered_subs)} high-quality assets")

            # ── 4. Liveness Probing ───────────────
            pb = self._get_pb(4, "Liveness Probing", len(filtered_subs))
            alive = self.recon.run_alive_check(filtered_subs, self.context, pb)
            pb.complete(f"{len(alive)} hosts are ALIVE")

            # ── 5. Tech Detection ─────────────────
            pb = self._get_pb(5, "Technology Detection", len(alive))
            tech_map = self.recon.run_tech_detect(alive, self.context, pb)
            self.context.metadata["tech_map"] = tech_map
            pb.complete("Fingerprinting finished")

            # ── 6. Scoring & Ranking ───────────────
            pb = self._get_pb(6, "Quality Scoring & Ranking", len(alive))
            ranked = self.filter.score_and_rank(alive, tech_map, self.context, pb)
            top_targets = [t for t in ranked if t["score"] >= 40]
            pb.complete(f"Identified {len(top_targets)} high-value attack surfaces")

            # ── 7. Port Scanning ──────────────────
            pb = self._get_pb(7, "Smart Port Scanning", len(top_targets))
            port_data = self.recon.run_port_scan([t["url"] for t in top_targets], self.context, pb)
            pb.complete("Port audit finished")

            # ── 8. Vulnerability Scanning ─────────
            pb = self._get_pb(8, "Vulnerability Scanning", len(top_targets))
            findings = []
            if not self.args.no_nuclei:
                findings = self.recon.run_nuclei([t["url"] for t in top_targets], self.context, pb)
            pb.complete(f"Nuclei found {len(findings)} potential vulns")

            # ── 9. CVE Intelligence Mapping ───────
            pb = self._get_pb(9, "CVE Intelligence Mapping", len(findings))
            mapped_cves = self.cve.run(findings, self.context, pb)
            pb.complete(f"Mapped {len(mapped_cves)} actionable CVEs")

            # ── 10. JS Link Extraction ──────────
            pb = self._get_pb(10, "JS Link Extraction", len(top_targets))
            js_links = self.recon.run_js_extraction([t["url"] for t in top_targets], self.context, pb)
            pb.complete(f"Extracted {len(js_links)} deep links")

            # ── 11. Smart Fuzzing ─────────────────
            pb = self._get_pb(11, "Targeted API Fuzzing", len(top_targets))
            if not self.args.no_fuzzing:
                self.fuzzer.run(top_targets, self.context, pb)
            pb.complete("Fuzzing cycle finished")

            # ── 12. Exploit Audit ───────────────
            pb = self._get_pb(12, "Exploit Intelligence Audit", len(top_targets))
            exploit_results = []
            if not self.args.no_exploit:
                exploit_results = self.exploiter.run(top_targets, self.context, pb)
            pb.complete("Exploit audit finished")

            # ── 13. Final Report Generation ───────
            pb = self._get_pb(13, "Intelligence Reporting", 1)
            report_path = self.reporter.generate(exploit_results, ranked, [])
            self.notifier.send_summary(ranked, exploit_results)
            pb.complete(f"All updates pushed. Report: {report_path}")

        except Exception as e:
            log(f"[FATAL] Global pipeline crash: {e}", Colors.RED)
            raise e

def parse_args():
    parser = argparse.ArgumentParser(description="BugHunter Pro v2.0")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-s", "--scope", default=None)
    parser.add_argument("-o", "--output", default="outputs")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--no-nuclei", action="store_true")
    parser.add_argument("--no-fuzzing", action="store_true")
    parser.add_argument("--no-exploit", action="store_true")
    parser.add_argument("--shodan-key", default="")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if not validate_domain(args.target):
        log(f"Invalid domain: {args.target}", Colors.RED)
        sys.exit(1)
    
    hunter = BugHunterPro(args)
    hunter.run()
