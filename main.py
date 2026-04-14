"""
main.py — BugHunter Pro v2.0 (Orchestration Engine)
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime

from utils import banner, log, Colors, ensure_dirs, validate_domain, ProgressBar
from core import PipelineContext, validate_module, PipelineConfig, DependencyGuard
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

        # 1. Initialize Config & Dependencies (Centralized)
        self.config = PipelineConfig(args)
        self.deps   = DependencyGuard()
        
        # 2. Pre-flight Check (Fail Fast)
        self._preflight_check()

        # 3. Initialize Context
        scope = self._load_scope(args.scope) if args.scope else [args.target]
        self.context = PipelineContext(args.target, scope, self.output, self.config, self.deps)
        
        # 4. Initialize Engines
        self.recon = ReconEngine(self.output)
        self.filter = FilterPipeline(self.output)
        self.cve = CVEMapper(self.output)
        self.fuzzer = FuzzingEngine(self.output)
        self.exploiter = ExploitEngine(self.output)
        self.notifier = Notifier(args)
        self.reporter = ReportEngine(self.output, args.target)

        # 5. Validate Module Contracts
        self._validate_contracts()

    def _load_scope(self, scope_file: str) -> list:
        try:
            with open(scope_file) as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception:
            return []

    def _preflight_check(self):
        """Validates environment and critical dependencies."""
        log("[*] Performing dependency pre-flight check...", Colors.CYAN)
        required = ["httpx", "nuclei", "subfinder"]
        missing = [t for t in required if not self.deps.has_tool(t)]
        if missing:
            log(f"[!] Warning: Missing critical tools: {', '.join(missing)}", Colors.YELLOW)
            log("[!] Some stages may be skipped or use slower fallbacks.", Colors.YELLOW)

    def _validate_contracts(self):
        """Strict validation of module signatures."""
        modules = [self.recon, self.filter, self.cve, self.fuzzer, self.exploiter]
        for mod in modules:
            validate_module(mod)

    def _get_pb(self, stage: int, name: str, tasks: int):
        return ProgressBar(stage, name, tasks)

    def run(self):
        banner()
        log(f"[*] Engine    : BugHunter Pro v2.0 (Self-Healing Mode)", Colors.CYAN)
        log(f"[*] Target    : {self.context.target}", Colors.CYAN)
        log(f"[*] Scope     : {len(self.context.scope)} domain(s)", Colors.CYAN)
        log(f"[*] Threads   : {self.config.threads}", Colors.CYAN)
        log(f"[*] Workspace : {self.output}\n", Colors.CYAN)

        try:
            # ── 1. Subdomain Discovery ────────────
            pb = self._get_pb(1, "Subdomain Discovery", len(self.context.scope))
            discovery_out = self.recon.run_discovery(None, self.context, pb)
            subdomains = discovery_out.data
            pb.complete(f"Found {discovery_out.stats.get('total', 0)} subdomains")

            # ── 2. Asset Monitoring ───────────────
            pb = self._get_pb(2, "Asset Monitoring", 1)
            assets_out = self.recon.track_assets(subdomains, self.context, pb)
            pb.complete(f"Detected {assets_out.stats.get('new', 0)} NEW | {assets_out.stats.get('removed', 0)} REMOVED")

            # ── 3. Intelligence Filtering ──────────
            pb = self._get_pb(3, "Intelligence Filtering", len(subdomains))
            filter_out = self.filter.run(subdomains, self.context, pb)
            filtered_subs = filter_out.data
            pb.complete(f"Filtered {filter_out.stats.get('clean_count', 0)} high-quality assets")

            # ── 4. Liveness Probing ───────────────
            pb = self._get_pb(4, "Liveness Probing", len(filtered_subs))
            alive_out = self.recon.run_alive_check(filtered_subs, self.context, pb)
            alive = alive_out.data
            pb.complete(f"{alive_out.stats.get('alive', 0)} hosts are ALIVE")

            # ── 5. Tech Detection ─────────────────
            pb = self._get_pb(5, "Technology Detection", len(alive))
            tech_out = self.recon.run_tech_detect(alive, self.context, pb)
            tech_map = tech_out.meta.get("tech_map", {})
            self.context.metadata["tech_map"] = tech_map
            pb.complete(f"Fingerprinted {tech_out.stats.get('tech_detected', 0)} endpoints")

            # ── 6. Scoring & Ranking ───────────────
            pb = self._get_pb(6, "Quality Scoring & Ranking", len(alive))
            ranking_out = self.filter.score_and_rank(alive, tech_map, self.context, pb)
            ranked = ranking_out.data
            top_targets = [t for t in ranked if t["score"] >= 40]
            pb.complete(f"Identified {ranking_out.stats.get('high_value', 0)} high-value attack surfaces")

            # ── 7. Port Scanning ──────────────────
            pb = self._get_pb(7, "Smart Port Scanning", len(top_targets))
            targets_urls = [t["url"] for t in top_targets]
            port_out = self.recon.run_port_scan(targets_urls, self.context, pb)
            pb.complete(f"Port audit finished for {port_out.stats.get('scanned', 0)} targets")

            # ── 8. Vulnerability Scanning ─────────
            findings = []
            if not self.args.no_nuclei:
                pb = self._get_pb(8, "Vulnerability Scanning", len(top_targets))
                vuln_out = self.recon.run_nuclei(targets_urls, self.context, pb)
                findings = vuln_out.data
                pb.complete(f"Nuclei found {vuln_out.stats.get('vulnerabilities', 0)} potential vulns")

            # ── 9. CVE Intelligence Mapping ───────
            mapped_findings = []
            if findings:
                pb = self._get_pb(9, "CVE Intelligence Mapping", len(findings))
                cve_out = self.cve.run(findings, self.context, pb)
                mapped_findings = cve_out.data
                pb.complete(f"Mapped {cve_out.stats.get('mapped_findings', 0)} actionable CVEs")

            # ── 10. JS Link Extraction ──────────
            pb = self._get_pb(10, "JS Link Extraction", len(top_targets))
            js_out = self.recon.run_js_extraction(targets_urls, self.context, pb)
            js_links = js_out.data
            pb.complete(f"Extracted {js_out.stats.get('endpoints', 0)} deep links")

            # ── 11. Smart Fuzzing ─────────────────
            fuzz_results = []
            if not self.args.no_fuzzing:
                pb = self._get_pb(11, "Targeted API Fuzzing", len(top_targets))
                fuzz_out = self.fuzzer.run(top_targets, self.context, pb)
                fuzz_results = fuzz_out.data
                pb.complete(f"Fuzzing cycle fuzzed {fuzz_out.stats.get('fuzzed_endpoints', 0)} endpoints")

            # ── 12. Exploit Audit ───────────────
            exploit_results = []
            if not self.args.no_exploit:
                pb = self._get_pb(12, "Exploit Intelligence Audit", len(top_targets))
                exploit_out = self.exploiter.run(top_targets, self.context, pb)
                exploit_results = exploit_out.data
                pb.complete(f"Exploit audit found {exploit_out.stats.get('vulnerabilities', 0)} actionable items")

            # ── 13. Final Report Generation ───────
            pb = self._get_pb(13, "Intelligence Reporting", 1)
            report_path = self.reporter.generate(exploit_results, ranked, [])
            self.notifier.send_summary(ranked, exploit_results)
            pb.complete(f"All updates pushed. Report: {report_path}")

        except KeyboardInterrupt:
            log("\n[!] Execution interrupted by user.", Colors.YELLOW)
            sys.exit(0)
        except Exception as e:
            log(f"[FATAL] Global pipeline crash: {e}", Colors.RED)
            import traceback
            traceback.print_exc()
            sys.exit(1)


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
    parser.add_argument("--seclists-path", default="", help="Path to Seclists directory")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if not validate_domain(args.target):
        log(f"Invalid domain: {args.target}", Colors.RED)
        sys.exit(1)
    
    hunter = BugHunterPro(args)
    hunter.run()
