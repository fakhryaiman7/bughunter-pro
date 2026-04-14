"""
fuzzing_engine.py — Smart Fuzzing Engine (Refactored) v2.0
"""

import threading
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils import log, Colors, run_cmd, tool_available, extract_domain
from core import PipelineContext, batcher, StageOutput, PipelineConfig, DependencyGuard, VulnerabilityValidator, Finding

class FuzzingEngine:
    def __init__(self, config: PipelineConfig, context: PipelineContext, deps: DependencyGuard):
        self.config = config
        self.context = context
        self.deps = deps
        self.output = context.output
        self.results: List[Dict] = []
        self._lock = threading.Lock()

    def run(self, data: Any, context: PipelineContext, pb=None) -> StageOutput:
        """Standard entry point."""
        if not context.deps.has_tool("ffuf"):
            pb.update(0, status="ffuf not found, skipping deep fuzzing...", is_fail=True)
            return StageOutput(data=[], stats={"error": "ffuf missing"})

        # Defensive extraction of targets
        targets = data if isinstance(data, list) else getattr(data, 'data', [])
        if not targets:
            pb.update(0, status="No high-value targets for fuzzing.")
            return StageOutput(data=[], stats={"fuzzed": 0})

        pb.update(0, status=f"Starting high-precision fuzzing on {len(targets)} targets...")
        
        batches = list(batcher(targets, size=5))
        pb.set_batch(0, len(batches))

        for i, batch in enumerate(batches):
            pb.set_batch(i + 1, len(batches))
            with ThreadPoolExecutor(max_workers=context.config.threads) as ex:
                futures = [ex.submit(self._fuzz_target, t, context, pb) for t in batch]
                for fut in as_completed(futures):
                    fut.result()

        self._write_results()
        return StageOutput(data=self.results, stats={"fuzzed_endpoints": len(self.results)})


    def _fuzz_target(self, target: Dict, context: PipelineContext, pb: Any):
        url = target["url"]
        domain = target.get("domain", extract_domain(url))
        tags = target.get("tags", [])
        
        pb.update(0, status=f"Fuzzing: {domain}")
        
        # 1. Baseline Profiling
        context.fetch_baseline(domain)
        
        category = "API" if "API" in tags else "ADMIN" if "ADMIN" in tags else "default"
        wordlist = self._resolve_wordlist(category, context)
        
        out_file = self.output / f"ffuf_{domain.replace('.','_')}.json"
        
        cmd = [
            "ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
            "-o", str(out_file), "-of", "json",
            "-mc", "200,201,301,302", "-t", "40", "-silent"
        ]

        rc, out, err = run_cmd(cmd, timeout=300)

        if out_file.exists():
            try:
                with open(out_file) as f:
                    data = json.load(f)
                
                raw_results = data.get("results", [])
                valid_results = []

                # 2. Intelligence Validation Gap (Probe discovered endpoints)
                for r in raw_results:
                    found_url = r.get("url")
                    if not found_url: continue
                    
                    try:
                        # Validation request
                        resp = context.session.get(found_url, timeout=5, verify=False)
                        v = VulnerabilityValidator.validate(resp, f"Discovered Endpoint ({category})", context)
                        
                        if v.confidence >= 60:
                            valid_results.append({
                                "url": v.url, "status": resp.status_code,
                                "length": len(resp.text), "confidence": v.confidence,
                                "reason": v.reason, "target": url
                            })
                            log(f"[{v.severity} | CONF: {v.confidence}%]", Colors.GREEN)
                            log(f"Discovered: {v.url} → {v.reason}", Colors.WHITE)
                    except:
                        continue

                with self._lock:
                    self.results.extend(valid_results)
                
                pb.update(1, status=f"Fuzzing complete: {domain}")
            except Exception as e:
                pb.update(1, status=f"Fuzzing failed for {domain}: {str(e)[:20]}", is_fail=True)

    def _resolve_wordlist(self, category: str, context: PipelineContext) -> str:
        """3-tier wordlist resolution: SecLists -> Local -> Minimal Fallback."""
        rel_path = context.config.seclists_map.get(category, context.config.seclists_map["default"])
        sec_path = context.config.seclists_base / rel_path
        if sec_path.exists():
            return str(sec_path)
            
        local_path = context.config.wordlists_dir / f"{category.lower()}.txt"
        if local_path.exists():
            return str(local_path)
        
        words = ["admin", "api", "v1", "v2", "config", "backup", "login", ".env", "phpinfo", "test"]
        local_path.write_text("\n".join(words))
        return str(local_path)

    def _write_results(self):
        out = self.output / "fuzzing_results.json"
        with open(out, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # Human readable summary
        readable = self.output / "fuzzing_summary.txt"
        with open(readable, "w") as f:
            f.write(f"# Fuzzing Summary ({datetime.now()})\n")
            for r in self.results:
                f.write(f"[{r['status']}] {r['url']} (CONF: {r['confidence']}% - {r['reason']})\n")
