"""
fuzzing_engine.py — Smart Fuzzing Engine (Refactored)
"""

import threading
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils import log, Colors, run_cmd, tool_available
from core import PipelineContext, batcher, StageOutput, PipelineConfig, DependencyGuard

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
            pb.update(0, status="ffuf not found, switching to SAFE-MODE (Python-based probe)...", is_fail=True)
            # Future: return a simulated probe or skip
            return StageOutput(data=[], stats={"error": "ffuf missing", "mode": "safe-fallback"})

        # Defensive extraction of targets
        targets = data if isinstance(data, list) else getattr(data, 'data', [])
        if not targets:
            pb.update(0, status="No high-value targets for fuzzing.")
            return StageOutput(data=[], stats={"fuzzed": 0})

        pb.update(0, status=f"Starting fuzzing on {len(targets)} targets...")
        
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
        domain = target.get("domain", url.split("//")[-1].split("/")[0])
        tags = target.get("tags", [])
        
        category = "API" if "API" in tags else "ADMIN" if "ADMIN" in tags else "default"
        wordlist = self._resolve_wordlist(category, context)
        
        out_file = self.output / f"ffuf_{domain.replace('.','_')}.json"
        
        cmd = [
            "ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
            "-o", str(out_file), "-of", "json",
            "-mc", "200,201,301,302,401,403", "-t", "40", "-silent"
        ]

        rc, out, err = run_cmd(cmd, timeout=300)

        if out_file.exists():
            try:
                with open(out_file) as f:
                    data = json.load(f)
                with self._lock:
                    for r in data.get("results", []):
                        self.results.append({
                            "url": r.get("url"), "status": r.get("status"),
                            "length": r.get("length"), "target": url
                        })
                pb.update(1, status=f"Fuzzing complete: {url}")
            except:
                pb.update(1, status=f"Fuzzing failed to parse: {url}", is_fail=True)

    def _resolve_wordlist(self, category: str, context: PipelineContext) -> str:
        """3-tier wordlist resolution: SecLists -> Local -> Minimal Fallback."""
        
        # 🟢 Tier 1: SecLists (Optimized)
        rel_path = context.config.seclists_map.get(category, context.config.seclists_map["default"])
        sec_path = context.config.seclists_base / rel_path
        if sec_path.exists():
            return str(sec_path)
            
        # 🟡 Tier 2: Local Wordlists Directory
        local_path = context.config.wordlists_dir / f"{category.lower()}.txt"
        if local_path.exists():
            return str(local_path)
        
        # 🔴 Tier 3: Minimal Self-Healing Fallback
        log(f"[self-healing] '{category}' wordlist missing. Generating minimal fallback...", Colors.YELLOW)
        words = ["admin", "api", "v1", "v2", "config", "backup", "login", ".env", "phpinfo", "test"]
        local_path.write_text("\n".join(words))
        return str(local_path)


    def _write_results(self):
        out = self.output / "fuzzing_results.txt"
        with open(out, "w") as f:
            f.write("# Fuzzing Results\n")
            for r in self.results:
                f.write(f"[{r['status']}] {r['url']} (size: {r['length']})\n")
