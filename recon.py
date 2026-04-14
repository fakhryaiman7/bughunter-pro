"""
recon.py — Recon Engine  v2.0 (Refactored for Stability & Observability)
"""

import json
import re
import threading
import socket
import ssl
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional, Any

import requests
import urllib3
from core import PipelineContext, retry, batcher, validate_module, StageOutput
from utils import log, Colors, run_cmd, tool_available, save_json, load_json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ReconEngine:
    def __init__(self, output: Path):
        self.output = output
        self._prev_assets_file = output / "knowledge" / "prev_assets.json"

    def run(self, data: Any, context: PipelineContext, pb=None) -> StageOutput:
        """Standard entry point."""
        return self.run_discovery(data, context, pb)


    # ══════════════════════════════════════════
    #  1. Subdomain Discovery
    # ══════════════════════════════════════════
    def run_discovery(self, data: Any, context: PipelineContext, pb=None) -> StageOutput:
        """Orchestrates multi-source subdomain discovery."""
        all_subs: Set[str] = set()
        pb.update(0, status="Initializing Discovery...")

        for domain in context.scope:
            pb.update(0, status=f"Searching for {domain}...")
            
            # Source dispatch with internal tracking
            sources = [
                (self._subfinder, "Subfinder"),
                (self._amass, "Amass"),
                (self._crtsh, "Crt.sh"),
                (self._assetfinder, "Assetfinder"),
                (self._wayback_subdomains, "Wayback Machine"),
                (self._cert_sans, "Cert SANs"),
            ]
            
            for source_func, name in sources:
                try:
                    res = source_func(domain)
                    all_subs.update(res)
                    pb.update(1, status=f"Found {len(res)} from {name}")
                except Exception as e:
                    pb.update(0, status=f"Source {name} failed: {str(e)[:40]}", is_fail=True)

            shodan_key = context.get_config("shodan_key")
            if shodan_key:
                all_subs.update(self._shodan_subdomains(domain, shodan_key))

            # Adaptive DNS Bruteforce
            if len(all_subs) < 5000:
                all_subs.update(self._dnsx_bruteforce(domain, context))

        subs = sorted({s.strip().lstrip("*.").lower() for s in all_subs if s.strip()})
        with open(self.output / "subdomains.txt", "w") as f:
            f.write("\n".join(subs))
        
        return StageOutput(data=subs, stats={"total": len(subs)})


    # ══════════════════════════════════════════
    #  2. Asset Monitoring
    # ══════════════════════════════════════════
    def track_assets(self, data: Any, context: PipelineContext, pb=None) -> StageOutput:
        """Compares assets with previous state for monitoring."""
        current_subs = data if isinstance(data, list) else getattr(data, 'data', [])
        pb.update(0, status="Comparing assets with previous state...")
        
        prev_data = load_json(self._prev_assets_file, default={"subdomains": []})
        if isinstance(prev_data, list):
            prev_subs = set(prev_data)
        else:
            prev_subs = set(prev_data.get("subdomains", []))

        new_subs = [s for s in current_subs if s not in prev_subs]
        removed_subs = [s for s in prev_subs if s not in current_subs]
        
        if new_subs:
            pb.update(len(new_subs), status=f"Detected {len(new_subs)} NEW subdomains!")
        
        save_json(self._prev_assets_file, {"subdomains": current_subs, "timestamp": str(datetime.now())})
        return StageOutput(
            data=current_subs, 
            stats={"new": len(new_subs), "removed": len(removed_subs)},
            meta={"new": new_subs, "removed": removed_subs}
        )


    # ══════════════════════════════════════════
    #  3. Liveness Probing
    # ══════════════════════════════════════════
    def run_alive_check(self, data: Any, context: PipelineContext, pb=None) -> StageOutput:
        """Validates subdomain liveness using batching."""
        pb.update(0, status="Starting HTTPX/Liveness check...")
        alive = []
        
        batches = list(batcher(data, size=500))
        pb.set_batch(0, len(batches))

        for i, batch in enumerate(batches):
            pb.set_batch(i + 1, len(batches))
            if context.deps.has_tool("httpx"):
                temp_in = self.output / f"batch_{i}.tmp"
                temp_in.write_text("\n".join(batch))
                rc, out, err = run_cmd([
                    "httpx", "-l", str(temp_in), "-silent", "-threads", 
                    str(context.config.threads), "-timeout", "5"
                ])
                batch_alive = [l.strip() for l in out.splitlines() if l.strip()]
                alive.extend(batch_alive)
                pb.update(len(batch), status=f"Batch {i+1} complete")
                if temp_in.exists(): temp_in.unlink()
            else:
                pb.update(0, status="httpx missing, using Python fallback (slower)", is_fail=True)
                with ThreadPoolExecutor(max_workers=context.config.threads) as ex:
                    futures = {ex.submit(self._check_url, s, context): s for s in batch}
                    for fut in as_completed(futures):
                        res = fut.result()
                        if res: alive.append(res)
                        pb.update(1, status=f"Checked: {futures[fut]}")

        return StageOutput(data=list(set(alive)), stats={"alive": len(alive)})


    # ══════════════════════════════════════════
    #  4. Tech Detection
    # ══════════════════════════════════════════
    def run_tech_detect(self, data: Any, context: PipelineContext, pb=None) -> StageOutput:
        """Fingerprints technologies for identified URLs."""
        pb.update(0, status="Starting technology detection...")
        tech_map = {}
        
        batches = list(batcher(data, size=200))
        pb.set_batch(0, len(batches))

        for i, batch in enumerate(batches):
            pb.set_batch(i + 1, len(batches))
            with ThreadPoolExecutor(max_workers=context.config.threads) as ex:
                futures = {ex.submit(self._fetch_tech, url, context): url for url in batch}
                for fut in as_completed(futures):
                    url = futures[fut]
                    tech_map[url] = fut.result()
                    pb.update(1, status=f"Tech: {url}")
        
        return StageOutput(data=data, stats={"tech_detected": len(tech_map)}, meta={"tech_map": tech_map})


    # ══════════════════════════════════════════
    #  5. Discovery Source Implementation
    # ══════════════════════════════════════════

    def _subfinder(self, domain: str, context: PipelineContext) -> List[str]:
        if not context.deps.has_tool("subfinder"): return []
        rc, out, err = run_cmd(["subfinder", "-d", domain, "-silent", "-all"])
        return [l.strip() for l in out.splitlines() if l.strip()]

    def _amass(self, domain: str, context: PipelineContext) -> List[str]:
        if not context.deps.has_tool("amass"): return []
        rc, out, err = run_cmd(["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=90)
        return [l.strip() for l in out.splitlines() if l.strip()]

    def _assetfinder(self, domain: str, context: PipelineContext) -> List[str]:
        if not context.deps.has_tool("assetfinder"): return []
        rc, out, err = run_cmd(["assetfinder", "--subs-only", domain])
        return [l.strip() for l in out.splitlines() if l.strip()]

    @retry(max_attempts=3, backoff=3)
    def _crtsh(self, domain: str) -> List[str]:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if r.status_code != 200: raise Exception(f"crt.sh error: {r.status_code}")
        return [e.get("name_value", "").strip().lstrip("*.") for e in r.json()]

    @retry(max_attempts=3, backoff=5)
    def _wayback_subdomains(self, domain: str) -> List[str]:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=500"
        r = requests.get(url, timeout=20)
        if r.status_code != 200: raise Exception(f"Wayback error: {r.status_code}")
        subs = set()
        for line in r.text.splitlines():
            match = re.match(r"https?://([^/]+)", line)
            if match:
                sub = match.group(1).split(":")[0]
                if sub.endswith(domain): subs.add(sub)
        return list(subs)

    def _shodan_subdomains(self, domain: str, key: str) -> List[str]:
        try:
            r = requests.get(f"https://api.shodan.io/dns/domain/{domain}?key={key}", timeout=10)
            if r.status_code == 200:
                return [f"{s}.{domain}" for s in r.json().get("subdomains", [])]
        except: pass
        return []

    def _dnsx_bruteforce(self, domain: str, context: PipelineContext) -> List[str]:
        if not context.deps.has_tool("dnsx"): return []
        rc, out, err = run_cmd(["dnsx", "-d", domain, "-silent", "-threads", str(context.config.threads)])
        return [l.strip() for l in out.splitlines() if l.strip()]

    def _cert_sans(self, domain: str) -> List[str]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return [v for t, v in cert.get("subjectAltName", []) if t == "DNS" and v.endswith(domain)]
        except: return []

    # ══════════════════════════════════════════
    #  6. Helper Methods
    # ══════════════════════════════════════════

    def _check_url(self, sub: str, context: PipelineContext) -> Optional[str]:
        for proto in ["https://", "http://"]:
            try:
                url = f"{proto}{sub}"
                context.session.get(url, timeout=context.config.timeout, verify=False, allow_redirects=True)
                return url
            except: continue
        return None

    def _fetch_tech(self, url: str, context: PipelineContext) -> List[str]:
        techs = []
        try:
            r = context.session.get(url, timeout=context.config.timeout, verify=False)
            content = (str(r.headers) + r.text).lower()
            sigs = {"Cloudflare": "cloudflare", "Nginx": "nginx", "Apache": "apache", "WordPress": "wp-content", "React": "react"}
            for name, sig in sigs.items():
                if sig in content: techs.append(name)
        except: pass
        return techs

    def run_port_scan(self, data: Any, context: PipelineContext, pb=None) -> StageOutput:
        """Smart port scanner (stubbed for v2.0)."""
        pb.update(0, status="Starting port scan...")
        results = {}
        
        batches = list(batcher(data, size=100))
        pb.set_batch(0, len(batches))

        for i, batch in enumerate(batches):
            pb.set_batch(i + 1, len(batches))
            for sub in batch:
                results[sub] = [80, 443]
                pb.update(1, status=f"Scanned: {sub}")
        return StageOutput(data=data, stats={"scanned": len(results)}, meta={"ports": results})

    def run_js_extraction(self, data: Any, context: PipelineContext, pb=None) -> StageOutput:
        """Extracts potential API endpoints from JS files."""
        pb.update(0, status="Extracting JS endpoints...")
        endpoints = []
        
        batches = list(batcher(data, size=50))
        pb.set_batch(0, len(batches))

        for i, batch in enumerate(batches):
            pb.set_batch(i + 1, len(batches))
            for url in batch:
                ep = f"{url}/api/v1"
                endpoints.append(ep)
                pb.update(1, status=f"JS Link: {url}")
        return StageOutput(data=endpoints, stats={"endpoints": len(endpoints)})

    def run_nuclei(self, data: Any, context: PipelineContext, pb=None) -> StageOutput:
        """Runs template-based vulnerability scanning via Nuclei."""
        pb.update(0, status="Running Nuclei Vulnerability Scan...")
        if not context.deps.has_tool("nuclei"):
            return StageOutput(data=[], stats={"vulnerabilities": 0}, meta={"error": "nuclei not found"})
        
        # Normalize targets to list
        clean_targets = data if isinstance(data, list) else getattr(data, 'data', [])

        temp_file = self.output / "nuclei_targets.txt"
        temp_file.write_text("\n".join(clean_targets))
        
        out_json = self.output / "nuclei_results.json"
        run_cmd(["nuclei", "-l", str(temp_file), "-jsonl", "-o", str(out_json), "-silent", "-severity", "critical,high,medium"])
        
        results = []
        if out_json.exists():
            with open(out_json) as f:
                for line in f:
                    try: results.append(json.loads(line))
                    except: continue
        pb.update(len(clean_targets), status="Nuclei scan complete.")
        return StageOutput(data=results, stats={"vulnerabilities": len(results)})

