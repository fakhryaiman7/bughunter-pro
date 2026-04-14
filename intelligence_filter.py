import re
import socket
import random
import string
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple, Set, Any
from pathlib import Path

from utils import log, Colors

from core import PipelineContext, batcher, StageOutput
from concurrent.futures import ThreadPoolExecutor, as_completed

class FilterPipeline:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def run(self, data: Any, context: PipelineContext, pb=None) -> StageOutput:
        """
        Processes subdomains in batches to avoid memory spikes.
        """
        pb.update(0, status="Starting Intelligence Filtering Pipeline...")
        
        stats = {
            "wildcard_domains_detected": {},
            "noise_removed": 0,
            "clean_count": 0
        }

        # 1. Deduplication
        clean_input = []
        for chunk in batcher(data, size=len(data) if data else 1):
            clean_input = chunk
            break
            
        deduped = list(set([s.strip().lower() for s in clean_input if s.strip()]))
        stats["raw"] = len(deduped)

        # 2. Wildcard Detection
        wildcards = self._detect_wildcards(context.scope)
        stats["wildcard_domains_detected"] = wildcards

        # 3. Filter Noise and Wildcards (Batch Processing)
        clean_subdomains = []
        batches = list(batcher(deduped, size=1000))
        pb.set_batch(0, len(batches))

        for i, batch in enumerate(batches):
            pb.set_batch(i + 1, len(batches))
            for sub in batch:
                if self._is_wildcard(sub, wildcards, context.scope):
                    stats["noise_removed"] += 1
                    continue
                if self._is_noise(sub):
                    stats["noise_removed"] += 1
                    continue
                clean_subdomains.append(sub)
                pb.update(1, status=f"Filtered {len(clean_subdomains)} assets...")

        stats["clean_count"] = len(clean_subdomains)
        return StageOutput(data=clean_subdomains, stats=stats)

    def score_and_rank(self, data: Any, tech_map: Dict[str, List[str]], context: PipelineContext, pb=None) -> StageOutput:
        """Scores endpoints based on intelligence signatures."""
        pb.update(0, status="Scoring and ranking assets...")
        ranked_targets = []
        
        alive_urls = data if isinstance(data, list) else getattr(data, 'data', [])
        
        # Batch status checking
        status_map = {}
        
        def get_status(url):
            try:
                r = context.session.get(url, timeout=5, verify=False, allow_redirects=False)
                return url, r.status_code
            except Exception:
                return url, 0

        batches = list(batcher(alive_urls, size=200))
        pb.set_batch(0, len(batches))

        for i, batch in enumerate(batches):
            pb.set_batch(i + 1, len(batches))
            with ThreadPoolExecutor(max_workers=context.get_config("threads", 10)) as ex:
                futures = [ex.submit(get_status, url) for url in batch]
                for fut in as_completed(futures):
                    url, status = fut.result()
                    status_map[url] = status
                    pb.update(1, status=f"Ranking: {url}")

        for url in alive_urls:
            score = 0
            label = "LOW VALUE"
            
            if re.search(r'(api|admin|dev|staging|test|v1|v2|graphql|dashboard)', url, re.I):
                score += 30
                
            status = status_map.get(url, 0)
            if status == 200: score += 10
            elif status in (401, 403): score += 25
                
            techs = tech_map.get(url, [])
            if any(t in techs for t in ["GraphQL", "Swagger", "Jenkins", "Jira", "Spring"]):
                score += 30

            score = min(score, 100)
            if score >= 60: label = "HIGH VALUE"
            elif score >= 30: label = "MEDIUM VALUE"

            if label != "LOW VALUE" or score > 10:
                ranked_targets.append({
                    "url": url, "score": score, "label": label, "tech": techs, "status": status
                })

        ranked_sorted = sorted(ranked_targets, key=lambda x: x["score"], reverse=True)
        return StageOutput(data=ranked_sorted, stats={"high_value": len([r for r in ranked_sorted if r['score'] >= 60])})



    def _detect_wildcards(self, domains: List[str]) -> Dict[str, Set[str]]:
        wildcards = {}
        def check(domain):
            ips = []
            for _ in range(3):
                rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
                test_sub = f"{rand_str}.{domain}"
                try:
                    res = socket.gethostbyname(test_sub)
                    ips.append(res)
                except socket.gaierror:
                    continue
            if len(ips) == 3 and len(set(ips)) == 1:
                return domain, ips[0]
            return None, None

        with ThreadPoolExecutor(max_workers=len(domains) if domains else 1) as ex:
            results = ex.map(check, domains)
            for domain, ip in results:
                if domain:
                    if domain not in wildcards:
                        wildcards[domain] = set()
                    wildcards[domain].add(ip)
        return wildcards

    def _get_base_domain(self, subdomain: str, scope: List[str]) -> str:
        for s in scope:
            if subdomain.endswith(s):
                return s
        parts = subdomain.split('.')
        return ".".join(parts[-2:]) if len(parts) > 2 else subdomain

    def _is_wildcard(self, subdomain: str, wildcards: Dict[str, Set[str]], scope: List[str]) -> bool:
        base = self._get_base_domain(subdomain, scope)
        if base in wildcards:
            try:
                ip = socket.gethostbyname(subdomain)
                if ip in wildcards[base]:
                    # Exception for exact main domain or obvious www
                    if subdomain == base or subdomain == f"www.{base}":
                        return False
                    return True
            except socket.gaierror:
                return False
        return False

    def _is_noise(self, subdomain: str) -> bool:
        # random hash-like
        if re.search(r'[a-f0-9]{16,}', subdomain): return True
        # purely numeric subdomain prefixes (e.g. 12345.example.com)
        parts = subdomain.split('.')
        if len(parts) > 2 and parts[0].isdigit(): return True
        # duplicate patterns (e.g., test.test.example.com)
        if len(parts) > 3 and parts[0] == parts[1]: return True
        # purely cdn/static without interesting keywords
        if re.search(r'^(cdn|static|assets)\.', subdomain, re.I) and not re.search(r'(api|admin|dev)', subdomain, re.I):
            return True
        return False

    def generate_report(self, stats: Dict, ranked_targets: List[Dict]):
        path = self.output_dir / "filter_report.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Intelligence Filter Report\n\n")
            f.write(f"Raw Subdomains : {stats['raw']}\n")
            f.write(f"Cleaned Targets: {stats['clean_count']}\n")
            f.write(f"Noise Removed  : {stats['noise_removed']}\n")
            f.write(f"Wildcard Domains: {list(stats['wildcard_domains_detected'].keys())}\n\n")
            f.write("## Ranked Targets\n")
            for t in ranked_targets:
                f.write(f"[{t['score']:>2}] {t['url']} → {t['label']}\n")
        log(f"[filter] Filter report generated at {path}", Colors.GREEN)
