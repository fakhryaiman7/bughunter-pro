import re
import socket
import random
import string
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple, Set, Any
from pathlib import Path

from utils import log, Colors

class FilterPipeline:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def run(self, raw_subdomains: List[str], scope: List[str], pb=None) -> Tuple[List[str], Dict[str, Any]]:
        if pb: pb.update(0, status="Starting Quality Filter Pipeline...")
        log("[filter] Starting Quality Filter Pipeline", Colors.CYAN)
        stats = {
            "raw": len(raw_subdomains),
            "wildcard_domains_detected": {},
            "noise_removed": 0,
            "clean_count": 0
        }

        # 1. Deduplication
        deduped = list(set([s.strip().lower() for s in raw_subdomains if s.strip()]))

        # 2. Wildcard Detection
        wildcards = self._detect_wildcards(scope)
        stats["wildcard_domains_detected"] = wildcards
        if wildcards:
            log(f"[filter] Detected {len(wildcards)} wildcard domains: {list(wildcards.keys())}", Colors.YELLOW)

        # 3. Filter Noise and Wildcards
        clean_subdomains = []
        for sub in deduped:
            if self._is_wildcard(sub, wildcards, scope):
                stats["noise_removed"] += 1
                continue
            if self._is_noise(sub):
                stats["noise_removed"] += 1
                continue
            clean_subdomains.append(sub)
            if pb: pb.update(1, status=f"Filtered {sub}")

        stats["clean_count"] = len(clean_subdomains)
        log(f"[filter] Removed {stats['noise_removed']} noise/wildcard entries", Colors.GREEN)
        
        return clean_subdomains, stats

    def score_and_rank(self, alive_urls: List[str], tech_map: Dict[str, List[str]], status_map: Dict[str, int] = None, pb=None) -> List[Dict]:
        """Scores validated endpoints from 0-100 based on keywords, tech, and responses."""
        if pb: pb.update(0, status="Fetching target statuses for ranking...")
        import requests
        ranked_targets = []
        if status_map is None:
            status_map = {}
            def get_status(url):
                try:
                    r = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                    return url, r.status_code
                except Exception:
                    return url, 0
            with ThreadPoolExecutor(max_workers=20) as ex:
                futures = [ex.submit(get_status, url) for url in alive_urls]
                from concurrent.futures import as_completed
                for fut in as_completed(futures):
                    url, status = fut.result()
                    status_map[url] = status
                    if pb: pb.update(1, status=f"Checked status of {url}")
                    
        for url in alive_urls:
            score = 0
            label = "LOW VALUE"
            
            # 1. Keywords
            if re.search(r'(api|admin|dev|staging|test|v1|v2|graphql|dashboard)', url, re.I):
                score += 30
                
            # 2. Response Status
            status = status_map.get(url, 0)
            if status == 200:
                score += 10
            elif status in (301, 302):
                score += 5
            elif status in (401, 403, 404):
                if status == 404:
                    score += 0
                else:
                    score += 25  # High value if protected
                
            # 3. Tech hints
            techs = tech_map.get(url, [])
            if any(t in techs for t in ["GraphQL", "Swagger", "Jenkins", "Jira", "Kubernetes", "Docker", "MongoDB", "Redis", "Spring"]):
                score += 30
            elif len(techs) > 0:
                score += 10

            score = min(score, 100)
            
            if score >= 60:
                label = "HIGH VALUE"
            elif score >= 30:
                label = "MEDIUM VALUE"
            elif score < 15 and re.search(r'(cdn|static|assets)', url, re.I):
                label = "NOISE"

            if label != "NOISE":
                ranked_targets.append({
                    "url": url,
                    "score": score,
                    "label": label,
                    "tech": techs,
                    "status": status
                })

        # Sort targets by score descending
        ranked_targets = sorted(ranked_targets, key=lambda x: x["score"], reverse=True)
        return ranked_targets

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
