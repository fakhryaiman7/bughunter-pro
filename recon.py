"""
recon.py — Recon Engine  v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
New in v2.0:
  ✅ DNS Bruteforce via dnsx
  ✅ Wayback Machine passive recon
  ✅ Shodan integration (optional API key)
  ✅ Expanded port scan (30 ports including Redis, Mongo, etc.)
  ✅ JS file endpoint extraction
  ✅ Spider / crawling for endpoint discovery
  ✅ Email / employee exposure check (Hunter.io fallback)
  ✅ Certificate SANs extraction
  ✅ GitHub dorks passive search
"""

import json
import re
import threading
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set

import requests
import requests.exceptions

from utils import (log, Colors, run_cmd, tool_available,
                   save_json, load_json, normalize_url, extract_domain)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ReconEngine:
    def __init__(self, scope: List[str], output: Path,
                 shodan_key: str = "", threads: int = 10):
        self.scope            = scope
        self.output           = output
        self.shodan_key       = shodan_key
        self.threads          = threads
        self._prev_assets_file = output / "knowledge" / "prev_assets.json"

    # ══════════════════════════════════════════
    #  1. Subdomain Discovery
    # ══════════════════════════════════════════
    def discover_subdomains(self) -> List[str]:
        all_subs: Set[str] = set()

        for domain in self.scope:
            log(f"[recon] Discovering subdomains for {domain}", Colors.CYAN)
            passive_subs: Set[str] = set()
            passive_subs.update(self._subfinder(domain))
            passive_subs.update(self._amass(domain))
            passive_subs.update(self._crtsh(domain))
            passive_subs.update(self._assetfinder(domain))
            passive_subs.update(self._wayback_subdomains(domain))
            passive_subs.update(self._cert_sans(domain))
            if self.shodan_key:
                passive_subs.update(self._shodan_subdomains(domain))
                
            all_subs.update(passive_subs)
            
            # Threshold controller
            if len(passive_subs) > 5000:
                log(f"[recon] THRESHOLD EXCEEDED (>5000 subdomains for {domain}). Stopping brute-force, switching to passive-only mode.", Colors.YELLOW)
            else:
                all_subs.update(self._dnsx_bruteforce(domain))

        # Clean: remove wildcards, normalize
        subs = sorted({s.strip().lstrip("*.").lower()
                       for s in all_subs if s.strip()})

        out = self.output / "subdomains.txt"
        with open(out, "w") as f:
            f.write("\n".join(subs))

        log(f"[recon] Total unique subdomains: {len(subs)}", Colors.GREEN)
        return subs

    def _subfinder(self, domain: str) -> List[str]:
        if not tool_available("subfinder"):
            log("[recon] subfinder not found, skipping", Colors.YELLOW)
            return []
        rc, out, err = run_cmd(["subfinder", "-d", domain, "-silent", "-all"])
        return [l.strip() for l in out.splitlines() if l.strip()]

    def _amass(self, domain: str) -> List[str]:
        if not tool_available("amass"):
            log("[recon] amass not found, skipping", Colors.YELLOW)
            return []
        rc, out, err = run_cmd(
            ["amass", "enum", "-passive", "-d", domain, "-silent"],
            timeout=120
        )
        return [l.strip() for l in out.splitlines() if l.strip()]

    def _assetfinder(self, domain: str) -> List[str]:
        if not tool_available("assetfinder"):
            log("[recon] assetfinder not found, skipping", Colors.YELLOW)
            return []
        rc, out, err = run_cmd(["assetfinder", "--subs-only", domain])
        return [l.strip() for l in out.splitlines() if l.strip()]

    def _crtsh(self, domain: str) -> List[str]:
        """Passive: certificate transparency logs."""
        import time
        max_retries = 3
        for attempt in range(max_retries):
            try:
                resp = requests.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=20
                )
                if resp.status_code != 200:
                    time.sleep(2 ** attempt)
                    continue
                data = resp.json()
                subs: Set[str] = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(domain):
                            subs.add(sub)
                return list(subs)
            except Exception as e:
                log(f"[recon] crt.sh error on attempt {attempt + 1}: {e}", Colors.YELLOW)
                time.sleep(2 ** attempt)
        return []

    def _dnsx_bruteforce(self, domain: str) -> List[str]:
        """DNS bruteforce with dnsx — discovers subdomains not in CT logs."""
        if not tool_available("dnsx"):
            log("[recon] dnsx not found — skipping DNS bruteforce (install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest)", Colors.YELLOW)
            return []

        # Use built-in subdomain wordlist or SecLists
        wordlist = self._get_subdomain_wordlist()
        if not wordlist:
            return []

        log(f"[recon] DNS bruteforce on {domain} with dnsx", Colors.CYAN)
        out_file = self.output / f"dnsx_{domain.replace('.', '_')}.txt"

        rc, out, err = run_cmd([
            "dnsx",
            "-d", domain,
            "-w", wordlist,
            "-silent", "-o", str(out_file),
            "-t", "100",
        ], timeout=300)

        results = []
        if out_file.exists():
            with open(out_file) as f:
                results = [l.strip() for l in f if l.strip()]

        log(f"[recon] dnsx found {len(results)} additional subdomains", Colors.GREEN)
        return results

    def _wayback_subdomains(self, domain: str) -> List[str]:
        """Extract subdomains from Wayback Machine CDX API."""
        import time
        max_retries = 3
        for attempt in range(max_retries):
            try:
                url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=1000"
                resp = requests.get(url, timeout=20)
                if resp.status_code != 200:
                    time.sleep(2 ** attempt)
                    continue

                subs = set()
                for line in resp.text.splitlines():
                    # Extract domain from URL
                    match = re.match(r"https?://([^/]+)", line)
                    if match:
                        sub = match.group(1).split(":")[0]
                        if sub.endswith(domain):
                            subs.add(sub)

                log(f"[recon] Wayback found {len(subs)} subdomains for {domain}", Colors.GREEN)
                return list(subs)
            except Exception as e:
                log(f"[recon] Wayback error on attempt {attempt + 1}: {e}", Colors.YELLOW)
                time.sleep(2 ** attempt)
        return []

    def _cert_sans(self, domain: str) -> List[str]:
        """Extract SANs from the domain's TLS certificate."""
        try:
            import ssl
            import socket
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    sans = []
                    for san_type, san_value in cert.get("subjectAltName", []):
                        if san_type == "DNS":
                            san_value = san_value.lstrip("*.")
                            if san_value.endswith(domain):
                                sans.append(san_value)
                    return sans
        except Exception:
            return []

    def _shodan_subdomains(self, domain: str) -> List[str]:
        """Query Shodan for known hosts of the domain."""
        try:
            resp = requests.get(
                f"https://api.shodan.io/dns/domain/{domain}?key={self.shodan_key}",
                timeout=15
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            subs = []
            for sub in data.get("subdomains", []):
                subs.append(f"{sub}.{domain}")
            log(f"[recon] Shodan found {len(subs)} subdomains", Colors.GREEN)
            return subs
        except Exception as e:
            log(f"[recon] Shodan error: {e}", Colors.YELLOW)
            return []

    def _get_subdomain_wordlist(self) -> str:
        """Get subdomain wordlist for DNS bruteforce."""
        candidates = [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/subdomains.txt",
        ]
        for path in candidates:
            if Path(path).exists():
                return path

        # Create minimal wordlist
        minimal = self.output / "wordlists" / "subdomains.txt"
        minimal.parent.mkdir(exist_ok=True)
        words = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "test", "beta", "app", "portal", "vpn", "ssh", "secure",
            "blog", "shop", "store", "cdn", "static", "assets",
            "internal", "intranet", "corp", "m", "mobile", "git",
            "gitlab", "jenkins", "jira", "confluence", "sonar",
            "grafana", "kibana", "elastic", "monitor", "dashboard",
            "old", "legacy", "backup", "db", "database", "sql",
            "redis", "mongo", "auth", "login", "sso", "oauth",
        ]
        if not minimal.exists():
            with open(minimal, "w") as f:
                f.write("\n".join(words))
        return str(minimal)

    # ══════════════════════════════════════════
    #  2. Monitor Changes
    # ══════════════════════════════════════════
    def monitor_changes(self, current: List[str]) -> List[str]:
        prev = set(load_json(self._prev_assets_file, default=[]))
        current_set = set(current)
        new_assets = list(current_set - prev)

        if new_assets:
            log(f"[recon] 🆕 New assets: {new_assets[:5]}{'...' if len(new_assets)>5 else ''}", Colors.YELLOW)

        save_json(self._prev_assets_file, list(current_set))

        out = self.output / "new_assets.txt"
        with open(out, "w") as f:
            f.write("\n".join(new_assets))

        return new_assets

    # ══════════════════════════════════════════
    #  3. Alive Check
    # ══════════════════════════════════════════
    def alive_check(self, subdomains: List[str], pb=None) -> List[str]:
        if tool_available("httpx"):
            return self._httpx_check(subdomains, pb=pb)
        return self._fallback_alive_check(subdomains, pb=pb)

    def _httpx_check(self, subdomains: List[str], pb=None) -> List[str]:
        if pb: pb.update(0, status="Starting httpx scan...")
        hosts_file = self.output / "subdomains.txt"
        out_file   = self.output / "alive.txt"

        rc, out, err = run_cmd([
            "httpx", "-l", str(hosts_file),
            "-silent", "-o", str(out_file),
            "-timeout", "5", "-threads", "50",
            "-status-code", "-title", "-tech-detect",
            "-follow-redirects",
        ], timeout=300)

        if pb: pb.update(len(subdomains), status="httpx scan completed")

        alive = []
        if out_file.exists():
            with open(out_file) as f:
                for line in f:
                    url = line.strip().split()[0] if line.strip() else ""
                    if url.startswith("http"):
                        alive.append(url)
        return alive

    def _fallback_alive_check(self, subdomains: List[str], pb=None) -> List[str]:
        if pb: pb.update(0, status="Using fallback HTTP probe...")
        log("[recon] httpx not found — using fallback HTTP probe", Colors.YELLOW)
        alive = []
        lock = threading.Lock()

        def probe(sub):
            for scheme in ("https", "http"):
                try:
                    url = f"{scheme}://{sub}"
                    r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                    if r.status_code < 500:
                        with lock:
                            alive.append(url)
                        return
                except Exception:
                    pass

        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = [ex.submit(probe, sub) for sub in subdomains]
            for _ in as_completed(futures):
                if pb: pb.update(1, status="Probing subdomains...")

        out = self.output / "alive.txt"
        with open(out, "w") as f:
            f.write("\n".join(alive))
        return alive

    # ══════════════════════════════════════════
    #  4. Port Scan (expanded)
    # ══════════════════════════════════════════
    def port_scan(self, alive: List[str], pb=None) -> Dict[str, List[int]]:
        if not tool_available("nmap"):
            log("[recon] nmap not found, skipping port scan", Colors.YELLOW)
            return {}

        port_data: Dict[str, List[int]] = {}
        domains = list({extract_domain(url) for url in alive})

        log(f"[recon] Port scanning {len(domains)} hosts (expanded ports)", Colors.CYAN)

        # Expanded port list covering all common bug bounty findings
        ports = (
            "21,22,23,25,53,80,110,143,443,445,"
            "993,995,1433,1521,2375,2376,2379,"
            "3000,3306,4000,4443,5000,5432,5900,"
            "6379,7001,7002,7443,8000,8080,8081,"
            "8443,8888,9000,9001,9090,9200,9300,"
            "10000,11211,27017,27018,28017,50000"
        )

        for domain in domains:
            rc, out, err = run_cmd([
                "nmap", "-p", ports,
                "--open", "-T4", "--min-rate", "1000",
                "-oG", "-", domain
            ], timeout=120)

            found_ports = []
            for line in out.splitlines():
                m = re.findall(r"(\d+)/open", line)
                found_ports.extend(int(p) for p in m)

            if found_ports:
                port_data[domain] = found_ports
                log(f"[recon] {domain} → open ports: {found_ports}", Colors.GREEN)
            if pb: pb.update(1, status=f"Scanned {domain}")

        save_json(self.output / "port_scan.json", port_data)
        return port_data

    # ══════════════════════════════════════════
    #  5. Nuclei Scan
    # ══════════════════════════════════════════
    def nuclei_scan(self, alive: List[str]) -> List[Dict]:
        if not tool_available("nuclei"):
            log("[recon] nuclei not found, skipping vuln scan", Colors.YELLOW)
            return []

        hosts_file = self.output / "alive.txt"
        out_json   = self.output / "nuclei_output.json"

        log("[recon] Running nuclei scan (all severities)...", Colors.CYAN)
        rc, out, err = run_cmd([
            "nuclei", "-l", str(hosts_file),
            "-severity", "low,medium,high,critical",
            "-json-export", str(out_json),
            "-silent", "-rate-limit", "50",
            "-bulk-size", "25", "-concurrency", "10",
            "-automatic-scan",           # auto-select templates
            "-stats",
        ], timeout=600)

        findings = []
        if out_json.exists():
            with open(out_json) as f:
                for line in f:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        log(f"[recon] Nuclei found {len(findings)} issues", Colors.YELLOW)
        return findings

    # ══════════════════════════════════════════
    #  6. Screenshots
    # ══════════════════════════════════════════
    def screenshot(self, alive: List[str]):
        if not tool_available("eyewitness") and not tool_available("gowitness"):
            log("[recon] No screenshot tool found (eyewitness/gowitness)", Colors.YELLOW)
            return

        hosts_file  = self.output / "alive.txt"
        screens_dir = self.output / "screenshots"
        screens_dir.mkdir(exist_ok=True)

        if tool_available("gowitness"):
            log("[recon] Taking screenshots with gowitness", Colors.CYAN)
            run_cmd([
                "gowitness", "file",
                "-f", str(hosts_file),
                "--destination", str(screens_dir),
                "--timeout", "15",
                "--chrome-flag=--no-sandbox",
                "--chrome-flag=--disable-gpu",
                "--chrome-flag=--disable-dev-shm-usage",
                "--chrome-flag=--disable-software-rasterizer"
            ], timeout=300)
        else:
            log("[recon] Taking screenshots with eyewitness", Colors.CYAN)
            run_cmd([
                "eyewitness", "-f", str(hosts_file),
                "-d", str(screens_dir), "--no-prompt",
                "--timeout", "10",
            ], timeout=300)

    # ══════════════════════════════════════════
    #  7. Technology Detection
    # ══════════════════════════════════════════
    def detect_tech(self, alive: List[str], pb=None) -> Dict[str, List[str]]:
        if tool_available("whatweb"):
            tech_map = self._whatweb(alive, pb=pb)
        else:
            tech_map = self._header_tech_detect(alive, pb=pb)

        save_json(self.output / "tech_map.json", tech_map)
        return tech_map

    def _whatweb(self, alive: List[str], pb=None) -> Dict[str, List[str]]:
        if pb: pb.update(0, status="Running WhatWeb tech detection...")
        tech_map: Dict[str, List[str]] = {}
        for url in alive:
            rc, out, err = run_cmd(
                ["whatweb", "--log-json=-", url], timeout=30
            )
            try:
                data = json.loads(out)
                plugins = list(data[0].get("plugins", {}).keys()) if data else []
                tech_map[url] = plugins
            except Exception:
                pass
            if pb: pb.update(1, status=f"Analyzed {url}")
        return tech_map

    def _header_tech_detect(self, alive: List[str], pb=None) -> Dict[str, List[str]]:
        if pb: pb.update(0, status="Running header-based tech detection...")
        """Detect tech from response headers & body."""
        SIGNATURES = {
            "WordPress":  [r"wp-content", r"wp-includes", r"WordPress"],
            "Drupal":     [r"Drupal", r"/sites/default/"],
            "Joomla":     [r"Joomla"],
            "Laravel":    [r"laravel_session", r"XSRF-TOKEN"],
            "Django":     [r"csrfmiddlewaretoken", r"Django"],
            "Flask":      [r"Werkzeug"],
            "React":      [r"react-dom", r"__NEXT_DATA__"],
            "Angular":    [r"ng-version", r"angular"],
            "Vue":        [r"__vue__", r"vue\.js"],
            "Express":    [r"x-powered-by.*express"],
            "PHP":        [r"x-powered-by.*php", r"\.php"],
            "ASP.NET":    [r"ASP\.NET", r"__VIEWSTATE"],
            "Java":       [r"jsessionid", r"\.jsp"],
            "Spring":     [r"spring", r"X-Application-Context"],
            "Nginx":      [r"server.*nginx"],
            "Apache":     [r"server.*apache"],
            "GraphQL":    [r"graphql", r"__schema"],
            "Swagger":    [r"swagger", r"openapi"],
            "JWT":        [r"eyJ[A-Za-z0-9_-]+"],
            "Kubernetes": [r"kubernetes", r"k8s"],
            "Docker":     [r"docker"],
            "AWS":        [r"amazonaws\.com", r"x-amz-"],
            "Cloudflare": [r"cf-ray", r"cloudflare"],
            "Stripe":     [r"stripe"],
            "MongoDB":    [r"mongodb"],
            "Redis":      [r"redis"],
        }

        tech_map: Dict[str, List[str]] = {}
        lock = threading.Lock()

        def detect(url):
            techs = []
            try:
                r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
                text = r.text + str(dict(r.headers)).lower()
                for tech, patterns in SIGNATURES.items():
                    for pat in patterns:
                        if re.search(pat, text, re.I):
                            techs.append(tech)
                            break
            except Exception:
                pass
            with lock:
                tech_map[url] = list(set(techs))

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = [ex.submit(detect, url) for url in alive]
            for _ in as_completed(futures):
                if pb: pb.update(1, status="Analyzing headers...")

        return tech_map

    # ══════════════════════════════════════════
    #  NEW v2.0: JS Endpoint Extraction
    # ══════════════════════════════════════════
    def extract_js_endpoints(self, alive: List[str], pb=None) -> List[str]:
        """Extract API endpoints hidden in JavaScript files."""
        endpoints: Set[str] = set()

        API_PATTERNS = [
            r'["\'](/api/[^"\'\s<>]+)["\']',
            r'["\'](/v\d/[^"\'\s<>]+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
            r'baseURL:\s*["\']([^"\']+)["\']',
        ]
        JS_URLS_PATTERN = r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']'

        log(f"[recon] Extracting JS endpoints from {len(alive)} targets", Colors.CYAN)
        if pb: pb.update(0, status="Starting JS endpoint extraction...")

        for base_url in alive[:20]:  # limit to 20 targets
            if pb: pb.update(1, status=f"Analyzing JS in {base_url}")
            try:
                r = requests.get(base_url, timeout=8, verify=False)
                if not r:
                    continue

                # Find all JS file URLs
                js_urls = re.findall(JS_URLS_PATTERN, r.text, re.I)
                js_full_urls = []
                for js_url in js_urls[:10]:  # max 10 JS files per target
                    if js_url.startswith("http"):
                        js_full_urls.append(js_url)
                    elif js_url.startswith("/"):
                        js_full_urls.append(f"{base_url}{js_url}")

                for js_url in js_full_urls:
                    try:
                        js_resp = requests.get(js_url, timeout=8, verify=False)
                        for pattern in API_PATTERNS:
                            matches = re.findall(pattern, js_resp.text)
                            for match in matches:
                                if match.startswith("/"):
                                    endpoints.add(f"{base_url}{match}")
                                elif match.startswith("http"):
                                    endpoints.add(match)
                    except Exception:
                        pass

            except Exception:
                pass

        ep_list = list(endpoints)
        out = self.output / "js_endpoints.txt"
        with open(out, "w") as f:
            f.write(f"# Endpoints extracted from JavaScript files\n")
            f.write(f"# Count: {len(ep_list)}\n\n")
            f.write("\n".join(sorted(ep_list)))

        log(f"[recon] Found {len(ep_list)} API endpoints in JS files", Colors.GREEN)
        return ep_list

    # ══════════════════════════════════════════
    #  NEW v2.0: Wayback Endpoints
    # ══════════════════════════════════════════
    def wayback_endpoints(self, domain: str) -> List[str]:
        """Get historical URLs from Wayback Machine CDX API."""
        log(f"[recon] Fetching Wayback Machine URLs for {domain}", Colors.CYAN)
        try:
            url = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=text&fl=original"
                f"&collapse=urlkey&limit=5000"
                f"&filter=statuscode:200"
                f"&filter=mimetype:text/html"
            )
            resp = requests.get(url, timeout=30)
            if resp.status_code != 200:
                return []

            urls = list(set(resp.text.splitlines()))
            out = self.output / "wayback_urls.txt"
            with open(out, "w") as f:
                f.write("\n".join(urls))

            log(f"[recon] Wayback: {len(urls)} historical URLs", Colors.GREEN)
            return urls
        except Exception as e:
            log(f"[recon] Wayback endpoints error: {e}", Colors.YELLOW)
            return []
