import re
import json
from collections import defaultdict
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple

from utils import log, Colors, save_json, load_json

from core import PipelineContext, batcher, StageOutput

class CVEMapper:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.cve_db_path = Path("cve_database.json")
        self.cve_db = self._load_cve_db()

    def _load_cve_db(self) -> Dict[str, Any]:
        """Load offline CVE database if available."""
        if self.cve_db_path.exists():
            try:
                return load_json(self.cve_db_path, default={})
            except Exception as e:
                log(f"[cve_mapper] Failed to load {self.cve_db_path}: {e}", Colors.YELLOW)
        return {}

    def run(self, data: Any, context: PipelineContext, pb=None) -> StageOutput:
        """
        Process, enrich, and prioritize raw Nuclei findings.
        """
        pb.update(0, status="Initializing CVE Mapping & Exploit Intel...")
        enriched_findings = []
        
        # Defensive extraction of findings
        nuclei_findings = data if isinstance(data, list) else getattr(data, 'data', [])
        if not nuclei_findings:
            return StageOutput(data=[], stats={"mapped": 0})

        # Batch processing for consistency
        batches = list(batcher(nuclei_findings, size=500))
        pb.set_batch(0, len(batches))

        for i, batch in enumerate(batches):
            pb.set_batch(i + 1, len(batches))
            for finding in batch:
                info = finding.get("info", {})
                severity = info.get("severity", "info").upper()
                
                # Noise filter
                if severity == "INFO" and "fuzz" in finding.get("template-id", "").lower():
                    pb.update(1, status="Skipping noise finding...")
                    continue

                cves = self._extract_cves(finding)
                exploitability = self._score_exploitability(finding, cves)
                impact, real_severity = self._calculate_impact(finding, exploitability)
                attack_path = self._suggest_attack_path(finding)

                enriched = {
                    "url": finding.get("matched-at", finding.get("host", "")),
                    "template": finding.get("template-id", "unknown"),
                    "cves": list(cves),
                    "original_severity": severity,
                    "adjusted_severity": real_severity,
                    "exploitability": exploitability,
                    "impact": impact,
                    "next_step": attack_path,
                    "raw_finding": finding
                }
                enriched_findings.append(enriched)
                pb.update(1, status=f"Mapped: {enriched['template']}")

        # 2. Filter noise heavily
        valid_findings = [f for f in enriched_findings if f["exploitability"] >= 10 or f["adjusted_severity"] in ["CRITICAL", "HIGH", "MEDIUM"]]
        valid_findings = [f for f in valid_findings if f["adjusted_severity"] != "INFO"]

        # 3. Prioritize & Cluster
        prioritized = sorted(valid_findings, key=lambda x: (
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(x["adjusted_severity"], 0),
            x["exploitability"]
        ), reverse=True)

        clusters = self._cluster_findings(prioritized)

        # 4. Write exports
        self._write_raw(nuclei_findings)
        self._write_cve_mapped(prioritized)
        self._write_prioritized_vulns(prioritized)
        self._write_exploit_intel(clusters)

        return StageOutput(data=prioritized, stats={"mapped_findings": len(prioritized)})



    def _extract_cves(self, finding: Dict) -> Set[str]:
        """Extract CVE IDs using template metadata and regex."""
        cves = set()
        info = finding.get("info", {})
        
        # Method 1: Metadata
        classification = info.get("classification", {})
        cve_id = classification.get("cve-id", "")
        if cve_id:
            if isinstance(cve_id, list):
                for c in cve_id:
                    cves.add(c.upper())
            else:
                cves.add(cve_id.upper())

        # Method 2: Keyword Matching
        text_to_search = f"{info.get('name', '')} {info.get('description', '')} {finding.get('template-id', '')}"
        matches = re.findall(r"(CVE-\d{4}-\d{4,7})", text_to_search, re.I)
        for m in matches:
            cves.add(m.upper())

        return set(cves)

    def _score_exploitability(self, finding: Dict, cves: Set[str]) -> int:
        """Calculate exploitability score 0-100."""
        score = 0
        info = finding.get("info", {})
        tags = info.get("tags", "").lower()
        desc = info.get("description", "").lower()
        name = info.get("name", "").lower()
        full_text = f"{tags} {desc} {name}"

        # Public Exploit (+30)
        if any(keyword in full_text for keyword in ["exploit", "cisa", "kev", "poc", "metasploit"]):
            score += 30
        
        # Remote Code Execution (+40)
        if any(keyword in full_text for keyword in ["rce", "remote code execution", "command-injection", "cmd-injection", "ognl", "eval("]):
            score += 40
        elif any(keyword in full_text for keyword in ["sqli", "sql injection"]):
            score += 30

        # Authentication (-20)
        if "authenticated" in full_text or "auth-required" in full_text:
            score -= 20

        # Complexity Low (+20)
        if "unauthenticated" in full_text or "pre-auth" in full_text or "idor" in full_text:
            score += 20
        
        # Method 3: DB Enrich (If we have local cve_database.json knowledge)
        for cve in cves:
            if cve in self.cve_db:
                cve_meta = self.cve_db[cve]
                if cve_meta.get("has_exploit"): score += 20
                if cve_meta.get("is_rce"): score += 20
                if cve_meta.get("auth_required"): score -= 20

        return max(0, min(100, score))

    def _calculate_impact(self, finding: Dict, exploitability: int) -> Tuple[str, str]:
        """Determine Real-World Impact string and adjusted Severity."""
        info = finding.get("info", {})
        original_sev = info.get("severity", "info").upper()
        tags = info.get("tags", "").lower()
        
        # Determine RCE / Data Breach
        if exploitability >= 70 or "rce" in tags or "sqli" in tags:
            return "Remote Code Execution or highly critical data breach possible.", "CRITICAL"
        
        if "idor" in tags or "bypass" in tags or "lfi" in tags or exploitability >= 50:
            return "Authentication bypass, IDOR, or Local File Inclusion.", "HIGH"
            
        if "xss" in tags or "info" in tags or "disclosure" in tags or "ssrf" in tags:
            return "Information disclosure, SSRF, or Cross-Site Scripting.", "MEDIUM"
            
        return "Misconfiguration or low severity issue.", original_sev if original_sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "LOW"

    def _suggest_attack_path(self, finding: Dict) -> str:
        """Generate safe, targeted exploitation guidance."""
        info = finding.get("info", {})
        tags = info.get("tags", "").lower()
        name = info.get("name", "").lower()
        
        if "rce" in tags or "rce" in name:
            return "Test execution endpoints or parameters with safe payloads (e.g., whoami / id) to confirm RCE."
        if "sqli" in tags:
            return "Test vulnerable parameters with time-based or boolean logic (e.g., AND 1=1 / AND SLEEP(5))."
        if "lfi" in tags:
            return "Test directory traversal payloads (../../../../etc/passwd) on file retrieval endpoints."
        if "xss" in tags:
            return "Inject harmless alert or console.log to confirm execution context."
        if "ssrf" in tags:
            return "Attempt to fetch internal metadata endpoints (e.g., AWS 169.254.169.254) or scan internal ports."
        if "cve" in name:
            return "Search exploit-db or GitHub for public Proof of Concepts for this CVE."
            
        return "Review the endpoint parameters manually. Check for missing validation or authorization."

    def _cluster_findings(self, prioritized: List[Dict]) -> Dict[str, List[Dict]]:
        """Group related vulnerabilities by target host."""
        clusters = defaultdict(list)
        from urllib.parse import urlparse
        
        for p in prioritized:
            try:
                domain = urlparse(p["url"]).netloc or p["url"]
            except Exception:
                domain = p["url"]
            clusters[domain].append(p)
            
        return dict(clusters)

    def _write_raw(self, findings: List[Dict]):
        path = self.output_dir / "nuclei_raw.txt"
        with open(path, "w", encoding="utf-8") as f:
            for fd in findings:
                f.write(json.dumps(fd) + "\n")
                
    def _write_cve_mapped(self, prioritized: List[Dict]):
        path = self.output_dir / "cve_mapped.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Mapped CVEs from Vulnerability Scan\n\n")
            for p in prioritized:
                cves = ", ".join(p["cves"]) if p["cves"] else "No CVE"
                f.write(f"[{p['adjusted_severity']}] {p['url']} → {p['template']} ({cves})\n")

    def _write_prioritized_vulns(self, prioritized: List[Dict]):
        path = self.output_dir / "prioritized_vulns.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Prioritized Vulnerability List\n")
            f.write("# Sorted by Severity and Exploitability\n\n")
            for p in prioritized:
                f.write(f"[{p['adjusted_severity']}] EXPL:{p['exploitability']}/100 - {p['url']}\n")
                f.write(f"    Template: {p['template']}\n")
                if p["cves"]:
                    f.write(f"    CVEs: {', '.join(p['cves'])}\n")
                f.write("\n")

    def _write_exploit_intel(self, clusters: Dict[str, List[Dict]]):
        path = self.output_dir / "exploit_intel.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Exploit Intelligence Report\n")
            f.write("=================================================\n\n")
            
            for domain, vulns in clusters.items():
                f.write(f"🎯 TARGET CLUSTER: {domain}\n")
                f.write(f"   Total Actionable Findings: {len(vulns)}\n\n")
                
                for v in vulns:
                    f.write(f"  [{v['adjusted_severity']}] {v['url']}\n")
                    f.write(f"  Template: {v['template']}\n")
                    if v["cves"]: f.write(f"  CVE: {', '.join(v['cves'])}\n")
                    f.write(f"  Exploitability: {v['exploitability']}/100\n\n")
                    f.write(f"  Impact:\n  {v['impact']}\n\n")
                    f.write(f"  Next Step:\n  {v['next_step']}\n")
                    f.write(f"  {'-'*40}\n")
                f.write("=================================================\n\n")
