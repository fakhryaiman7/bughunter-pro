"""
intelligence.py — Intelligence & Analysis Engine  v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
New in v2.0:
  ✅ HTTP status code scoring (403 on admin = bonus)
  ✅ Path-level pattern scoring (not just subdomain)
  ✅ More tech scores (Spring, Docker, K8s)
  ✅ Expanded interesting patterns
  ✅ More recommendation types (SSRF, CORS, JWT, takeover)
"""

import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

from utils import log, Colors, save_json


# ─────────────────────────────────────────────
#  Scoring weights
# ─────────────────────────────────────────────

INTERESTING_PORTS = {
    21:    10,  # FTP
    22:     5,  # SSH
    23:    20,  # Telnet
    25:     5,  # SMTP
    53:     5,  # DNS
    80:     5,  # HTTP
    110:    5,  # POP3
    143:    5,  # IMAP
    443:    5,  # HTTPS
    445:   15,  # SMB
    1433:  25,  # MSSQL
    1521:  25,  # Oracle DB
    2375:  30,  # Docker (unauthenticated)
    2376:  25,  # Docker TLS
    2379:  25,  # etcd (Kubernetes)
    3000:  15,  # Dev server
    3306:  20,  # MySQL
    4000:  10,  # Alt dev
    4443:  10,  # Alt HTTPS
    5000:  15,  # Flask / dev
    5432:  20,  # PostgreSQL
    5900:  20,  # VNC
    6379:  30,  # Redis (often no auth!)
    7001:  20,  # WebLogic
    7002:  20,  # WebLogic HTTPS
    8000:  15,  # Django dev
    8080:  10,  # Alt HTTP
    8081:  10,  # Alt HTTP
    8443:  10,  # Alt HTTPS
    8888:  15,  # Jupyter / dev
    9000:  15,  # Various dev / PHP-FPM
    9090:  15,  # Prometheus
    9200:  25,  # Elasticsearch (often open!)
    9300:  20,  # Elasticsearch transport
    10000: 20,  # Webmin
    11211: 25,  # Memcached
    27017: 25,  # MongoDB
    27018: 20,  # MongoDB
    28017: 20,  # MongoDB HTTP
    50000: 15,  # SAP / various
}

INTERESTING_PATTERNS = {
    # Admin / management
    "admin":      20, "administrator": 20, "dashboard":  18,
    "manage":     15, "management":    15, "cms":        15,
    "controlpanel":15,"panel":         12, "backend":    15,
    "superadmin": 30, "root":          25, "sysadmin":   25,

    # Development / staging
    "dev":        20, "staging":       25, "test":       20,
    "beta":       15, "internal":      25, "corp":       15,
    "debug":      20, "demo":          15, "sandbox":    20,
    "localhost":  25, "local":         15,

    # API
    "api":        15, "graphql":       20, "rest":       15,
    "swagger":    20, "openapi":       20, "endpoint":   15,
    "webhook":    15, "callback":      15,

    # Auth / identity
    "login":      10, "auth":          12, "oauth":      15,
    "sso":        15, "saml":          15, "jwt":        15,
    "token":      12, "signin":        10,

    # DevOps / CI/CD
    "jenkins":    30, "gitlab":        20, "github":     15,
    "jira":       15, "confluence":    15, "sonar":      20,
    "grafana":    20, "kibana":        25, "elastic":    25,
    "prometheus": 20, "kubernetes":    25, "k8s":        25,
    "docker":     20, "registry":      20,

    # Data / DB
    "db":         25, "database":      25, "sql":        25,
    "mongo":      20, "redis":         25, "elastic":    25,
    "backup":     25, "old":           20, "legacy":     20,

    # Secrets / config
    "secret":     30, "private":       20, "hidden":     25,
    "config":     25, "env":           25, "settings":   20,
    "credential": 30, "password":      25, "passwd":     25,
    "vault":      25, "key":           20,

    # VPN / remote
    "vpn":        10, "remote":        10, "rdp":        20,
    "ssh":        10, "ftp":           10,
}

TECH_SCORES = {
    "WordPress":  15, "Drupal":  15, "Joomla":   15,
    "Laravel":     5, "Django":   5, "Flask":      5,
    "Express":     5, "Spring":  20,
    "GraphQL":    20, "Swagger": 15, "JWT":       15,
    "Java":       10, "PHP":     10,
    "MongoDB":    15, "Redis":   15, "Elasticsearch": 20,
    "Docker":     15, "Kubernetes": 25,
    "AWS":        10, "Cloudflare": -5,  # WAF = deduct a bit
}

NUCLEI_SEVERITY = {
    "critical": 40, "high": 25, "medium": 15, "low": 5, "info": 2
}

TAGS_RULES = {
    "API":    lambda url, tech: (
        any(p in url.lower() for p in ["api", "graphql", "swagger", "v1", "v2", "v3", "rest", "endpoint"])
        or any(t in tech for t in ["GraphQL", "Swagger"])
    ),
    "ADMIN":  lambda url, tech: any(p in url.lower() for p in
                                    ["admin", "dashboard", "manage", "cms", "control", "panel", "backend"]),
    "LOGIN":  lambda url, tech: any(p in url.lower() for p in
                                    ["login", "auth", "signin", "sso", "oauth", "saml"]),
    "DEV":    lambda url, tech: any(p in url.lower() for p in
                                    ["dev", "staging", "test", "beta", "debug", "internal", "sandbox", "demo"]),
    "DB":     lambda url, tech: any(p in url.lower() for p in
                                    ["db", "database", "sql", "mongo", "redis", "elastic"])
               or any(t in tech for t in ["MongoDB", "Redis", "Elasticsearch"]),
    "LEGACY": lambda url, tech: any(p in url.lower() for p in
                                    ["old", "legacy", "backup", "archive", "v1"]),
    "CMS":    lambda url, tech: any(t in tech for t in ["WordPress", "Drupal", "Joomla"]),
    "DEVOPS": lambda url, tech: any(p in url.lower() for p in
                                    ["jenkins", "gitlab", "grafana", "kibana", "prometheus"])
               or any(t in tech for t in ["Docker", "Kubernetes"]),
    "CLOUD":  lambda url, tech: "AWS" in tech or any(p in url.lower() for p in ["s3", "amazonaws"]),
}


# ─────────────────────────────────────────────
#  IntelligenceEngine
# ─────────────────────────────────────────────

class IntelligenceEngine:
    def __init__(self, output: Path):
        self.output = output

    def analyze(
        self,
        alive: List[str],
        port_data: Dict[str, List[int]],
        nuclei_findings: List[Dict],
        tech_map: Dict[str, List[str]],
        new_assets: List[str],
        status_map: Dict[str, int] = None,
    ) -> List[Dict[str, Any]]:

        # Build nuclei lookup
        nuclei_lookup: Dict[str, int] = {}
        for finding in nuclei_findings:
            host = finding.get("host", "")
            sev  = finding.get("info", {}).get("severity", "info").lower()
            score = NUCLEI_SEVERITY.get(sev, 0)
            nuclei_lookup[host] = max(nuclei_lookup.get(host, 0), score)

        scored: List[Dict[str, Any]] = []

        for url in alive:
            domain = url.replace("https://", "").replace("http://", "").split("/")[0]
            tech   = tech_map.get(url, [])
            ports  = port_data.get(domain, [])

            score   = 0
            reasons: List[str] = []

            # Pattern scoring (both subdomain + path)
            url_lower = url.lower()
            for pattern, pts in INTERESTING_PATTERNS.items():
                if pattern in url_lower:
                    score += pts
                    reasons.append(f"keyword '{pattern}' (+{pts})")

            # Port scoring
            for port in ports:
                pts = INTERESTING_PORTS.get(port, 0)
                if pts:
                    score += pts
                    reasons.append(f"port {port} (+{pts})")

            # Tech scoring
            for t in tech:
                pts = TECH_SCORES.get(t, 0)
                if pts:
                    score += pts
                    reasons.append(f"tech {t} (+{pts})")

            # Nuclei bonus
            n_score = nuclei_lookup.get(url, nuclei_lookup.get(domain, 0))
            if n_score:
                score += n_score
                reasons.append(f"nuclei finding (+{n_score})")

            # New asset bonus
            if domain in new_assets or url in new_assets:
                score += 10
                reasons.append("new asset (+10)")

            # Status code scoring
            if status_map:
                status = status_map.get(url, 200)
                if status in (401, 403):
                    score += 10
                    reasons.append(f"protected endpoint {status} (+10)")

            score = min(score, 100)
            tags = [tag for tag, rule in TAGS_RULES.items() if rule(url, tech)]

            scored.append({
                "url":     url,
                "domain":  domain,
                "score":   score,
                "tags":    tags,
                "tech":    tech,
                "ports":   ports,
                "reasons": reasons,
            })

        self._write_recommendations(scored)
        save_json(self.output / "scored_targets.json", scored)

        return sorted(scored, key=lambda x: x["score"], reverse=True)

    def prioritize(self, scored: List[Dict], pattern_hits: List[Dict]) -> List[Dict]:
        hit_urls = {h["url"] for h in pattern_hits}
        for t in scored:
            if t["url"] in hit_urls:
                t["score"] = min(t["score"] + 15, 100)
                t["reasons"].append("pattern match boost (+15)")
        return sorted(scored, key=lambda x: x["score"], reverse=True)

    def _write_recommendations(self, scored: List[Dict]):
        lines = [
            "# BugHunter Pro v2.0 — Recommendations",
            f"# Generated: {datetime.now()}",
            "",
        ]

        for t in sorted(scored, key=lambda x: x["score"], reverse=True):
            if t["score"] < 30:
                continue
            lines.append(f"{'─'*60}")
            lines.append(f"TARGET : {t['url']}")
            lines.append(f"SCORE  : {t['score']}/100")
            lines.append(f"TAGS   : {', '.join(t['tags']) or 'none'}")
            lines.append(f"TECH   : {', '.join(t['tech']) or 'unknown'}")
            lines.append(f"PORTS  : {t['ports'] or 'standard'}")
            lines.append("")
            lines.append("RECOMMENDATIONS:")
            for rec in self._generate_recs(t):
                lines.append(f"  • {rec}")
            lines.append("")

        out = self.output / "recommendations.txt"
        with open(out, "w") as f:
            f.write("\n".join(lines))

        log("[intel] recommendations.txt written", Colors.GREEN)

    def _generate_recs(self, target: Dict) -> List[str]:
        recs = []
        tags = target.get("tags", [])
        tech = target.get("tech", [])
        url  = target["url"]
        ports= target.get("ports", [])

        if "API" in tags:
            recs += [
                "Test for IDOR: enumerate numeric IDs in endpoints",
                "Check for missing authentication on API endpoints",
                "Test CORS: send Origin: https://evil.com",
                "Test SSRF via URL parameters (url=, redirect=, fetch=)",
                "Test GraphQL introspection if GraphQL detected",
                "Check for rate limiting absence on login/register",
                "Look for verbose error messages revealing internals",
                "Test HTTP Parameter Pollution (duplicate params)",
            ]
        if "ADMIN" in tags:
            recs += [
                "Test for default credentials (admin/admin, admin/password)",
                "Check for authentication bypass via header manipulation",
                "Look for privilege escalation opportunities",
                "Test Host Header Injection → password reset poisoning",
            ]
        if "LOGIN" in tags:
            recs += [
                "Test for account enumeration via timing/response differences",
                "Check password reset flow for weak/reusable tokens",
                "Test for session fixation vulnerabilities",
                "Look for 2FA bypass (skip step, repeat token)",
                "Test OAuth flow for redirect_uri bypass",
            ]
        if "DEV" in tags:
            recs += [
                "Staging environments often have weaker auth — test thoroughly",
                "Look for debug endpoints (/debug, /trace, /.env)",
                "Check for exposed environment variables",
                "Test for source code disclosure (.git, .svn)",
            ]
        if "DEVOPS" in tags:
            recs += [
                "Jenkins: test /script endpoint for RCE (Groovy console)",
                "Grafana: test for CVE-2021-43798 (path traversal)",
                "Kubernetes: check /api/v1/ and /metrics exposure",
                "Docker API: check port 2375 for unauthenticated access",
            ]
        if "CLOUD" in tags:
            recs += [
                "Check for public S3 buckets and misconfigurations",
                "Test SSRF to AWS metadata (169.254.169.254)",
                "Look for exposed IAM credentials in responses",
            ]
        if "WordPress" in tech:
            recs += [
                "Run wpscan for known vulnerabilities",
                "Check /wp-json/wp/v2/users for user enumeration",
                "Test /xmlrpc.php for credential brute-force",
                "Check for outdated plugins with known CVEs",
            ]
        if "JWT" in tech:
            recs += [
                "Decode JWT at jwt.io — check algorithm",
                "Try alg:none attack (remove signature)",
                "Test RS256→HS256 confusion attack if asymmetric",
                "Check if token expiry (exp) is enforced",
            ]
        if "GraphQL" in tech:
            recs += [
                "Send introspection query: {__schema{types{name}}}",
                "Map all queries and mutations",
                "Test for IDOR via ID-based queries",
                "Check for batch query DoS",
            ]
        if 6379 in ports:
            recs.append("Redis (6379) open — test for unauthenticated access and RCE via crafted commands")
        if 2375 in ports:
            recs.append("Docker API (2375) open — test for unauthenticated container management")
        if 9200 in ports:
            recs.append("Elasticsearch (9200) open — check for unauthenticated index access")
        if 27017 in ports:
            recs.append("MongoDB (27017) open — test for unauthenticated database access")

        if not recs:
            recs.append("Perform general recon and manual inspection")
            recs.append("Check for subdomain takeover if DNS resolution fails")

        return recs
