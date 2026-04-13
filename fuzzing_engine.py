"""
fuzzing_engine.py — Smart Fuzzing Engine
Uses ffuf + SecLists wordlists.
Only fuzzes targets with score >= 60 tagged as API or ADMIN.
Auto-selects wordlist based on tech/tags.
"""

import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

from utils import log, Colors, run_cmd, tool_available


# ─────────────────────────────────────────────
#  Wordlist paths (SecLists or bundled)
# ─────────────────────────────────────────────

SECLISTS_BASE  = Path("/usr/share/seclists")
LOCAL_WL_BASE  = Path("wordlists")   # fallback local wordlists

WORDLIST_MAP = {
    "default": "dirs.txt",
    "API":     "api.txt",
    "ADMIN":   "admin.txt",
    "LOGIN":   "admin.txt",
    "DEV":     "dirs.txt",
    "params":  "params.txt",
}

SECLISTS_MAP = {
    "default": "Discovery/Web-Content/common.txt",
    "API":     "Discovery/Web-Content/api/api-endpoints.txt",
    "ADMIN":   "Discovery/Web-Content/AdminPanels.fuzz.txt",
    "params":  "Discovery/Web-Content/burp-parameter-names.txt",
}


def _resolve_wordlist(category: str) -> str:
    """Find wordlist in SecLists first, then local fallback."""
    sec_rel = SECLISTS_MAP.get(category, SECLISTS_MAP["default"])
    sec_path = SECLISTS_BASE / sec_rel
    if sec_path.exists():
        return str(sec_path)

    local_file = WORDLIST_MAP.get(category, "dirs.txt")
    local_path = LOCAL_WL_BASE / local_file
    if local_path.exists():
        return str(local_path)

    # Last resort: minimal built-in wordlist
    return _create_minimal_wordlist(category)


def _create_minimal_wordlist(category: str) -> str:
    """Create a minimal wordlist when SecLists is unavailable."""
    LOCAL_WL_BASE.mkdir(exist_ok=True)

    WORDS = {
        "default": [
            "admin", "login", "dashboard", "api", "v1", "v2",
            "config", "backup", "debug", "test", "staging", "old",
            ".env", "config.json", "robots.txt", "sitemap.xml",
            "swagger.json", "openapi.json", "api-docs",
        ],
        "API": [
            "api", "v1", "v2", "v3", "graphql", "rest", "endpoints",
            "users", "user", "accounts", "account", "profile", "me",
            "admin", "auth", "token", "refresh", "logout", "health",
            "status", "ping", "docs", "swagger", "openapi",
        ],
        "ADMIN": [
            "admin", "administrator", "admin/login", "admin/dashboard",
            "admin/users", "admin/config", "admin/settings",
            "dashboard", "manage", "management", "cms", "cp",
            "controlpanel", "panel", "manager", "backend",
        ],
        "params": [
            "id", "user_id", "user", "username", "email", "token",
            "key", "secret", "password", "debug", "redirect", "url",
            "callback", "next", "return", "file", "path", "page",
        ],
    }

    words = WORDS.get(category, WORDS["default"])
    path = LOCAL_WL_BASE / f"{category.lower()}.txt"
    with open(path, "w") as f:
        f.write("\n".join(words))
    return str(path)


# ─────────────────────────────────────────────
#  FuzzingEngine
# ─────────────────────────────────────────────

class FuzzingEngine:
    def __init__(self, output: Path):
        self.output = output
        self.results: List[Dict] = []
        self._lock = threading.Lock()

    def run(self, targets: List[Dict[str, Any]], tech_map: Dict[str, List[str]]):
        if not tool_available("ffuf"):
            log("[fuzz] ffuf not found — install from https://github.com/ffuf/ffuf", Colors.YELLOW)
            self._write_results()
            return

        if not targets:
            log("[fuzz] No high-value targets for fuzzing", Colors.YELLOW)
            return

        log(f"[fuzz] ⚡ Starting fuzzing on {len(targets)} targets", Colors.YELLOW)

        threads = []
        for target in targets:
            t = threading.Thread(target=self._fuzz_target, args=(target, tech_map))
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=300)

        self._write_results()

    def _fuzz_target(self, target: Dict, tech_map: Dict):
        url   = target["url"]
        tags  = target.get("tags", [])
        tech  = tech_map.get(url, [])

        # Choose wordlist
        category = "API" if "API" in tags else "ADMIN" if "ADMIN" in tags else "default"
        wordlist  = _resolve_wordlist(category)

        out_file = self.output / f"ffuf_{target['domain'].replace('.','_')}.json"

        log(f"[fuzz] Fuzzing {url} with {category} wordlist", Colors.YELLOW)

        cmd = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-o", str(out_file),
            "-of", "json",
            "-mc", "200,201,204,301,302,307,401,403",  # interesting codes
            "-t", "50",          # threads
            "-timeout", "10",
            "-r",                # follow redirects
            "-recursion",        # recursive fuzzing
            "-recursion-depth", "2",
            "-c",                # colorize
            "-ic",               # ignore comments in wordlist
            "-rate", "100",      # rate limit
        ]

        rc, out, err = run_cmd(cmd, timeout=240)

        if out_file.exists():
            import json
            try:
                with open(out_file) as f:
                    data = json.load(f)
                results_raw = data.get("results", [])
                with self._lock:
                    for r in results_raw:
                        self.results.append({
                            "url":    r.get("url", ""),
                            "status": r.get("status", 0),
                            "length": r.get("length", 0),
                            "target": url,
                            "words":  r.get("words", 0),
                            "time":   str(datetime.now()),
                        })
                log(f"[fuzz] {url} → {len(results_raw)} results", Colors.GREEN)
            except Exception as e:
                log(f"[fuzz] Parse error for {url}: {e}", Colors.YELLOW)

        # Also fuzz parameters
        self._param_fuzz(url)

    def _param_fuzz(self, url: str):
        """Fuzz common parameters on discovered endpoints."""
        wordlist = _resolve_wordlist("params")
        out_file = self.output / f"params_{url.replace('/', '_').replace(':', '')[:50]}.json"

        cmd = [
            "ffuf",
            "-u", f"{url}?FUZZ=test",
            "-w", wordlist,
            "-o", str(out_file),
            "-of", "json",
            "-mc", "200,201,301,302",
            "-t", "30",
            "-timeout", "10",
            "-fs", "0",          # filter empty responses
        ]

        run_cmd(cmd, timeout=120)

    def _write_results(self):
        out = self.output / "fuzzing_results.txt"
        with open(out, "w") as f:
            f.write("# BugHunter Pro — Fuzzing Results\n")
            f.write(f"# Generated: {datetime.now()}\n\n")
            for r in sorted(self.results, key=lambda x: x.get("status", 0)):
                status = r.get("status", "?")
                url    = r.get("url", "")
                length = r.get("length", 0)
                emoji  = "🔥" if status in (200, 201) else "⚠️"
                f.write(f"{emoji} [{status}] {url} (size: {length})\n")

        log(f"[fuzz] fuzzing_results.txt written — {len(self.results)} discoveries", Colors.GREEN)
