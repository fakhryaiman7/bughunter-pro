"""
learning_engine.py — Learning Engine
Stores previous findings in JSON knowledge base.
Matches patterns on new targets to boost scoring.
Learns from confirmed vulnerabilities.
"""

import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

from utils import log, Colors, load_json, save_json


# ─────────────────────────────────────────────
#  LearningEngine
# ─────────────────────────────────────────────

class LearningEngine:
    def __init__(self, kb_path: Path):
        self.kb_path = kb_path
        self.kb_path.parent.mkdir(parents=True, exist_ok=True)
        self.kb = load_json(self.kb_path, default={
            "version": "1.0",
            "created": str(datetime.now()),
            "runs": 0,
            "findings": [],
            "patterns": [],
            "stats": {
                "total_targets": 0,
                "total_vulns": 0,
                "high_value_types": {},
            }
        })

    # ── Update knowledge base ─────────────────
    def update(self, scored: List[Dict[str, Any]]):
        """Store current run's findings into the knowledge base."""
        self.kb["runs"] += 1
        self.kb["stats"]["total_targets"] += len(scored)

        for target in scored:
            if target["score"] >= 50:
                entry = {
                    "url":    target["url"],
                    "domain": target["domain"],
                    "score":  target["score"],
                    "tags":   target["tags"],
                    "tech":   target["tech"],
                    "seen":   str(datetime.now()),
                }
                # avoid duplicates
                existing_urls = {f["url"] for f in self.kb["findings"]}
                if entry["url"] not in existing_urls:
                    self.kb["findings"].append(entry)

        # extract learned patterns
        self._extract_patterns(scored)

        save_json(self.kb_path, self.kb)
        log(f"[learn] Knowledge base updated — {len(self.kb['findings'])} findings stored", Colors.MAGENTA)

    def record_vuln(self, vuln_type: str, url: str, severity: str):
        """Call this after a confirmed vulnerability to reinforce learning."""
        stats = self.kb["stats"]["high_value_types"]
        stats[vuln_type] = stats.get(vuln_type, 0) + 1
        self.kb["stats"]["total_vulns"] += 1

        # Add URL pattern as learned pattern
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        parts  = re.split(r"[.\-_/]", domain)
        for part in parts:
            if len(part) > 3 and part not in self.kb["patterns"]:
                self.kb["patterns"].append(part)

        save_json(self.kb_path, self.kb)

    # ── Extract patterns from high-value targets
    def _extract_patterns(self, scored: List[Dict]):
        """Learn keyword patterns from high-scoring targets."""
        for t in scored:
            if t["score"] < 60:
                continue
            parts = re.split(r"[.\-_/:]", t["url"])
            for part in parts:
                if (len(part) > 3 and part not in ("http", "https", "www", "com", "net", "org")
                        and part not in self.kb["patterns"]):
                    self.kb["patterns"].append(part)

    # ── Match patterns on new targets ─────────
    def match_patterns(self, scored: List[Dict]) -> List[Dict]:
        """
        Compare current targets against stored knowledge.
        Returns list of targets that match previously seen patterns.
        """
        patterns = self.kb.get("patterns", [])
        if not patterns:
            return []

        hits = []
        for target in scored:
            url_lower = target["url"].lower()
            matched = [p for p in patterns if p.lower() in url_lower]
            if matched:
                target["matched_patterns"] = matched
                hits.append(target)
                log(f"[learn] 🧠 Pattern match: {target['url']} → {matched}", Colors.MAGENTA)

        return hits

    # ── Stats ─────────────────────────────────
    def get_stats(self) -> Dict:
        return {
            "runs":          self.kb["runs"],
            "total_findings":len(self.kb["findings"]),
            "patterns_known":len(self.kb["patterns"]),
            "top_vuln_types":sorted(
                self.kb["stats"]["high_value_types"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5],
        }

    def print_stats(self):
        stats = self.get_stats()
        log(f"[learn] Runs: {stats['runs']} | Findings: {stats['total_findings']} | "
            f"Patterns: {stats['patterns_known']}", Colors.MAGENTA)
        if stats["top_vuln_types"]:
            log(f"[learn] Top vuln types: {stats['top_vuln_types']}", Colors.MAGENTA)
