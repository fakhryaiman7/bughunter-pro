"""
report_engine.py — HTML Report Generator  v1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Generates a professional, dark-themed HTML report with:
  ✅ Executive summary dashboard
  ✅ Interactive vulnerability table
  ✅ Severity breakdown charts
  ✅ Target prioritization list
  ✅ Pattern match insights
  ✅ Full finding details with remediation
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

from utils import log, Colors


# ─────────────────────────────────────────────
#  HTML Template
# ─────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>BugHunter Pro — Security Report — {target}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --text-muted: #8b949e; --accent: #58a6ff;
    --red: #f85149; --orange: #d29922; --yellow: #e3b341;
    --green: #3fb950; --blue: #58a6ff; --purple: #bc8cff;
    --critical: #da3633; --high: #e05c4b; --medium: #e3b341;
    --low: #3fb950; --info: #8b949e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
  }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* Header */
  .header {{
    background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
    border-bottom: 1px solid var(--border);
    padding: 2rem 3rem;
    display: flex; align-items: center; gap: 1.5rem;
  }}
  .logo {{ font-size: 2.5rem; }}
  .header-text h1 {{ font-size: 1.8rem; color: var(--accent); font-weight: 700; }}
  .header-text .meta {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem; }}
  .legal {{
    background: #2d1f00; border: 1px solid #d29922; color: #e3b341;
    padding: 0.6rem 1.5rem; border-radius: 6px; font-size: 0.85rem;
    margin-left: auto;
  }}

  /* Container */
  .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem 3rem; }}

  /* Stats Grid */
  .stats-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem; margin-bottom: 2rem;
  }}
  .stat-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.25rem; text-align: center;
    transition: transform 0.2s;
  }}
  .stat-card:hover {{ transform: translateY(-2px); }}
  .stat-card .number {{ font-size: 2.2rem; font-weight: 700; }}
  .stat-card .label {{ color: var(--text-muted); font-size: 0.85rem; margin-top: 0.25rem; }}
  .stat-critical .number {{ color: var(--critical); }}
  .stat-high .number {{ color: var(--high); }}
  .stat-medium .number {{ color: var(--medium); }}
  .stat-low .number {{ color: var(--low); }}
  .stat-info .number {{ color: var(--info); }}
  .stat-targets .number {{ color: var(--accent); }}

  /* Section */
  .section {{ margin-bottom: 2.5rem; }}
  .section-title {{
    font-size: 1.1rem; font-weight: 600; color: var(--accent);
    border-bottom: 1px solid var(--border); padding-bottom: 0.5rem;
    margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;
  }}

  /* Vuln Table */
  .vuln-table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  .vuln-table th {{
    background: var(--surface); color: var(--text-muted); font-weight: 600;
    padding: 0.75rem 1rem; text-align: left; border-bottom: 2px solid var(--border);
    white-space: nowrap;
  }}
  .vuln-table td {{
    padding: 0.75rem 1rem; border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  .vuln-table tr:hover td {{ background: rgba(88, 166, 255, 0.05); }}
  .vuln-table .url {{
    font-family: monospace; font-size: 0.82rem; color: var(--accent);
    max-width: 300px; overflow: hidden; text-overflow: ellipsis;
    white-space: nowrap; display: block;
  }}

  /* Severity badges */
  .badge {{
    display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
    font-size: 0.78rem; font-weight: 700; white-space: nowrap;
  }}
  .badge-CRITICAL {{ background: rgba(218,54,51,0.2); color: #f85149; border: 1px solid #da3633; }}
  .badge-HIGH     {{ background: rgba(224,92,75,0.2); color: #ffa657; border: 1px solid #e05c4b; }}
  .badge-MEDIUM   {{ background: rgba(227,179,65,0.2); color: #e3b341; border: 1px solid #d29922; }}
  .badge-LOW      {{ background: rgba(63,185,80,0.2);  color: #3fb950; border: 1px solid #238636; }}
  .badge-INFO     {{ background: rgba(139,148,158,0.2);color: #8b949e; border: 1px solid #30363d; }}

  /* Target list */
  .target-list {{ list-style: none; }}
  .target-item {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 0.5rem;
    display: flex; align-items: center; gap: 1rem;
  }}
  .score-badge {{
    display: inline-flex; align-items: center; justify-content: center;
    min-width: 48px; height: 28px; border-radius: 4px; font-weight: 700;
    font-size: 0.85rem; flex-shrink: 0;
  }}
  .score-high  {{ background: rgba(218,54,51,0.2); color: #f85149; }}
  .score-med   {{ background: rgba(227,179,65,0.2); color: #e3b341; }}
  .score-low   {{ background: rgba(63,185,80,0.2);  color: #3fb950; }}

  .tag {{
    display: inline-block; padding: 0.15rem 0.4rem; margin: 0 0.1rem;
    border: 1px solid var(--border); border-radius: 3px;
    font-size: 0.75rem; color: var(--text-muted);
  }}

  /* Finding cards */
  .finding-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; margin-bottom: 1rem; overflow: hidden;
  }}
  .finding-header {{
    padding: 0.75rem 1rem; display: flex; align-items: center; gap: 0.75rem;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
  }}
  .finding-header:hover {{ background: rgba(88,166,255,0.05); }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .finding-body {{ padding: 1rem; font-size: 0.9rem; }}
  .finding-body .field {{ margin-bottom: 0.75rem; }}
  .finding-body .field-label {{
    color: var(--text-muted); font-size: 0.8rem; margin-bottom: 0.2rem;
    text-transform: uppercase; letter-spacing: 0.05em;
  }}
  .finding-body .field-value {{
    font-family: monospace; font-size: 0.85rem; background: #0d1117;
    padding: 0.5rem 0.75rem; border-radius: 4px; overflow-x: auto;
    white-space: pre-wrap; word-break: break-all;
  }}
  .rec {{ background: rgba(63,185,80,0.08); padding: 0.6rem 0.9rem; border-radius: 4px;
          border-left: 3px solid var(--green); font-size: 0.88rem; }}

  /* Filter bar */
  .filter-bar {{
    display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap;
  }}
  .filter-btn {{
    padding: 0.4rem 1rem; border-radius: 20px; border: 1px solid var(--border);
    background: var(--surface); color: var(--text-muted); cursor: pointer;
    font-size: 0.85rem; transition: all 0.2s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    border-color: var(--accent); color: var(--accent);
    background: rgba(88,166,255,0.1);
  }}

  /* Footer */
  .footer {{
    text-align: center; padding: 2rem; color: var(--text-muted);
    font-size: 0.85rem; border-top: 1px solid var(--border);
    margin-top: 3rem;
  }}

  /* Scrollbar */
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
</style>
</head>
<body>

<div class="header">
  <div class="logo">🔍</div>
  <div class="header-text">
    <h1>BugHunter Pro — Security Report</h1>
    <div class="meta">Target: <strong>{target}</strong> &nbsp;|&nbsp; Generated: {timestamp} &nbsp;|&nbsp; v2.0</div>
  </div>
  <div class="legal">⚠ Authorized Testing Only</div>
</div>

<div class="container">

  <!-- Stats -->
  <div class="section">
    <div class="section-title">📊 Executive Summary</div>
    <div class="stats-grid">
      <div class="stat-card stat-critical">
        <div class="number">{cnt_critical}</div>
        <div class="label">CRITICAL</div>
      </div>
      <div class="stat-card stat-high">
        <div class="number">{cnt_high}</div>
        <div class="label">HIGH</div>
      </div>
      <div class="stat-card stat-medium">
        <div class="number">{cnt_medium}</div>
        <div class="label">MEDIUM</div>
      </div>
      <div class="stat-card stat-low">
        <div class="number">{cnt_low}</div>
        <div class="label">LOW / INFO</div>
      </div>
      <div class="stat-card stat-targets">
        <div class="number">{cnt_targets}</div>
        <div class="label">Live Targets</div>
      </div>
      <div class="stat-card stat-targets">
        <div class="number">{cnt_high_val}</div>
        <div class="label">High-Value</div>
      </div>
    </div>
  </div>

  <!-- Vulnerability Table -->
  <div class="section">
    <div class="section-title">🔥 Findings</div>
    <div class="filter-bar" id="filterBar">
      <button class="filter-btn active" onclick="filterFindings('ALL')">All</button>
      <button class="filter-btn" onclick="filterFindings('CRITICAL')" style="color:#f85149">🔴 Critical</button>
      <button class="filter-btn" onclick="filterFindings('HIGH')" style="color:#ffa657">🟠 High</button>
      <button class="filter-btn" onclick="filterFindings('MEDIUM')" style="color:#e3b341">🟡 Medium</button>
      <button class="filter-btn" onclick="filterFindings('LOW')" style="color:#3fb950">🟢 Low</button>
      <button class="filter-btn" onclick="filterFindings('INFO')" style="color:#8b949e">⚪ Info</button>
    </div>
    <div id="findingsContainer">
      {findings_html}
    </div>
  </div>

  <!-- Prioritized Targets -->
  <div class="section">
    <div class="section-title">🎯 Prioritized Targets</div>
    <ul class="target-list">
      {targets_html}
    </ul>
  </div>

</div>

<div class="footer">
  BugHunter Pro v2.0 &nbsp;|&nbsp; For authorized security research only &nbsp;|&nbsp; {timestamp}
</div>

<script>
  function filterFindings(severity) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.finding-card').forEach(card => {{
      if (severity === 'ALL' || card.dataset.severity === severity) {{
        card.style.display = '';
      }} else {{
        card.style.display = 'none';
      }}
    }});
  }}
</script>
</body>
</html>
"""


from core import PipelineContext, PipelineConfig, DependencyGuard

# ─────────────────────────────────────────────
#  ReportEngine
# ─────────────────────────────────────────────

class ReportEngine:
    def __init__(self, config: PipelineConfig, context: PipelineContext, deps: DependencyGuard):
        self.config = config
        self.context = context
        self.deps = deps
        self.output = context.output
        self.target = context.target

    def generate(self, findings: List[Dict], targets: List[Dict],
                 pattern_hits: List[Dict]) -> str:
        """Generate HTML report. Returns path to generated file."""
        log("[report] 📄 Generating HTML report...", Colors.CYAN)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda x: sev_order.get(x.get("severity", "INFO"), 99))

        findings_html = self._build_findings_html(sorted_findings)
        targets_html  = self._build_targets_html(targets)

        cnt = {sev: sum(1 for f in findings if f.get("severity") == sev)
               for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}

        html = HTML_TEMPLATE.format(
            target       = self.target,
            timestamp    = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            cnt_critical = cnt["CRITICAL"],
            cnt_high     = cnt["HIGH"],
            cnt_medium   = cnt["MEDIUM"],
            cnt_low      = cnt["LOW"] + cnt["INFO"],
            cnt_targets  = len(targets),
            cnt_high_val = sum(1 for t in targets if t.get("score", 0) >= 60),
            findings_html = findings_html,
            targets_html  = targets_html,
        )

        out = self.output / "report.html"
        with open(out, "w", encoding="utf-8") as f:
            f.write(html)

        log(f"[report] ✅ HTML report saved: {out}", Colors.GREEN)
        return str(out)

    def _build_findings_html(self, findings: List[Dict]) -> str:
        if not findings:
            return '<p style="color:var(--text-muted);padding:1rem">No findings recorded.</p>'

        parts = []
        for i, f in enumerate(findings):
            sev   = f.get("severity", "INFO")
            vtype = f.get("type", "Unknown")
            url   = f.get("url", "")
            detail = f.get("detail", "")
            rec   = f.get("recommendation", "")
            ts    = f.get("time", "")

            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                    "LOW": "🟢", "INFO": "⚪"}.get(sev, "⚪")

            parts.append(f"""
<div class="finding-card" data-severity="{sev}" id="finding-{i}">
  <div class="finding-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
    <span class="badge badge-{sev}">{icon} {sev}</span>
    <span class="finding-title">{self._esc(vtype)}</span>
    <span style="color:var(--text-muted);font-size:0.8rem">{ts[:16] if ts else ''}</span>
  </div>
  <div class="finding-body">
    <div class="field">
      <div class="field-label">URL</div>
      <div class="field-value"><a href="{self._esc(url)}" target="_blank">{self._esc(url)}</a></div>
    </div>
    <div class="field">
      <div class="field-label">Detail</div>
      <div class="field-value">{self._esc(detail)}</div>
    </div>
    {f'<div class="field"><div class="field-label">Remediation</div><div class="rec">{self._esc(rec)}</div></div>' if rec else ''}
  </div>
</div>""")

        return "\n".join(parts)

    def _build_targets_html(self, targets: List[Dict]) -> str:
        parts = []
        for t in targets[:30]:  # top 30
            score = t.get("score", 0)
            url   = t.get("url", "")
            tags  = t.get("tags", [])
            tech  = t.get("tech", [])[:3]

            score_class = "score-high" if score >= 70 else "score-med" if score >= 50 else "score-low"
            tags_html = " ".join(f'<span class="tag">{tag}</span>' for tag in tags)
            tech_html = " ".join(f'<span class="tag" style="color:var(--accent)">{t_}</span>' for t_ in tech)

            parts.append(f"""
<li class="target-item">
  <span class="score-badge {score_class}">{score}</span>
  <a href="{self._esc(url)}" target="_blank" style="font-family:monospace;font-size:0.9rem;flex:1">{self._esc(url)}</a>
  <span>{tags_html} {tech_html}</span>
</li>""")

        return "\n".join(parts)

    @staticmethod
    def _esc(text: str) -> str:
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))
