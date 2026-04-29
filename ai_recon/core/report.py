"""Report generation: JSON, Markdown, HTML, and SARIF 2.1.0."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ai_recon.core.models import Finding, Report

# Severity → SARIF level mapping
_SARIF_LEVEL = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}

_SEVERITY_EMOJI = {
    "info": "ℹ️",
    "low": "🟡",
    "medium": "🟠",
    "high": "🔴",
    "critical": "🚨",
}


class ReportEmitter:
    """Serialises a Report to various formats."""

    def __init__(self, report: Report) -> None:
        self._r = report

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        return self._r.model_dump_json(indent=indent)

    def write_json(self, path: Path) -> None:
        path.write_text(self.to_json())

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def to_markdown(self) -> str:
        r = self._r
        lines: list[str] = [
            f"# ai-recon Report — {r.scope.engagement.name}",
            "",
            f"**Run ID:** `{r.run_id}`  ",
            f"**Profile:** `{r.profile}`  ",
            f"**Started:** {r.started_at.isoformat()}  ",
            f"**Finished:** {r.finished_at.isoformat()}  ",
            f"**Authorization:** `{r.scope.engagement.authorization_ref}`  ",
            "",
        ]
        if r.diff_vs:
            lines += [f"> Diffed against run `{r.diff_vs}`", ""]

        # Findings summary
        counts: dict[str, int] = {}
        for f in r.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        lines += ["## Summary", ""]
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in counts:
                lines.append(f"- {_SEVERITY_EMOJI[sev]} **{sev.upper()}**: {counts[sev]}")
        lines.append("")

        # Model profiles
        if r.model_profiles:
            lines += ["## Model Profiles", ""]
            for tid, mp in r.model_profiles.items():
                lines += [
                    f"### Target `{tid}`",
                    f"- Vendor: `{mp.vendor or '?'}`  Family: `{mp.family or '?'}`  "
                    f"Size: `{mp.size_hint or '?'}`",
                    f"- Cutoff: `{mp.knowledge_cutoff or '?'}`  "
                    f"Context window: `{mp.context_window or '?'}` tokens",
                    f"- Tokenizer: `{mp.tokenizer or '?'}`  "
                    f"Confidence: `{mp.confidence:.0%}`",
                    "",
                ]

        # RAG profiles
        if r.rag_profiles:
            lines += ["## RAG Profiles", ""]
            for tid, rp in r.rag_profiles.items():
                lines += [
                    f"### Target `{tid}`",
                    f"- Detected: `{rp.detected}`  "
                    f"Exposure: `{rp.exposure_level}`  "
                    f"Vector store: `{rp.vector_store or '?'}`",
                    f"- Embedding: `{rp.embedding_model or '?'}`  "
                    f"Threshold: `{rp.inferred_threshold or '?'}`",
                    f"- Documents indexed: {len(rp.documents)}",
                    "",
                ]

        # Findings detail
        lines += ["## Findings", ""]
        for sev in ("critical", "high", "medium", "low", "info"):
            sevfinds = [f for f in r.findings if f.severity == sev]
            if not sevfinds:
                continue
            lines += [f"### {_SEVERITY_EMOJI[sev]} {sev.upper()}", ""]
            for f in sevfinds:
                lines += [
                    f"#### {f.title}",
                    f"- **ID:** `{f.id}`  **Technique:** `{f.technique}`  "
                    f"**Target:** `{f.target_id}`",
                    f"- **Confidence:** `{f.confidence}`  "
                    f"**Intrusiveness:** `{f.intrusiveness}`  "
                    f"**At:** {f.detected_at.isoformat()}",
                    "",
                ]
                if f.evidence:
                    lines += ["<details><summary>Evidence</summary>", "", "```json"]
                    lines.append(json.dumps(f.evidence, indent=2, default=str))
                    lines += ["```", "", "</details>", ""]
                if f.references:
                    lines += ["**References:**"]
                    for ref in f.references:
                        lines.append(f"- {ref}")
                    lines.append("")

        return "\n".join(lines)

    def write_markdown(self, path: Path) -> None:
        path.write_text(self.to_markdown())

    # ------------------------------------------------------------------
    # SARIF 2.1.0
    # ------------------------------------------------------------------

    def to_sarif(self) -> dict[str, Any]:
        r = self._r
        rules: list[dict] = []
        seen_rules: set[str] = set()
        results: list[dict] = []

        for f in r.findings:
            if f.technique not in seen_rules:
                seen_rules.add(f.technique)
                rules.append({
                    "id": f.technique,
                    "name": f.technique.replace(".", "_"),
                    "shortDescription": {"text": f.technique},
                    "properties": {"intrusiveness": f.intrusiveness},
                })
            results.append({
                "ruleId": f.technique,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.title},
                "properties": {
                    "confidence": f.confidence,
                    "target_id": f.target_id,
                    "severity": f.severity,
                    "evidence": f.evidence,
                },
            })

        return {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ai-recon",
                            "version": "0.1.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "run_id": r.run_id,
                        "profile": r.profile,
                        "engagement": r.scope.engagement.name,
                    },
                }
            ],
        }

    def write_sarif(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_sarif(), indent=2))

    # ------------------------------------------------------------------
    # HTML (visual dashboard, self-contained)
    # ------------------------------------------------------------------

    def to_html(self) -> str:
        return _render_html(self._r)

    def write_html(self, path: Path) -> None:
        path.write_text(self.to_html())

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    @staticmethod
    def diff(base: Report, head: Report) -> dict[str, Any]:
        base_ids = {f.id for f in base.findings}
        head_ids = {f.id for f in head.findings}
        new_findings = [f for f in head.findings if f.id not in base_ids]
        resolved = [f for f in base.findings if f.id not in head_ids]
        return {
            "base_run_id": base.run_id,
            "head_run_id": head.run_id,
            "new_findings": [f.model_dump() for f in new_findings],
            "resolved_findings": [f.model_dump() for f in resolved],
            "new_count": len(new_findings),
            "resolved_count": len(resolved),
        }


# =============================================================================
# Visual HTML renderer (self-contained, no external assets)
# =============================================================================

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_COLOR = {
    "critical": "#7f1d1d",
    "high":     "#dc2626",
    "medium":   "#ea580c",
    "low":      "#ca8a04",
    "info":     "#2563eb",
}


def _esc(s: Any) -> str:
    if s is None:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _json_pretty(obj: Any) -> str:
    try:
        return json.dumps(obj, indent=2, default=str, ensure_ascii=False)
    except Exception:
        return str(obj)


def _render_html(r: Report) -> str:
    counts = {s: 0 for s in _SEV_ORDER}
    for f in r.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    total = sum(counts.values())

    by_tech: dict[str, int] = {}
    for f in r.findings:
        by_tech[f.technique] = by_tech.get(f.technique, 0) + 1
    tech_rows = sorted(by_tech.items(), key=lambda x: -x[1])

    # Severity bars
    sev_cards = "".join(
        f'''<div class="sev-card" style="--c:{_SEV_COLOR[s]}">
              <div class="sev-num">{counts[s]}</div>
              <div class="sev-lbl">{s.upper()}</div>
            </div>''' for s in _SEV_ORDER if counts[s] > 0
    ) or '<div class="muted">No findings</div>'

    # Model profiles
    mp_html = ""
    if r.model_profiles:
        rows = []
        for tid, mp in r.model_profiles.items():
            rows.append(f"""
              <tr>
                <td><code>{_esc(tid)}</code></td>
                <td>{_esc(mp.vendor or '?')}</td>
                <td>{_esc(mp.family or '?')}</td>
                <td>{_esc(mp.size_hint or '?')}</td>
                <td>{_esc(mp.tokenizer or '?')}</td>
                <td>{_esc(mp.knowledge_cutoff or '?')}</td>
                <td>{_esc(mp.context_window or '?')}</td>
                <td>{mp.confidence:.0%}</td>
              </tr>""")
        mp_html = f"""
          <h2>Model profiles</h2>
          <table class="data">
            <thead><tr>
              <th>Target</th><th>Vendor</th><th>Family</th><th>Size</th>
              <th>Tokenizer</th><th>Cutoff</th><th>Ctx</th><th>Conf.</th>
            </tr></thead>
            <tbody>{''.join(rows)}</tbody>
          </table>"""

    # RAG profiles
    rag_html = ""
    if r.rag_profiles:
        rows = []
        for tid, rp in r.rag_profiles.items():
            rows.append(f"""
              <tr>
                <td><code>{_esc(tid)}</code></td>
                <td>{'✅' if rp.detected else '❌'}</td>
                <td>{_esc(rp.exposure_level)}</td>
                <td>{_esc(rp.vector_store or '?')}</td>
                <td>{_esc(rp.embedding_model or '?')}</td>
                <td>{_esc(rp.inferred_threshold or '?')}</td>
                <td>{len(rp.documents)}</td>
              </tr>""")
        rag_html = f"""
          <h2>RAG profiles</h2>
          <table class="data">
            <thead><tr>
              <th>Target</th><th>Detected</th><th>Exposure</th>
              <th>Vector store</th><th>Embedding</th><th>Threshold</th><th>Docs</th>
            </tr></thead>
            <tbody>{''.join(rows)}</tbody>
          </table>"""

    # Techniques table
    tech_html = ""
    if tech_rows:
        rows = "".join(
            f'<tr><td><code>{_esc(t)}</code></td><td class="num">{n}</td></tr>'
            for t, n in tech_rows
        )
        tech_html = f"""
          <h2>Findings by technique</h2>
          <table class="data">
            <thead><tr><th>Technique</th><th>Count</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>"""

    # Findings detail
    finds_html_parts: list[str] = []
    for sev in _SEV_ORDER:
        sf = [f for f in r.findings if f.severity == sev]
        if not sf:
            continue
        cards = []
        for f in sf:
            ev = ""
            if f.evidence:
                ev = (
                    f'<details><summary>Evidence</summary>'
                    f'<pre>{_esc(_json_pretty(f.evidence))}</pre></details>'
                )
            refs = ""
            if f.references:
                refs = "<ul class='refs'>" + "".join(
                    f'<li><a href="{_esc(x)}" target="_blank" rel="noopener">{_esc(x)}</a></li>'
                    for x in f.references
                ) + "</ul>"
            cards.append(f"""
              <article class="finding" data-sev="{sev}" data-tech="{_esc(f.technique)}">
                <header>
                  <span class="sev-pill" style="background:{_SEV_COLOR[sev]}">{sev.upper()}</span>
                  <h4>{_esc(f.title)}</h4>
                </header>
                <div class="meta">
                  <span><b>Technique:</b> <code>{_esc(f.technique)}</code></span>
                  <span><b>Target:</b> <code>{_esc(f.target_id)}</code></span>
                  <span><b>Confidence:</b> {_esc(f.confidence)}</span>
                  <span><b>Intrusiveness:</b> {_esc(f.intrusiveness)}</span>
                  <span><b>Detected:</b> {_esc(f.detected_at.isoformat())}</span>
                  <span class="id"><code>{_esc(f.id)}</code></span>
                </div>
                {ev}
                {refs}
              </article>""")
        # critical/high open by default; medium/low/info collapsed
        is_open = "open" if sev in ("critical", "high", "medium") else ""
        finds_html_parts.append(f"""
          <details class="sev-group" data-sev="{sev}" {is_open} style="--c:{_SEV_COLOR[sev]}">
            <summary>
              <span class="sev-pill" style="background:{_SEV_COLOR[sev]}">{sev.upper()}</span>
              <span class="sev-count">{len(sf)} finding{'s' if len(sf)!=1 else ''}</span>
              <span class="chev">▾</span>
            </summary>
            <div class="sev-body">
              {''.join(cards)}
            </div>
          </details>""")
    findings_html = "".join(finds_html_parts) or '<p class="muted">No findings collected.</p>'

    eng = r.scope.engagement
    title = _esc(eng.name or "ai-recon")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ai-recon — {title}</title>
<style>
  :root {{
    --bg: #0b1020; --panel: #131a30; --ink: #e6edf3; --muted: #8b97b1;
    --accent: #4f46e5; --border: #1f2a44;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ background: var(--bg); color: var(--ink); margin: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         line-height: 1.45; }}
  .wrap {{ max-width: 1180px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
  header.top {{ display: flex; align-items: baseline; justify-content: space-between;
                gap: 1rem; flex-wrap: wrap; border-bottom: 1px solid var(--border);
                padding-bottom: 1rem; margin-bottom: 1.5rem; }}
  header.top h1 {{ margin: 0; font-size: 1.5rem; }}
  header.top h1 small {{ color: var(--muted); font-weight: 400; font-size: .9rem; }}
  .pill {{ display: inline-block; padding: .15rem .55rem; border-radius: 999px;
          background: var(--panel); border: 1px solid var(--border);
          font-family: var(--mono); font-size: .8rem; color: var(--muted); }}
  .grid {{ display: grid; gap: 1rem; }}
  .grid.kpis {{ grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); }}
  .grid.two   {{ grid-template-columns: 1fr 1fr; }}
  @media (max-width: 800px) {{ .grid.two {{ grid-template-columns: 1fr; }} }}
  .panel {{ background: var(--panel); border: 1px solid var(--border);
            border-radius: 10px; padding: 1rem 1.25rem; }}
  h2 {{ margin: 1.5rem 0 .75rem; font-size: 1.1rem; letter-spacing: .02em; }}
  h2::before {{ content: "▌ "; color: var(--accent); }}
  .sev-card {{ border: 1px solid var(--border); background: var(--panel);
              border-radius: 10px; padding: .9rem 1rem; text-align: center;
              border-left: 4px solid var(--c); }}
  .sev-num {{ font-size: 1.8rem; font-weight: 700; color: var(--c); font-family: var(--mono); }}
  .sev-lbl {{ font-size: .75rem; letter-spacing: .12em; color: var(--muted); }}
  table.data {{ width: 100%; border-collapse: collapse; font-size: .9rem;
                background: var(--panel); border-radius: 8px; overflow: hidden;
                border: 1px solid var(--border); }}
  table.data th, table.data td {{ padding: .55rem .75rem; text-align: left;
                                  border-bottom: 1px solid var(--border); }}
  table.data thead th {{ background: #182142; font-weight: 600; font-size: .75rem;
                         text-transform: uppercase; letter-spacing: .08em;
                         color: var(--muted); }}
  table.data td.num {{ text-align: right; font-family: var(--mono); }}
  table.data tbody tr:last-child td {{ border-bottom: none; }}
  code {{ font-family: var(--mono); font-size: .85em;
          background: #0f1530; padding: 1px 5px; border-radius: 4px;
          color: #d2dafe; border: 1px solid var(--border); }}
  .sev-pill {{ display: inline-block; padding: .12rem .55rem; font-size: .7rem;
              letter-spacing: .1em; font-weight: 700; color: white;
              border-radius: 4px; vertical-align: middle; }}
  .sev-h {{ margin-top: 1.75rem; padding-bottom: .35rem;
           border-bottom: 2px solid var(--c); color: var(--c); }}
  article.finding {{ background: var(--panel); border: 1px solid var(--border);
                     border-left: 4px solid var(--c, #999);
                     border-radius: 8px; padding: .85rem 1rem; margin: .65rem 0; }}
  article.finding[data-sev="critical"] {{ --c: {_SEV_COLOR['critical']}; }}
  article.finding[data-sev="high"]     {{ --c: {_SEV_COLOR['high']}; }}
  article.finding[data-sev="medium"]   {{ --c: {_SEV_COLOR['medium']}; }}
  article.finding[data-sev="low"]      {{ --c: {_SEV_COLOR['low']}; }}
  article.finding[data-sev="info"]     {{ --c: {_SEV_COLOR['info']}; }}
  article.finding header {{ display: flex; align-items: center; gap: .65rem; }}
  article.finding h4 {{ margin: 0; font-size: 1rem; }}
  .meta {{ display: flex; flex-wrap: wrap; gap: .35rem 1rem; font-size: .8rem;
          color: var(--muted); margin: .5rem 0 .25rem; }}
  .meta b {{ color: #cdd5e8; font-weight: 600; }}
  .meta .id {{ margin-left: auto; opacity: .55; }}
  details {{ margin-top: .5rem; }}
  details > summary {{ cursor: pointer; color: var(--muted); font-size: .85rem;
                       user-select: none; }}
  details[open] > summary {{ color: var(--ink); }}
  details.sev-group {{ background: var(--panel); border: 1px solid var(--border);
                       border-left: 4px solid var(--c); border-radius: 8px;
                       margin: .65rem 0; padding: 0; }}
  details.sev-group > summary {{ list-style: none; display: flex;
                                 align-items: center; gap: .65rem;
                                 padding: .75rem 1rem; font-size: .95rem;
                                 color: var(--ink); }}
  details.sev-group > summary::-webkit-details-marker {{ display: none; }}
  details.sev-group .sev-count {{ color: var(--muted); font-size: .85rem; }}
  details.sev-group .chev {{ margin-left: auto; color: var(--muted);
                             transition: transform .15s ease; }}
  details.sev-group[open] .chev {{ transform: rotate(180deg); }}
  details.sev-group .sev-body {{ padding: .25rem 1rem 1rem; }}
  details.sev-group .finding {{ margin: .5rem 0; }}
  pre {{ background: #060a18; border: 1px solid var(--border); border-radius: 6px;
         padding: .75rem; overflow-x: auto; font-family: var(--mono); font-size: .8rem;
         margin: .5rem 0 0; }}
  ul.refs {{ margin: .35rem 0 0 1rem; padding: 0; font-size: .85rem; }}
  ul.refs a {{ color: #93b9ff; }}
  .muted {{ color: var(--muted); }}
  .toolbar {{ display: flex; gap: .5rem; flex-wrap: wrap; margin: 1rem 0; }}
  .toolbar input, .toolbar select, .toolbar button {{
    background: var(--panel); color: var(--ink); border: 1px solid var(--border);
    border-radius: 6px; padding: .4rem .65rem; font-size: .9rem; font-family: inherit;
  }}
  .toolbar button {{ cursor: pointer; }}
  .toolbar button:hover {{ background: #1a2350; }}
  .toolbar input {{ flex: 1; min-width: 200px; }}
  footer {{ margin-top: 3rem; color: var(--muted); font-size: .75rem; text-align: center; }}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div>
      <h1>ai-recon &middot; {title} <small>— recon report</small></h1>
      <div class="muted" style="font-size:.85rem;margin-top:.25rem;">
        <span class="pill">run <code>{_esc(r.run_id)}</code></span>
        <span class="pill">profile <code>{_esc(r.profile)}</code></span>
        <span class="pill">auth <code>{_esc(eng.authorization_ref or '—')}</code></span>
        <span class="pill">started {_esc(r.started_at.isoformat())}</span>
        <span class="pill">finished {_esc(r.finished_at.isoformat())}</span>
      </div>
    </div>
    <div class="muted" style="font-size:.85rem;text-align:right;">
      <div><b style="color:var(--ink)">{total}</b> findings</div>
      {f'<div>diff vs <code>{_esc(r.diff_vs)}</code></div>' if r.diff_vs else ''}
    </div>
  </header>

  <h2>Severity overview</h2>
  <div class="grid kpis">{sev_cards}</div>

  <div class="grid two" style="margin-top:1rem;">
    <div>{tech_html}</div>
    <div>{mp_html}{rag_html}</div>
  </div>

  <h2>Findings</h2>
  <div class="toolbar">
    <input id="q" type="search" placeholder="Filter by title, technique, target…">
    <select id="fsev">
      <option value="">All severities (open by default)</option>
      {''.join(f'<option value="{s}">Only {s.upper()}</option>' for s in _SEV_ORDER if counts[s] > 0)}
    </select>
    <button id="toggle-all" type="button">Expand / collapse all</button>
  </div>
  <div id="findings">
    {findings_html}
  </div>

  <footer>Generated by ai-recon · self-contained HTML report · open in any browser</footer>
</div>
<script>
(function() {{
  const q = document.getElementById('q');
  const fsev = document.getElementById('fsev');
  const toggle = document.getElementById('toggle-all');
  const groups = Array.from(document.querySelectorAll('details.sev-group'));
  const items = Array.from(document.querySelectorAll('article.finding'));

  function apply() {{
    const term = (q.value || '').toLowerCase().trim();
    const sev = fsev.value;

    items.forEach(el => {{
      const text = el.innerText.toLowerCase();
      const okSev = !sev || el.dataset.sev === sev;
      const okTxt = !term || text.includes(term);
      el.style.display = (okSev && okTxt) ? '' : 'none';
    }});

    groups.forEach(g => {{
      const visible = g.querySelectorAll('article.finding:not([style*="display: none"])').length;
      const matchesFilter = !sev || g.dataset.sev === sev;
      g.style.display = (visible > 0 && matchesFilter) ? '' : 'none';
      // when filtering by severity, force open the matching group
      if (sev && g.dataset.sev === sev) g.open = true;
    }});
  }}

  q.addEventListener('input', apply);
  fsev.addEventListener('change', apply);
  toggle.addEventListener('click', () => {{
    const anyClosed = groups.some(g => !g.open);
    groups.forEach(g => {{ g.open = anyClosed; }});
  }});
}})();
</script>
</body>
</html>"""
