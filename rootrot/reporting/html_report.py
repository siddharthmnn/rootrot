"""render a self-contained html view of a rootrot run report."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Mapping

from .common import write_text


def _display(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    return html.escape(str(value))


def render_html_report(report: Mapping[str, Any], max_events: int = 500) -> str:
    if not isinstance(report, Mapping):
        raise TypeError("report must be an object")
    if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
        raise ValueError("max_events must be a positive integer")

    summary = report.get("forensic_summary", {})
    if not isinstance(summary, Mapping):
        summary = {}
    findings = report.get("detections", [])
    events = report.get("events", [])
    if not isinstance(findings, list):
        findings = []
    if not isinstance(events, list):
        events = []

    event_rows = []
    for event in events[:max_events]:
        if not isinstance(event, Mapping):
            continue
        event_rows.append(
            "<tr>"
            f"<td>{_display(event.get('sequence', ''))}</td>"
            f"<td>{_display(event.get('timestamp', ''))}</td>"
            f"<td>{_display(event.get('source', ''))}</td>"
            f"<td>{_display(event.get('action', ''))}</td>"
            f"<td>{_display(event.get('severity', ''))}</td>"
            "</tr>"
        )
    if not event_rows:
        event_rows.append('<tr><td colspan="5" class="muted">no events were included in this report</td></tr>')

    finding_cards = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        finding_cards.append(
            '<article class="finding">'
            f'<div class="finding-head"><strong>{_display(finding.get("rule", "unnamed rule"))}</strong>'
            f'<span class="severity">{_display(finding.get("severity", "unknown"))}</span></div>'
            f'<p>{_display(finding.get("explanation", ""))}</p>'
            f'<p class="muted">score: {_display(finding.get("score", "n/a"))} · '
            f'rule id: {_display(finding.get("rule_id", "n/a"))}</p>'
            f'<details><summary>evidence</summary><pre>{_display(finding.get("evidence", {}))}</pre></details>'
            "</article>"
        )
    if not finding_cards:
        finding_cards.append('<p class="muted">no findings were generated for this run</p>')

    safety = report.get("safety", {})
    if not isinstance(safety, Mapping):
        safety = {}
    safety_rows = "".join(
        f"<tr><th>{_display(key.replace('_', ' '))}</th><td>{_display(value)}</td></tr>"
        for key, value in sorted(safety.items())
    )
    if not safety_rows:
        safety_rows = '<tr><td colspan="2" class="muted">no safety metadata was supplied</td></tr>'

    raw_summary = _display(dict(summary))
    run_id = _display(report.get("run_id", "unknown"))
    version = _display(report.get("version", "unknown"))
    event_count = _display(summary.get("event_count", report.get("event_count", len(events))))
    finding_count = _display(summary.get("findings", {}).get("count", len(findings))
                             if isinstance(summary.get("findings", {}), Mapping)
                             else len(findings))
    integrity = summary.get("integrity", {})
    if not isinstance(integrity, Mapping):
        integrity = {}
    integrity_label = "valid" if integrity.get("valid") else "not verified"

    omitted = max(0, len(events) - max_events)
    omitted_note = (
        f'<p class="muted">showing the first {max_events} of {len(events)} events</p>'
        if omitted else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>rootrot run report</title>
  <style>
    :root {{ color-scheme: dark; --bg: #100b1d; --panel: #191126; --line: #44305f; --text: #eee8fa; --muted: #b3a6c8; --accent: #b78aff; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 32px 18px; background: var(--bg); color: var(--text); font: 15px/1.6 system-ui, sans-serif; }}
    main {{ max-width: 1120px; margin: 0 auto; }}
    header {{ border: 1px solid var(--line); border-radius: 14px; padding: 24px; background: linear-gradient(135deg, #211438, #120d1d); }}
    h1 {{ margin: 0; color: var(--accent); font: 700 34px/1.1 ui-monospace, monospace; }}
    h2 {{ margin-top: 32px; padding-bottom: 9px; border-bottom: 1px solid var(--line); font-size: 20px; }}
    .meta, .muted {{ color: var(--muted); }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 18px 0; }}
    .stat, .finding {{ border: 1px solid var(--line); border-radius: 10px; background: var(--panel); padding: 16px; }}
    .stat strong {{ display: block; color: var(--accent); font-size: 24px; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 10px; overflow: hidden; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }}
    th {{ color: var(--accent); }}
    .finding {{ margin: 12px 0; }}
    .finding-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; }}
    .severity {{ border: 1px solid var(--line); border-radius: 999px; padding: 2px 9px; color: var(--accent); font-size: 12px; }}
    pre {{ white-space: pre-wrap; overflow-wrap: anywhere; color: var(--muted); }}
    summary {{ color: var(--accent); cursor: pointer; }}
    footer {{ margin-top: 36px; color: var(--muted); font-size: 12px; }}
    @media (max-width: 600px) {{ body {{ padding: 18px 10px; }} header {{ padding: 18px; }} th, td {{ padding: 8px 6px; font-size: 12px; }} }}
  </style>
</head>
<body>
<main>
  <header>
    <h1>rootrot</h1>
    <p>run report · version {version}</p>
    <p class="meta">run id: {run_id}</p>
  </header>

  <section class="stats">
    <div class="stat"><span class="muted">events</span><strong>{event_count}</strong></div>
    <div class="stat"><span class="muted">findings</span><strong>{finding_count}</strong></div>
    <div class="stat"><span class="muted">event chain</span><strong>{_display(integrity_label)}</strong></div>
    <div class="stat"><span class="muted">profile</span><strong>{_display(report.get("profile", "unknown"))}</strong></div>
  </section>

  <h2>findings</h2>
  {''.join(finding_cards)}

  <h2>event timeline</h2>
  {omitted_note}
  <table>
    <thead><tr><th>seq</th><th>timestamp</th><th>source</th><th>action</th><th>severity</th></tr></thead>
    <tbody>{''.join(event_rows)}</tbody>
  </table>

  <h2>run safety metadata</h2>
  <table><tbody>{safety_rows}</tbody></table>

  <h2>forensic summary</h2>
  <details><summary>view summary data</summary><pre>{raw_summary}</pre></details>

  <footer>generated locally by rootrot · this report describes simulated activity, not a verdict about a real host</footer>
</main>
</body>
</html>
"""


def write_html_report(
    report: Mapping[str, Any],
    destination: str | Path,
    *,
    overwrite: bool = False,
    max_events: int = 500,
) -> dict[str, object]:
    content = render_html_report(report, max_events=max_events)
    result = write_text(destination, content, overwrite=overwrite)
    return {**result, "format": "html"}
