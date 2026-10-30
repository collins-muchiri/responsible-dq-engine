"""Report builders: JSON and self-contained HTML.

Every dynamic value rendered into the HTML report passes through
html.escape; scanned values are untrusted input. Evidence strings are
pre-masked by the scanners (PII replaced with a 2-char + asterisks + 2-char
form) and sensitive free-text disclosures appear as matched terms only.

The HTML report is fully self-contained: inline CSS only, no external
assets, no scripts.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from . import __version__
from .rules import Finding, RULES, SEVERITY_ORDER

TOOL_NAME = "rdqe"
DEFAULT_RATE = 2500.0

SEVERITY_COLORS = {
    "critical": "#FFC7CE",
    "high": "#FCE4D6",
    "medium": "#FFEB9C",
    "low": "#E2EFDA",
    "info": "#DDEBF7",
}
_NAVY = "#1F3864"


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _sorted(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.index(f.severity), f.rule_id, f.resource),
    )


def build_summary(findings: List[Finding], rate: float) -> Dict[str, Any]:
    counts: Dict[str, Any] = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    counts["total_findings"] = len(findings)
    counts["total_effort_hours"] = round(sum(f.effort_hours for f in findings), 2)
    counts["total_est_cost_kes"] = round(sum(f.est_cost(rate) for f in findings), 2)
    counts["rate_kes_per_hour"] = rate
    return counts


def build_report(findings: List[Finding], meta: Dict[str, Any], rate: float) -> Dict[str, Any]:
    return {
        "tool": TOOL_NAME,
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "meta": meta,
        "summary": build_summary(findings, rate),
        "findings": [f.to_dict(rate) for f in _sorted(findings)],
    }


def to_json(findings: List[Finding], meta: Dict[str, Any], rate: float = DEFAULT_RATE) -> str:
    """Serialize the report as pretty-printed JSON."""
    return json.dumps(build_report(findings, meta, rate), indent=2, ensure_ascii=False) + "\n"


_CSS = """
body { font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
       margin: 0; background: #f5f6f8; color: #1c2330; }
.hero { background: #1F3864; color: #ffffff; padding: 26px 36px; }
.hero h1 { margin: 0 0 6px 0; font-size: 24px; }
.hero p { margin: 2px 0; font-size: 13px; color: #d7deee; }
.chip { display: inline-block; background: rgba(255,255,255,0.14); border-radius: 4px;
        padding: 2px 8px; margin: 3px 6px 0 0; font-size: 12px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; padding: 18px 36px 4px 36px; }
.card { min-width: 118px; border-radius: 8px; padding: 12px 16px; text-align: center;
        box-shadow: 0 1px 2px rgba(16,24,40,0.12); }
.card-count { display: block; font-size: 26px; font-weight: 700; }
.card-label { display: block; font-size: 12px; text-transform: uppercase;
              letter-spacing: 0.06em; color: #44506a; }
main { padding: 10px 36px 30px 36px; }
h2 { font-size: 17px; color: #1F3864; }
table { width: 100%; border-collapse: collapse; background: #ffffff; font-size: 12.5px; }
th { background: #1F3864; color: #ffffff; text-align: left; padding: 8px 10px;
     font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
td { border-bottom: 1px solid #e3e6ec; padding: 8px 10px; vertical-align: top; }
.sev-chip { padding: 2px 8px; border-radius: 4px; font-weight: 700; display: inline-block; }
td ul { margin: 0; padding-left: 16px; }
td ul li { margin: 2px 0; }
code { background: #eef1f6; padding: 1px 4px; border-radius: 3px; font-size: 12px; }
.methodology { background: #eef1f6; border-top: 3px solid #1F3864;
               padding: 20px 36px 30px 36px; font-size: 13px; color: #333f52; }
.methodology h2 { margin-top: 0; }
.methodology ul { padding-left: 20px; }
.methodology li { margin: 6px 0; }
"""

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>rdqe report - Responsible Data Quality Engine</title>
<style>{css}</style>
</head>
<body>
<header class="hero">
  <h1>Responsible Data Quality Engine - audit report</h1>
  <p>rdqe {version} &middot; generated {generated_at}</p>
  <p>{source_chips}</p>
  <p><span class="chip">Scan type: {scan_type}</span>
     <span class="chip">Cost rate: KES {rate:,.2f} / hour</span>
     <span class="chip">Local-only &middot; no telemetry</span></p>
</header>
<section class="cards">{cards}</section>
<main>
  <h2>Findings ({total}, sorted by severity)</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Rule</th><th>Resource</th><th>Detail</th>
          <th>Count</th><th>Evidence (masked)</th><th>Sample lines</th>
          <th>Legal references</th><th>Remediation</th><th>Effort &amp; cost</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</main>
<footer class="methodology">
  <h2>Method &amp; pledges</h2>
  <p>rdqe audits survey exports and form definitions with {rule_count} registered
  rules (R01-R14 for data, F01-F05 for forms plus R09). Each finding carries a
  severity, the Kenya Data Protection Act (2019) principle and GDPR article it
  implicates, a remediation note, a planning-level effort estimate in hours, and
  an estimated cost computed as effort hours &times; rate (currently KES
  {rate:,.2f} per hour). Estimates are planning inputs, not quotations, and the
  report is not legal advice.</p>
  <ul>
    <li><strong>Synthetic data only.</strong> rdqe ships and audits only obviously
    invented fixture data. No real survey, beneficiary, client or personal data
    belongs in this repository or its reports.</li>
    <li><strong>Local-only.</strong> The engine makes no network calls and collects
    no telemetry at runtime; reports are written to your local disk only.</li>
    <li><strong>Masked evidence.</strong> Personal data found in values is masked
    (for example 07******78) and sensitive free-text disclosures are reported as
    matched terms only, never as raw values.</li>
  </ul>
</footer>
</body>
</html>
"""


def to_html(findings: List[Finding], meta: Dict[str, Any], rate: float = DEFAULT_RATE) -> str:
    """Render the report as a self-contained HTML document."""
    ordered = _sorted(findings)
    summary = build_summary(findings, rate)

    cards = "".join(
        '<div class="card" style="background:{};">'
        '<span class="card-count">{}</span>'
        '<span class="card-label">{}</span></div>'.format(
            SEVERITY_COLORS[severity], summary[severity], _esc(severity)
        )
        for severity in SEVERITY_ORDER
    )

    sources = meta.get("sources")
    if isinstance(sources, list):
        source_chips = "".join(
            f'<span class="chip">Source: {_esc(src)}</span>' for src in sources
        )
    else:
        source_chips = f'<span class="chip">Source: {_esc(sources)}</span>' if sources else ""

    rows = []
    for finding in ordered:
        rule = RULES[finding.rule_id]
        evidence_items = "".join(f"<li>{_esc(item)}</li>" for item in finding.evidence)
        if not evidence_items:
            evidence_items = "<li>-</li>"
        sample = ", ".join(str(r) for r in finding.sample_rows) or "-"
        rows.append(
            "<tr>"
            '<td><span class="sev-chip" style="background:{bg};">{sev}</span></td>'
            "<td><strong>{rid}</strong><br>{title}</td>"
            "<td>{resource}</td>"
            "<td>{detail}</td>"
            "<td>{count}</td>"
            "<td><ul>{evidence}</ul></td>"
            "<td>{sample}</td>"
            "<td>Kenya DPA 2019: {dpa}<br>GDPR: {gdpr}</td>"
            "<td>{fix}</td>"
            "<td>{hours} h<br>KES {cost:,.2f}</td>"
            "</tr>".format(
                bg=SEVERITY_COLORS[finding.severity],
                sev=_esc(finding.severity),
                rid=_esc(finding.rule_id),
                title=_esc(rule.title),
                resource=_esc(finding.resource),
                detail=_esc(finding.detail),
                count=int(finding.count),
                evidence=evidence_items,
                sample=_esc(sample),
                dpa=_esc(rule.dpa_ref),
                gdpr=_esc(rule.gdpr_ref),
                fix=_esc(rule.remediation),
                hours=_esc(f"{finding.effort_hours:g}"),
                cost=finding.est_cost(rate),
            )
        )

    return _TEMPLATE.format(
        css=_CSS,
        version=_esc(__version__),
        generated_at=_esc(summary_meta_time(meta)),
        source_chips=source_chips,
        scan_type=_esc(meta.get("scan_type", "audit")),
        rate=rate,
        cards=cards,
        total=len(ordered),
        rows="".join(rows),
        rule_count=len(RULES),
    )


def summary_meta_time(meta: Dict[str, Any]) -> str:
    """Generated-at stamp: meta override when present, else now (UTC)."""
    override = meta.get("generated_at")
    if override:
        return str(override)
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
