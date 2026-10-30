"""Rule registry for the Responsible Data Quality Engine.

Every audit check in rdqe is registered here with a stable identifier, a
severity, a category, a reference to the Kenya Data Protection Act (2019)
and the GDPR article it mirrors, a remediation note, and a planning-level
remediation effort in hours.

Kenya DPA 2019 references use principle names (for example "accuracy
principle", "data minimisation", "sensitive personal data (health)",
"consent and transparency", "security of processing") rather than section
numbers. GDPR references use article numbers only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Rule:
    """A single auditable data quality or privacy rule."""

    rule_id: str
    title: str
    severity: str
    category: str
    dpa_ref: str
    gdpr_ref: str
    remediation: str
    effort_hours: float

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {self.severity!r}")


RULES: Dict[str, Rule] = {
    "R01": Rule(
        rule_id="R01",
        title="Duplicate records",
        severity="medium",
        category="duplication",
        dpa_ref="accuracy principle",
        gdpr_ref="Art. 5(1)(d)",
        remediation=(
            "Merge duplicates on a verified unique key before import, keep one "
            "canonical record per beneficiary visit, and document the merge rule "
            "in the data-management plan."
        ),
        effort_hours=3.0,
    ),
    "R02": Rule(
        rule_id="R02",
        title="Missing required values",
        severity="medium",
        category="completeness",
        dpa_ref="accuracy principle",
        gdpr_ref="Art. 5(1)(d)",
        remediation=(
            "Enforce required fields at collection time, re-contact respondents "
            "where appropriate and safe, and reconcile remaining gaps before "
            "analysis."
        ),
        effort_hours=4.0,
    ),
    "R03": Rule(
        rule_id="R03",
        title="Out-of-range values",
        severity="medium",
        category="validity",
        dpa_ref="accuracy principle",
        gdpr_ref="Art. 5(1)(d)",
        remediation=(
            "Add range constraints to numeric fields in the form, correct or "
            "quarantine out-of-range values, and retrain enumerators on the "
            "expected ranges."
        ),
        effort_hours=3.0,
    ),
    "R04": Rule(
        rule_id="R04",
        title="Date logic violations",
        severity="medium",
        category="temporal validity",
        dpa_ref="accuracy principle",
        gdpr_ref="Art. 5(1)(d)",
        remediation=(
            "Add date constraints to the form, correct inverted start/end pairs, "
            "and investigate future-dated entries for data-entry errors before "
            "they reach reporting."
        ),
        effort_hours=2.0,
    ),
    "R05": Rule(
        rule_id="R05",
        title="Skip pattern violations",
        severity="high",
        category="form logic",
        dpa_ref="data minimisation",
        gdpr_ref="Art. 5(1)(c)",
        remediation=(
            "Repair the relevant/skip logic in the form, retrain enumerators, and "
            "treat answers to non-applicable questions as missing during analysis."
        ),
        effort_hours=4.0,
    ),
    "R06": Rule(
        rule_id="R06",
        title="Disaggregation gaps",
        severity="medium",
        category="disaggregation",
        dpa_ref="accuracy principle",
        gdpr_ref="Art. 5(1)(d)",
        remediation=(
            "Constrain disaggregation fields to coded choice lists and review "
            "reporting outputs so every required category is captured and no "
            "uncoded values slip in."
        ),
        effort_hours=3.0,
    ),
    "R07": Rule(
        rule_id="R07",
        title="PII in values",
        severity="high",
        category="pii exposure",
        dpa_ref="data minimisation",
        gdpr_ref="Art. 5(1)(c)",
        remediation=(
            "Strip or mask identifiers from free text, move contact details to "
            "controlled-access columns, and restrict export permissions to staff "
            "who genuinely need them."
        ),
        effort_hours=6.0,
    ),
    "R08": Rule(
        rule_id="R08",
        title="Sensitive category data",
        severity="critical",
        category="sensitive data",
        dpa_ref="sensitive personal data (health)",
        gdpr_ref="Art. 9",
        remediation=(
            "Restrict access to sensitive columns, store them encrypted, "
            "aggregate or apply small-cell suppression before sharing, and "
            "reconfirm the lawful basis for collecting them."
        ),
        effort_hours=8.0,
    ),
    "R09": Rule(
        rule_id="R09",
        title="Direct identifiers collected",
        severity="medium",
        category="data minimisation",
        dpa_ref="data minimisation",
        gdpr_ref="Art. 5(1)(c)",
        remediation=(
            "Replace direct identifiers with pseudonymous study keys at the point "
            "of collection where possible; where names, phone numbers or national "
            "IDs are essential, limit retention and access."
        ),
        effort_hours=5.0,
    ),
    "R10": Rule(
        rule_id="R10",
        title="Location precision risk",
        severity="high",
        category="location privacy",
        dpa_ref="data minimisation",
        gdpr_ref="Art. 5(1)(c)",
        remediation=(
            "Round coordinates to at most 3 decimal places (about 110 m at the "
            "equator) or capture location at administrative-area level unless "
            "finer precision is essential to the programme."
        ),
        effort_hours=3.0,
    ),
    "R11": Rule(
        rule_id="R11",
        title="Child data present",
        severity="high",
        category="child safeguarding",
        dpa_ref="consent and transparency",
        gdpr_ref="Art. 8",
        remediation=(
            "Verify child safeguarding procedures, confirm guardian consent and "
            "child assent workflows, and restrict access to records about minors."
        ),
        effort_hours=4.0,
    ),
    "R12": Rule(
        rule_id="R12",
        title="Consent evidence missing",
        severity="critical",
        category="consent",
        dpa_ref="consent and transparency",
        gdpr_ref="Art. 7",
        remediation=(
            "Capture an explicit consent record per respondent, retain the signed "
            "or verbal-consent evidence, and exclude non-consenting records from "
            "analysis and sharing."
        ),
        effort_hours=6.0,
    ),
    "R13": Rule(
        rule_id="R13",
        title="Identifier format anomalies",
        severity="low",
        category="validity",
        dpa_ref="accuracy principle",
        gdpr_ref="Art. 5(1)(d)",
        remediation=(
            "Validate identifier and phone number formats at entry with regex "
            "constraints, then confirm and correct anomalous values at source."
        ),
        effort_hours=2.0,
    ),
    "R14": Rule(
        rule_id="R14",
        title="Category inconsistency",
        severity="low",
        category="consistency",
        dpa_ref="accuracy principle",
        gdpr_ref="Art. 5(1)(d)",
        remediation=(
            "Standardise choice lists to a single coded vocabulary, apply the same "
            "casing and spelling across exports, and map legacy variants on import."
        ),
        effort_hours=2.0,
    ),
    "F01": Rule(
        rule_id="F01",
        title="Form lacks consent or privacy notice",
        severity="critical",
        category="consent",
        dpa_ref="consent and transparency",
        gdpr_ref="Art. 7 and Art. 12-14",
        remediation=(
            "Add a consent and privacy-notice field group at the start of the form "
            "covering purpose, voluntary participation and data-use statements."
        ),
        effort_hours=4.0,
    ),
    "F02": Rule(
        rule_id="F02",
        title="Sensitive fields not encrypted",
        severity="high",
        category="encryption",
        dpa_ref="security of processing",
        gdpr_ref="Art. 32",
        remediation=(
            "Move sensitive questions behind encrypted field types (or "
            "server-side encryption) and limit who can export raw submissions."
        ),
        effort_hours=5.0,
    ),
    "F03": Rule(
        rule_id="F03",
        title="Unconstrained free text",
        severity="low",
        category="data minimisation",
        dpa_ref="data minimisation",
        gdpr_ref="Art. 5(1)(c) and Art. 25",
        remediation=(
            "Constrain free-text fields with length or regex constraints, and "
            "prefer coded choices for anything that needs to be analysed."
        ),
        effort_hours=2.0,
    ),
    "F04": Rule(
        rule_id="F04",
        title="GPS field precision",
        severity="medium",
        category="location privacy",
        dpa_ref="data minimisation",
        gdpr_ref="Art. 5(1)(c)",
        remediation=(
            "Capture locations at the coarsest useful precision: trim decimal "
            "places on geopoint fields or use administrative-area choice lists "
            "instead of raw coordinates."
        ),
        effort_hours=1.5,
    ),
    "F05": Rule(
        rule_id="F05",
        title="Broken relevant expression",
        severity="medium",
        category="form logic",
        dpa_ref="accuracy principle",
        gdpr_ref="Art. 25",
        remediation=(
            "Fix the relevant expression so every ${field} reference points to an "
            "existing field, and test the form in a web client before deployment."
        ),
        effort_hours=2.0,
    ),
}


@dataclass
class Finding:
    """One aggregated audit result for a rule applied to a resource."""

    rule_id: str
    resource: str
    detail: str
    count: int = 0
    evidence: List[str] = field(default_factory=list)
    sample_rows: List[int] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return RULES[self.rule_id].severity

    @property
    def effort_hours(self) -> float:
        return RULES[self.rule_id].effort_hours

    def est_cost(self, rate: float = 2500.0) -> float:
        """Estimated remediation cost in KES at *rate* KES per hour."""
        return round(self.effort_hours * rate, 2)

    def to_dict(self, rate: float = 2500.0) -> Dict[str, object]:
        rule = RULES[self.rule_id]
        return {
            "rule_id": self.rule_id,
            "title": rule.title,
            "severity": self.severity,
            "category": rule.category,
            "dpa_ref": rule.dpa_ref,
            "gdpr_ref": rule.gdpr_ref,
            "remediation": rule.remediation,
            "resource": self.resource,
            "detail": self.detail,
            "count": self.count,
            "evidence": list(self.evidence),
            "sample_rows": list(self.sample_rows),
            "effort_hours": self.effort_hours,
            "est_cost_kes": self.est_cost(rate),
        }


def meets_threshold(findings: List[Finding], fail_on: str = "high") -> bool:
    """Return True when *findings* pass the CI gate.

    The gate trips when at least one finding is at or above the configured
    severity on the SEVERITY_ORDER scale. ``fail_on="none"`` disables the
    gate entirely and always passes.
    """
    if fail_on == "none":
        return True
    if fail_on not in SEVERITY_ORDER:
        raise ValueError(f"unknown fail_on level: {fail_on!r}")
    threshold = SEVERITY_ORDER.index(fail_on)
    return all(SEVERITY_ORDER.index(f.severity) < threshold for f in findings)
