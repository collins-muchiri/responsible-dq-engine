"""XLSForm scanner: implements form rules F01-F05 plus R09.

Reads the survey sheet of an XLSForm workbook with openpyxl in read-only
mode. Headers are matched case-insensitively and lowercased; group and
repeat begin/end rows are skipped as structural markers, not fields.

Scanned form content is untrusted input; findings carry field names and
descriptions only, never cell values beyond what the rules themselves
quote (field names and types).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

from openpyxl import load_workbook

from . import pii_patterns as pp
from .rules import Finding

_CONSENT_KEYWORDS = (
    "consent",
    "kubali",
    "ridhaa",
    "privacy notice",
    "informed consent",
    "informed_consent",
    "agree to participate",
    "agree_to_participate",
)

# XLSForm function names that can legitimately appear inside ${...} in some
# authoring tools; they are not field references and must not raise F05.
_FUNCTION_NAMES = {
    "today",
    "now",
    "position",
    "random",
    "uuid",
    "roster",
    "true",
    "false",
}

_LOCATION_TYPES = {"geopoint", "geotrace", "geoshape"}
_SKIP_TYPE_PREFIXES = (
    "begin group",
    "begin_group",
    "begin repeat",
    "begin_repeat",
    "end group",
    "end_group",
    "end repeat",
    "end_repeat",
)


def _cell(row: tuple, index: Optional[int]) -> str:
    if index is None or index >= len(row):
        return ""
    return str(row[index] or "").strip()


def _parse_survey_rows(path: Path) -> List[Dict[str, str]]:
    workbook = load_workbook(str(path), read_only=True, data_only=True)
    try:
        sheet = next(
            (ws for ws in workbook.worksheets if ws.title.strip().lower() == "survey"),
            None,
        )
        if sheet is None:
            raise ValueError(
                "no 'survey' sheet found; the file is not a valid XLSForm"
            )
        raw_rows = [tuple(row) for row in sheet.iter_rows(values_only=True)]
    finally:
        workbook.close()

    if not raw_rows:
        raise ValueError("the survey sheet is empty")
    header = [str(cell or "").strip().lower() for cell in raw_rows[0]]

    def column(*names: str) -> Optional[int]:
        for name in names:
            if name in header:
                return header.index(name)
        return None

    idx_type = column("type")
    idx_name = column("name")
    idx_label = column("label")
    idx_relevant = column("relevant")
    idx_constraint = column("constraint")
    if idx_type is None or idx_name is None:
        raise ValueError("the survey sheet must have 'type' and 'name' columns")

    fields: List[Dict[str, str]] = []
    for row in raw_rows[1:]:
        type_value = _cell(row, idx_type)
        if not type_value:
            continue
        if type_value.lower().startswith(_SKIP_TYPE_PREFIXES):
            continue
        fields.append(
            {
                "type": type_value,
                "base_type": type_value.split()[0].lower(),
                "name": _cell(row, idx_name),
                "label": _cell(row, idx_label),
                "relevant": _cell(row, idx_relevant),
                "constraint": _cell(row, idx_constraint),
            }
        )
    return fields


def scan_xlsform(path: Path) -> List[Finding]:
    """Scan an XLSForm workbook and return aggregated findings."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"XLSForm not found: {path}")

    fields = _parse_survey_rows(path)
    findings: List[Finding] = []
    known_names = {f["name"] for f in fields if f["name"]}

    consent_found = False
    for field in fields:
        haystack = f"{field['name']} {field['label']}".lower()
        if any(keyword in haystack for keyword in _CONSENT_KEYWORDS):
            consent_found = True
            break
    if not consent_found:
        findings.append(
            Finding(
                rule_id="F01",
                resource="survey",
                detail="No consent or privacy-notice field was found in the form.",
                count=1,
                evidence=[
                    "no field name or label matched consent keywords (consent, "
                    "kubali, ridhaa, privacy notice, informed consent, agree to "
                    "participate)"
                ],
            )
        )

    for field in fields:
        name = field["name"]
        if not name:
            continue

        if (
            pp.is_sensitive_column(name)
            or pp.matched_sensitive_terms(field["label"])
        ) and "encrypt" not in field["type"].lower():
            findings.append(
                Finding(
                    rule_id="F02",
                    resource=name,
                    detail=(
                        f"Field '{name}' holds sensitive data but its type "
                        f"('{field['type']}') is not encrypted."
                    ),
                    count=1,
                    evidence=[
                        "sensitive field type without encryption; raw "
                        "submissions would be stored in plaintext"
                    ],
                )
            )

        if pp.is_name_column(name) or pp.is_national_id_column(name):
            findings.append(
                Finding(
                    rule_id="R09",
                    resource=name,
                    detail=(
                        f"Form collects a direct-identifier field '{name}'."
                    ),
                    count=1,
                    evidence=[
                        "direct identifiers should be avoided or replaced with "
                        "pseudonymous study keys"
                    ],
                )
            )

        if field["base_type"] in _LOCATION_TYPES:
            findings.append(
                Finding(
                    rule_id="F04",
                    resource=name,
                    detail=(
                        f"Location field '{name}' has no built-in precision limit."
                    ),
                    count=1,
                    evidence=[
                        "raw geopoint/geotrace/geoshape capture can identify a "
                        "household; consider coarse capture or trimmed precision"
                    ],
                )
            )

        if field["base_type"] == "text" and not field["constraint"]:
            findings.append(
                Finding(
                    rule_id="F03",
                    resource=name,
                    detail=(
                        f"Free-text field '{name}' has no constraint on length "
                        "or format."
                    ),
                    count=1,
                    evidence=[
                        "unconstrained free text invites PII disclosure and "
                        "unanalysable answers; add a length or regex constraint"
                    ],
                )
            )

        if field["relevant"]:
            for reference in re.findall(r"\$\{([^}]+)\}", field["relevant"]):
                reference = reference.strip()
                if reference in _FUNCTION_NAMES:
                    continue
                if reference not in known_names:
                    findings.append(
                        Finding(
                            rule_id="F05",
                            resource=name,
                            detail=(
                                f"Relevant expression on '{name}' references "
                                f"unknown field '${reference}'."
                            ),
                            count=1,
                            evidence=[
                                f"relevant expression references '${reference}', "
                                "which is not a field in this form"
                            ],
                        )
                    )

    return findings
