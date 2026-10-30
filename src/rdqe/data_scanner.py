"""CSV data scanner: implements data rules R01-R14.

Reads ODK/KoboToolbox-style survey exports with csv.DictReader using
utf-8-sig encoding (tolerating a UTF-8 BOM and replacing undecodable bytes).

Findings are aggregated per rule and resource: one Finding carries a count,
up to three masked evidence strings and up to five sample line numbers.
Sample line numbers are 1-based and header-aware: data row i (0-based) is
file line i + 2, because line 1 is the header.

Scanned values are untrusted input: every value that reaches Finding
evidence is masked first, and sensitive free-text disclosures are reported
as matched terms only.
"""

from __future__ import annotations

import csv
import hashlib
import re
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import pii_patterns as pp
from .rules import Finding

DEFAULT_MAX_ROWS = 50000
_MAX_EVIDENCE = 3
_MAX_SAMPLE_ROWS = 5

_DATE_FORMATS = ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y")
_DATE_NAME_TOKENS = {"date", "time", "timestamp"}
_START_TOKENS = {"start", "begin"}
_END_TOKENS = {"end", "finish", "stop"}


def _blank(value: Optional[str]) -> bool:
    return value is None or str(value).strip() == ""


def _as_float(value: Optional[str]) -> Optional[float]:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _parse_one(text: str, fmt: str) -> Optional[date]:
    try:
        return datetime.strptime(text, fmt).date()
    except ValueError:
        return None


def _parse_date(value: Optional[str]) -> Optional[date]:
    text = str(value).strip()
    for fmt in _DATE_FORMATS:
        parsed = _parse_one(text, fmt)
        if parsed is not None:
            return parsed
    return None


def _has_token(name: str, wanted: set) -> bool:
    return any(token in wanted for token in pp.tokens(name))


def _is_date_column(name: str) -> bool:
    return _has_token(name, _DATE_NAME_TOKENS)


def _date_base(name: str) -> str:
    kept = [t for t in pp.tokens(name) if t not in _START_TOKENS | _END_TOKENS]
    return "_".join(kept)


class _Accumulator:
    """Merge per-row rule events into one Finding per (rule, resource)."""

    def __init__(self) -> None:
        self._events: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add(
        self,
        rule_id: str,
        resource: str,
        evidence: Optional[str] = None,
        row: Optional[int] = None,
    ) -> None:
        key = (rule_id, resource)
        event = self._events.get(key)
        if event is None:
            event = {"count": 0, "evidence": [], "sample_rows": []}
            self._events[key] = event
        event["count"] += 1
        if evidence and len(event["evidence"]) < _MAX_EVIDENCE:
            event["evidence"].append(evidence)
        if row is not None and len(event["sample_rows"]) < _MAX_SAMPLE_ROWS:
            event["sample_rows"].append(row)

    def findings(self) -> List[Finding]:
        results: List[Finding] = []
        for (rule_id, resource), event in sorted(self._events.items()):
            count = event["count"]
            results.append(
                Finding(
                    rule_id=rule_id,
                    resource=resource,
                    detail=f"{count} instance(s) detected.",
                    count=count,
                    evidence=event["evidence"],
                    sample_rows=event["sample_rows"],
                )
            )
        return results


def _check_duplicates(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
    primary_key: Optional[str],
) -> None:
    seen_full: Dict[str, int] = {}
    seen_pk: Dict[str, int] = {}
    for line, row in rows:
        raw = tuple(row.get(name) for name in fieldnames)
        digest = hashlib.sha256(repr(raw).encode("utf-8")).hexdigest()
        if digest in seen_full:
            acc.add(
                "R01",
                "full-row",
                evidence=f"line {line} is an exact copy of line {seen_full[digest]}",
                row=line,
            )
        else:
            seen_full[digest] = line
        if primary_key is None or primary_key not in row:
            continue
        pk_value = row.get(primary_key) or ""
        if _blank(pk_value):
            continue
        key = pk_value.strip().casefold()
        if key in seen_pk:
            masked = pp.mask_text(pk_value.strip(), primary_key)
            acc.add(
                "R01",
                primary_key,
                evidence=(
                    f"primary key '{masked}' repeats on lines "
                    f"{seen_pk[key]} and {line}"
                ),
                row=line,
            )
        else:
            seen_pk[key] = line


def _check_required(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
    required_fields: List[str],
) -> None:
    for column in required_fields:
        if column not in fieldnames:
            acc.add(
                "R02",
                column,
                evidence="required column is missing from the export header entirely",
            )
            continue
        for line, row in rows:
            if _blank(row.get(column)):
                acc.add(
                    "R02",
                    column,
                    evidence=f"required value absent at line {line}",
                    row=line,
                )


def _check_ranges(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
    ranges: Dict[str, Dict[str, Any]],
) -> None:
    for column, bounds in ranges.items():
        if column not in fieldnames:
            continue
        low = bounds.get("min")
        high = bounds.get("max")
        for line, row in rows:
            number = _as_float(row.get(column))
            if number is None:
                continue
            too_low = low is not None and number < float(low)
            too_high = high is not None and number > float(high)
            if too_low or too_high:
                masked = pp.mask_text(str(row.get(column)).strip(), column)
                acc.add(
                    "R03",
                    column,
                    evidence=(
                        f"line {line}: {column}={masked} outside the expected "
                        f"range [{low}, {high}]"
                    ),
                    row=line,
                )


def _check_dates(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
    today: date,
) -> None:
    for column in fieldnames:
        if not _is_date_column(column):
            continue
        for line, row in rows:
            parsed = _parse_date(row.get(column))
            if parsed is not None and parsed > today:
                acc.add(
                    "R04",
                    column,
                    evidence=(
                        f"line {line}: {column}={parsed.isoformat()} is dated in "
                        "the future"
                    ),
                    row=line,
                )
    start_columns = [c for c in fieldnames if _has_token(c, _START_TOKENS)]
    end_columns = [c for c in fieldnames if _has_token(c, _END_TOKENS)]
    for start_col in start_columns:
        base = _date_base(start_col)
        if not base:
            continue
        for end_col in end_columns:
            if _date_base(end_col) != base:
                continue
            pair = f"{start_col} / {end_col}"
            for line, row in rows:
                start_date = _parse_date(row.get(start_col))
                end_date = _parse_date(row.get(end_col))
                if start_date is not None and end_date is not None and end_date < start_date:
                    acc.add(
                        "R04",
                        pair,
                        evidence=(
                            f"line {line}: {end_col} ({end_date.isoformat()}) "
                            f"precedes {start_col} ({start_date.isoformat()})"
                        ),
                        row=line,
                    )


def _check_skip_rules(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
    skip_rules: List[Dict[str, Any]],
) -> None:
    for number, rule in enumerate(skip_rules, start=1):
        condition = rule.get("if") or {}
        condition_column = condition.get("column")
        condition_value = condition.get("equals")
        then_required = rule.get("then_required") or []
        if not condition_column or condition_column not in fieldnames:
            continue
        resource = f"skip rule {number} ({condition_column} == {condition_value})"
        for line, row in rows:
            observed = row.get(condition_column)
            if _blank(observed):
                continue
            if str(observed).strip().casefold() != str(condition_value).strip().casefold():
                continue
            for required in then_required:
                if required not in fieldnames:
                    acc.add(
                        "R05",
                        resource,
                        evidence=(
                            f"line {line}: required follow-up column '{required}' "
                            "is missing from the export"
                        ),
                        row=line,
                    )
                elif _blank(row.get(required)):
                    acc.add(
                        "R05",
                        resource,
                        evidence=(
                            f"line {line}: '{required}' must be filled when "
                            f"{condition_column} == {condition_value}"
                        ),
                        row=line,
                    )


def _check_disaggregation(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
    disagg: Dict[str, List[str]],
) -> None:
    for column, allowed in disagg.items():
        if column not in fieldnames:
            continue
        allowed_values = {str(a).strip() for a in allowed}
        line_by_value: Dict[str, int] = {}
        observed = set()
        for line, row in rows:
            value = row.get(column)
            if _blank(value):
                continue
            text = str(value).strip()
            observed.add(text)
            line_by_value.setdefault(text, line)
        unexpected = sorted(observed - allowed_values)
        if unexpected:
            preview = ", ".join(pp.mask_text(v, column) for v in unexpected[:3])
            first_line = line_by_value[unexpected[0]]
            acc.add(
                "R06",
                column,
                evidence=(
                    "value(s) outside the allowed disaggregation set: "
                    f"{preview} (allowed: {', '.join(sorted(allowed_values))})"
                ),
                row=first_line,
            )
        for expected in sorted(allowed_values - observed):
            acc.add(
                "R06",
                column,
                evidence=(
                    f"allowed value '{expected}' never appears in the data; "
                    "the disaggregation is incomplete"
                ),
            )


def _check_pii_in_values(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
) -> None:
    for column in fieldnames:
        for line, row in rows:
            value = row.get(column) or ""
            for kind, matched in pp.find_pii_matches(value, column):
                acc.add(
                    "R07",
                    column,
                    evidence=(
                        f"{kind} detected at line {line} and masked as "
                        f"'{pp.mask_value(matched)}' (raw value withheld)"
                    ),
                    row=line,
                )


def _check_sensitive_data(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
) -> None:
    for column in fieldnames:
        if pp.is_sensitive_column(column):
            matched_tokens = sorted(set(pp.tokens(column)) & pp.SENSITIVE_TOKENS)
            substring_hits = [
                marker for marker in pp.SENSITIVE_SUBSTRINGS if marker in column.lower()
            ]
            reasons = ", ".join(matched_tokens + substring_hits)
            acc.add(
                "R08",
                column,
                evidence=(
                    f"column name matches sensitive-data markers: {reasons}; "
                    "values are not quoted in this report"
                ),
            )
            continue
        for line, row in rows:
            value = row.get(column) or ""
            terms = pp.matched_sensitive_terms(value)
            if terms:
                unique_terms = ", ".join(dict.fromkeys(t.lower() for t in terms))
                acc.add(
                    "R08",
                    column,
                    evidence=(
                        f"sensitive term(s) matched in free text at line {line}: "
                        f"{unique_terms} (raw value withheld)"
                    ),
                    row=line,
                )


def _check_direct_identifiers(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
) -> None:
    for column in fieldnames:
        is_direct = (
            pp.is_name_column(column)
            or pp.is_phone_column(column)
            or pp.is_national_id_column(column)
        )
        if not is_direct:
            continue
        populated = sum(1 for _, row in rows if not _blank(row.get(column)))
        if populated:
            acc.add(
                "R09",
                column,
                evidence=(
                    f"direct-identifier column holds {populated} value(s); "
                    "contents are not quoted in this report"
                ),
            )


def _check_location_precision(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
) -> None:
    for column in fieldnames:
        if not pp.is_location_column(column):
            continue
        for line, row in rows:
            value = row.get(column)
            if _blank(value):
                continue
            for part in str(value).replace(",", " ").split():
                if _as_float(part) is None:
                    continue
                places = pp.decimal_places(part)
                if places > 3:
                    acc.add(
                        "R10",
                        column,
                        evidence=(
                            f"line {line}: coordinate with {places} decimal "
                            "places exceeds the 3-decimal precision limit "
                            "(value withheld)"
                        ),
                        row=line,
                    )
                    break


def _check_child_data(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
) -> None:
    for column in fieldnames:
        if not pp.is_age_column(column):
            continue
        for line, row in rows:
            number = _as_float(row.get(column))
            if number is None:
                continue
            if 0 <= number < 18:
                acc.add(
                    "R11",
                    column,
                    evidence=(
                        f"line {line}: {column}={int(number)} indicates a data "
                        "subject below 18; child safeguarding rules apply"
                    ),
                    row=line,
                )


def _check_consent(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
) -> None:
    consent_columns = [c for c in fieldnames if pp.is_consent_column(c)]
    if not consent_columns:
        return
    for column in consent_columns:
        for line, row in rows:
            value = row.get(column)
            if _blank(value):
                acc.add(
                    "R12",
                    column,
                    evidence=f"line {line}: consent value is absent",
                    row=line,
                )
                continue
            if str(value).strip().casefold() not in pp.AFFIRMATIVE_CONSENT:
                masked = pp.mask_text(str(value).strip(), column)
                acc.add(
                    "R12",
                    column,
                    evidence=(
                        f"line {line}: consent value is not affirmative "
                        f"(recorded as '{masked}')"
                    ),
                    row=line,
                )


def _check_identifier_formats(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
) -> None:
    for column in fieldnames:
        id_context = pp.has_identifier_context(column)
        phone_column = pp.is_phone_column(column)
        if not (id_context or phone_column):
            continue
        for line, row in rows:
            value = str(row.get(column) or "").strip()
            if not value or not re.fullmatch(r"\d+", value):
                continue
            length = len(value)
            if id_context and length not in (7, 8):
                acc.add(
                    "R13",
                    column,
                    evidence=(
                        f"line {line}: {length}-digit identifier does not match "
                        f"the expected 7-8 digit format (masked: "
                        f"'{pp.mask_value(value)}')"
                    ),
                    row=line,
                )
            elif phone_column and length != 10:
                acc.add(
                    "R13",
                    column,
                    evidence=(
                        f"line {line}: {length}-digit phone number does not match "
                        f"the expected 10-digit format (masked: "
                        f"'{pp.mask_value(value)}')"
                    ),
                    row=line,
                )


def _check_category_consistency(
    acc: _Accumulator,
    rows: List[Tuple[int, Dict[str, str]]],
    fieldnames: List[str],
) -> None:
    for column in fieldnames:
        lines_by_value: Dict[str, set] = {}
        for line, row in rows:
            value = row.get(column)
            if _blank(value):
                continue
            lines_by_value.setdefault(str(value).strip(), set()).add(line)
        if len(lines_by_value) < 2 or len(lines_by_value) > 12:
            continue
        groups: Dict[str, List[str]] = {}
        for raw in lines_by_value:
            normalised = " ".join(raw.split()).casefold()
            groups.setdefault(normalised, []).append(raw)
        for variants in groups.values():
            if len(variants) < 2:
                continue
            preview = ", ".join(repr(v) for v in sorted(variants)[:3])
            first_line = min(min(lines_by_value[v]) for v in variants)
            acc.add(
                "R14",
                column,
                evidence=(
                    "case/spacing variants of the same category: "
                    f"{preview}; standardise to one coded value"
                ),
                row=first_line,
            )


def scan_csv(path: Path, config: Optional[Dict[str, Any]] = None) -> List[Finding]:
    """Scan a CSV survey export and return aggregated findings."""
    config = dict(config or {})
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found: {path}")
    max_rows = int(config.get("max_rows", DEFAULT_MAX_ROWS))
    if max_rows <= 0:
        raise ValueError("max_rows must be a positive integer")

    fieldnames: List[str] = []
    rows: List[Tuple[int, Dict[str, str]]] = []
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        for index, row in enumerate(reader):
            if index >= max_rows:
                break
            rows.append((index + 2, row))

    acc = _Accumulator()
    _check_duplicates(acc, rows, fieldnames, config.get("primary_key"))
    _check_required(acc, rows, fieldnames, list(config.get("required_fields") or []))
    _check_ranges(acc, rows, fieldnames, dict(config.get("ranges") or {}))
    _check_dates(acc, rows, fieldnames, date.today())
    _check_skip_rules(acc, rows, fieldnames, list(config.get("skip_rules") or []))
    _check_disaggregation(acc, rows, fieldnames, dict(config.get("disagg") or {}))
    _check_pii_in_values(acc, rows, fieldnames)
    _check_sensitive_data(acc, rows, fieldnames)
    _check_direct_identifiers(acc, rows, fieldnames)
    _check_location_precision(acc, rows, fieldnames)
    _check_child_data(acc, rows, fieldnames)
    _check_consent(acc, rows, fieldnames)
    _check_identifier_formats(acc, rows, fieldnames)
    _check_category_consistency(acc, rows, fieldnames)

    findings = acc.findings()
    if not any(pp.is_consent_column(c) for c in fieldnames):
        findings.append(
            Finding(
                rule_id="R12",
                resource="(dataset)",
                detail=(
                    "No consent-like column was detected (expected a column named "
                    "consent, kubali or ridhaa)."
                ),
                count=1,
                evidence=[
                    "no consent-like column detected in the export header; "
                    "consent evidence cannot be verified"
                ],
            )
        )
    return findings
