"""Command-line interface for rdqe.

Subcommands:
  scan-data CSV [--config JSON]   audit a survey export (rules R01-R14)
  scan-form XLSX                  audit an XLSForm definition (F01-F05, R09)
  demo                            write synthetic artefacts and audit them

Common flags: --out DIR (default: reports), --format {html,json} (repeatable,
default: both), --fail-on {none,low,medium,high,critical} (default: high),
--rate FLOAT (default: 2500.0 KES/hour).

Exit codes: 0 clean or below threshold, 1 gate tripped, 2 usage error
(missing file, unreadable config, unknown arguments).
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from openpyxl import Workbook

from . import __version__
from .data_scanner import scan_csv
from .report import to_html, to_json
from .rules import SEVERITY_ORDER, Finding, meets_threshold
from .xlsform_scanner import scan_xlsform

DEFAULT_OUT = "reports"
DEFAULT_RATE = 2500.0
FAILURE_LEVELS = ["none"] + SEVERITY_ORDER

DEMO_CONFIG: Dict[str, object] = {
    "primary_key": "record_id",
    "required_fields": ["record_id", "visit_start_date", "consent", "sex", "age"],
    "ranges": {"age": {"min": 0, "max": 120}},
    "skip_rules": [
        {
            "if": {"column": "currently_pregnant", "equals": "Yes"},
            "then_required": ["anc_facility"],
        }
    ],
    "disagg": {"sex": ["Male", "Female"]},
}

_DEMO_HEADERS = [
    "record_id",
    "beneficiary_name",
    "sex",
    "age",
    "currently_pregnant",
    "anc_facility",
    "visit_start_date",
    "visit_end_date",
    "interview_start",
    "interview_end",
    "national_id",
    "phone_number",
    "gps_location",
    "consent",
    "education_level",
    "hiv_art",
    "general_notes",
]

# Synthetic demo rows, seeded to trigger every data rule. Every value is
# obviously invented: names are "Test Person NN", contact details and IDs are
# impossible placeholder numbers, and no real person is represented.
_DEMO_ROWS = [
    ["REC-0001", "Test Person 01", "Female", "34", "No", "", "2024-02-10", "2024-02-10",
     "2024-02-01", "2024-02-05", "34567891", "", "", "Yes", "Primary", "",
     "Routine follow-up visit completed as scheduled."],
    ["REC-0002", "Test Person 02", "Male", "41", "No", "", "2024-02-11", "2024-02-11",
     "2024-02-02", "2024-02-06", "", "", "", "Yes", "Secondary", "",
     "Household verified during the visit."],
    ["REC-0002", "Test Person 03", "Female", "145", "Yes", "", "2024-02-12", "2024-02-12",
     "2024-02-03", "2024-02-04", "", "", "", "No", "primary", "",
     "Client mentioned ART adherence support."],
    ["REC-0004", "Test Person 04", "F", "29", "No", "", "2030-01-15", "2030-01-16",
     "2024-02-05", "2024-02-06", "", "", "", "Yes", "Secondary", "",
     "Visit scheduled from the referral list."],
    ["REC-0005", "Test Person 05", "Female", "36", "No", "", "2024-02-14", "2024-02-14",
     "2024-05-10", "2024-05-01", "", "", "", "Yes", "Tertiary", "",
     "Contact community health volunteer at 0712345678 or jane@example.com before "
     "the next visit."],
    ["REC-0006", "Test Person 06", "female", "17", "No", "", "2024-02-15", "2024-02-15",
     "2024-02-06", "2024-02-07", "", "", "", "Yes", "Secondary", "",
     "Guardian present during the interview."],
    ["REC-0007", "Test Person 07", "Male", "26", "No", "", "2024-02-16", "2024-02-16",
     "2024-02-07", "2024-02-08", "123456", "", "-1.292066 36.821234", "Yes", "Primary", "",
     "ID 1234567 shared during registration for verification."],
    ["REC-0008", "Test Person 08", "Male", "33", "No", "", "", "2024-02-17",
     "2024-02-08", "2024-02-09", "", "071234567", "", "", "Secondary", "",
     "Household visit pending."],
    ["REC-0009", "Test Person 09", "Male", "52", "No", "", "2024-03-01", "2024-03-01",
     "2024-03-01", "2024-03-02", "", "", "", "Yes", "PRIMARY ", "",
     "Client is a survivor of gbv and was referred for counselling."],
    ["REC-0009", "Test Person 09", "Male", "52", "No", "", "2024-03-01", "2024-03-01",
     "2024-03-01", "2024-03-02", "", "", "", "Yes", "PRIMARY ", "",
     "Client is a survivor of gbv and was referred for counselling."],
    ["REC-0011", "Test Person 11", "Male", "38", "No", "", "2024-03-02", "2024-03-02",
     "2024-03-02", "2024-03-03", "", "", "", "Yes", "Secondary", "Active",
     "Referred to the wellness clinic for review."],
    ["REC-0012", "Test Person 12", "Female", "27", "No", "", "2024-03-03", "2024-03-03",
     "2024-03-03", "2024-03-04", "", "", "", "Yes", "Primary", "",
     "Antenatal services discussed at the facility."],
]

_FORM_HEADERS = ["type", "name", "label", "relevant", "constraint", "required"]

_FORM_ROWS = [
    ["begin group", "respondent_group", "Respondent details", "", "", ""],
    ["text", "beneficiary_name", "Beneficiary full name", "", "", ""],
    ["integer", "national_id", "National ID number", "", "", ""],
    ["text", "hiv_status", "Ever tested for HIV? Latest result", "", "", ""],
    ["end group", "respondent_group", "", "", "", ""],
    ["geopoint", "home_location", "Home location", "", "", ""],
    ["text", "general_comments", "General comments", "", "", ""],
    ["text", "follow_up_notes", "Follow-up notes", "${referral_facility} != ''", "", ""],
    ["select_one yes_no", "household_visited", "Was the household visited?", "", "", ""],
]

_CHOICES_HEADERS = ["list_name", "name", "label"]
_CHOICES_ROWS = [
    ["yes_no", "yes", "Yes"],
    ["yes_no", "no", "No"],
]


def write_demo_csv(path: Path) -> Path:
    """Write the synthetic demo survey export."""
    path = Path(path)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(_DEMO_HEADERS)
        writer.writerows(_DEMO_ROWS)
    return path


def write_demo_xlsx(path: Path) -> Path:
    """Write the synthetic demo XLSForm definition."""
    path = Path(path)
    workbook = Workbook()
    survey = workbook.active
    survey.title = "survey"
    survey.append(_FORM_HEADERS)
    for row in _FORM_ROWS:
        survey.append(row)
    choices = workbook.create_sheet("choices")
    choices.append(_CHOICES_HEADERS)
    for row in _CHOICES_ROWS:
        choices.append(row)
    workbook.save(str(path))
    return path


def _write_reports(
    findings: List[Finding],
    meta: Dict[str, object],
    out_dir: Path,
    stem: str,
    formats: Sequence[str],
    rate: float,
) -> List[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[str] = []
    if "json" in formats:
        json_path = out_dir / f"{stem}_report.json"
        json_path.write_text(to_json(findings, meta, rate), encoding="utf-8")
        written.append(str(json_path))
    if "html" in formats:
        html_path = out_dir / f"{stem}_report.html"
        html_path.write_text(to_html(findings, meta, rate), encoding="utf-8")
        written.append(str(html_path))
    return written


def _finish(
    findings: List[Finding],
    sources: List[str],
    scan_type: str,
    stem: str,
    formats: Sequence[str],
    args: argparse.Namespace,
) -> int:
    meta = {
        "sources": sources,
        "scan_type": scan_type,
        "tool_version": __version__,
    }
    out_dir = Path(args.out)
    written = _write_reports(findings, meta, out_dir, stem, formats, args.rate)

    counts: Dict[str, int] = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    breakdown = ", ".join(f"{sev}={n}" for sev, n in counts.items() if n) or "none"
    total_cost = sum(f.est_cost(args.rate) for f in findings)
    print(f"rdqe {__version__}: {len(findings)} finding(s) [{breakdown}]")
    print(
        f"Estimated remediation: "
        f"{sum(f.effort_hours for f in findings):.2f} h, "
        f"KES {total_cost:,.2f} at rate {args.rate:,.2f} KES/h"
    )
    for path in written:
        print(f"Report written: {path}")
    gate = "disabled (--fail-on none)" if args.fail_on == "none" else f"threshold '{args.fail_on}'"
    passed = meets_threshold(findings, args.fail_on)
    print(f"CI gate {'passed' if passed else 'FAILED'} ({gate})")
    return 0 if passed else 1


def _read_json_config(config_path: Path) -> Optional[Dict[str, object]]:
    """Return the parsed JSON config, or None after printing a usage error."""
    if not config_path.is_file():
        print(f"rdqe: error: config file not found: {config_path}", file=sys.stderr)
        return None
    try:
        parsed = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"rdqe: error: invalid JSON in {config_path}: {exc}", file=sys.stderr)
        return None
    if not isinstance(parsed, dict):
        print(f"rdqe: error: config must be a JSON object: {config_path}", file=sys.stderr)
        return None
    return parsed


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    formats = args.formats or ["html", "json"]

    if args.command == "scan-data":
        csv_path = Path(args.csv)
        if not csv_path.is_file():
            print(f"rdqe: error: CSV file not found: {csv_path}", file=sys.stderr)
            return 2
        config: Dict[str, object] = {}
        if args.config:
            loaded = _read_json_config(Path(args.config))
            if loaded is None:
                return 2
            config = loaded
        findings = scan_csv(csv_path, config)
        return _finish(findings, [str(csv_path)], "data", csv_path.stem, formats, args)

    if args.command == "scan-form":
        xlsx_path = Path(args.xlsx)
        if not xlsx_path.is_file():
            print(f"rdqe: error: XLSForm file not found: {xlsx_path}", file=sys.stderr)
            return 2
        findings = scan_xlsform(xlsx_path)
        return _finish(findings, [str(xlsx_path)], "form", xlsx_path.stem, formats, args)

    if args.command == "demo":
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        csv_path = write_demo_csv(out_dir / "synthetic_survey_data.csv")
        xlsx_path = write_demo_xlsx(out_dir / "synthetic_form.xlsx")
        config_path = out_dir / "demo_config.json"
        config_path.write_text(json.dumps(DEMO_CONFIG, indent=2) + "\n", encoding="utf-8")
        print(
            "Demo artefacts written to "
            f"{out_dir}: synthetic_survey_data.csv, synthetic_form.xlsx, demo_config.json"
        )
        findings = scan_csv(csv_path, DEMO_CONFIG) + scan_xlsform(xlsx_path)
        return _finish(findings, [str(csv_path), str(xlsx_path)], "demo", "rdqe", formats, args)

    return 2


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help="directory for generated reports (default: reports)",
    )
    common.add_argument(
        "--format",
        dest="formats",
        action="append",
        choices=["html", "json"],
        default=None,
        help="report format; repeatable (default: both html and json)",
    )
    common.add_argument(
        "--fail-on",
        choices=FAILURE_LEVELS,
        default="high",
        help="severity threshold for the exit-code gate (default: high; 'none' disables)",
    )
    common.add_argument(
        "--rate",
        type=float,
        default=DEFAULT_RATE,
        help="remediation cost rate in KES per hour (default: 2500.0)",
    )

    parser = argparse.ArgumentParser(
        prog="rdqe",
        description=(
            "Responsible Data Quality Engine: audit survey exports and form "
            "definitions for data quality and privacy risks, with costed remediation."
        ),
    )
    parser.add_argument("--version", action="version", version=f"rdqe {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_data = subparsers.add_parser(
        "scan-data", parents=[common], help="audit a CSV survey export (rules R01-R14)"
    )
    p_data.add_argument("csv", help="path to the CSV export")
    p_data.add_argument(
        "--config", default=None, help="path to a JSON configuration file"
    )

    p_form = subparsers.add_parser(
        "scan-form", parents=[common], help="audit an XLSForm definition (F01-F05, R09)"
    )
    p_form.add_argument("xlsx", help="path to the XLSForm workbook")

    subparsers.add_parser(
        "demo", parents=[common],
        help="write synthetic demo artefacts and audit them",
    )
    return parser


def entry(argv: Optional[Sequence[str]] = None) -> None:
    """Console-script entry point."""
    sys.exit(main(argv))


if __name__ == "__main__":
    entry()
