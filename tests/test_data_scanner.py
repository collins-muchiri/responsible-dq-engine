"""Tests for the CSV data scanner (rules R01-R14) and registry semantics."""

import json

import pytest

from conftest import write_rows
from rdqe.cli import DEMO_CONFIG
from rdqe.data_scanner import scan_csv
from rdqe.rules import Finding, RULES, meets_threshold

ALL_DATA_RULES = {f"R{n:02d}" for n in range(1, 15)}


def test_demo_csv_triggers_all_fourteen_data_rules(demo_csv):
    findings = scan_csv(demo_csv, DEMO_CONFIG)
    rules = {f.rule_id for f in findings}
    assert ALL_DATA_RULES <= rules


def test_clean_csv_yields_zero_findings(clean_csv):
    assert scan_csv(clean_csv, DEMO_CONFIG) == []


def test_duplicate_fullrow_and_primary_key(demo_csv):
    findings = [f for f in scan_csv(demo_csv, DEMO_CONFIG) if f.rule_id == "R01"]
    resources = {f.resource for f in findings}
    assert "full-row" in resources
    assert "record_id" in resources
    for finding in findings:
        assert finding.severity == "medium"
        # Header-aware 1-based line numbers (header is line 1, data starts at 2).
        assert all(isinstance(r, int) and r >= 2 for r in finding.sample_rows)


def test_missing_required_values_and_ranges(demo_csv):
    findings = scan_csv(demo_csv, DEMO_CONFIG)
    r02 = [f for f in findings if f.rule_id == "R02"]
    assert {"consent", "visit_start_date"} <= {f.resource for f in r02}
    r03 = next(f for f in findings if f.rule_id == "R03")
    assert r03.resource == "age"
    assert r03.count == 1
    assert "145" in " ".join(r03.evidence)


def test_future_dates_and_start_end_inversions(demo_csv):
    findings = scan_csv(demo_csv, DEMO_CONFIG)
    r04 = [f for f in findings if f.rule_id == "R04"]
    assert any(f.resource == "visit_start_date" for f in r04), "future date not caught"
    assert any(f.resource == "visit_end_date" for f in r04), "future date not caught"
    assert any(
        f.resource == "interview_start / interview_end" for f in r04
    ), "inverted start/end not caught"


def test_skip_rule_violation(demo_csv):
    findings = scan_csv(demo_csv, DEMO_CONFIG)
    r05 = next(f for f in findings if f.rule_id == "R05")
    assert r05.count >= 1
    assert "anc_facility" in " ".join(r05.evidence)
    assert r05.severity == "high"


def test_disaggregation_unexpected_and_gap(tmp_path):
    path = write_rows(
        tmp_path / "sex.csv",
        ["record_id", "sex", "consent"],
        [["REC-0001", "Male", "Yes"], ["REC-0002", "M", "Yes"]],
    )
    findings = scan_csv(
        path, {"disagg": {"sex": ["Male", "Female"]}, "primary_key": "record_id"}
    )
    r06 = next(f for f in findings if f.rule_id == "R06")
    assert "M" in " ".join(r06.evidence)
    assert any("never appears" in e for e in r06.evidence)


def test_pii_evidence_is_masked(demo_csv):
    findings = scan_csv(demo_csv, DEMO_CONFIG)
    blob = json.dumps([f.to_dict() for f in findings])
    assert "0712345678" not in blob
    assert "jane@example.com" not in blob
    assert "*" in blob
    r07 = [f for f in findings if f.rule_id == "R07"]
    assert r07, "expected at least one R07 finding"
    assert any("07******78" in e for f in r07 for e in f.evidence)
    assert any("ja************om" in e for f in r07 for e in f.evidence)


def test_contextual_id_disclosure_is_masked(demo_csv):
    findings = scan_csv(demo_csv, DEMO_CONFIG)
    blob = json.dumps([f.to_dict() for f in findings])
    assert "1234567" not in blob
    r07 = [f for f in findings if f.rule_id == "R07"]
    assert any("12***67" in e for f in r07 for e in f.evidence)


def test_sensitive_findings_report_terms_only(demo_csv):
    r08 = [f for f in scan_csv(demo_csv, DEMO_CONFIG) if f.rule_id == "R08"]
    blob = json.dumps([f.to_dict() for f in r08])
    assert "hiv_art" in blob
    assert any("survivor" in e for f in r08 for e in f.evidence)
    assert any("art" in e for f in r08 for e in f.evidence)
    # Raw sentences must never be quoted.
    assert "Client is a survivor" not in blob
    assert "Client mentioned ART adherence" not in blob
    assert all(f.severity == "critical" for f in r08)


def test_location_precision_flagged(demo_csv):
    findings = scan_csv(demo_csv, DEMO_CONFIG)
    r10 = next(f for f in findings if f.rule_id == "R10")
    assert r10.resource == "gps_location"
    assert r10.count >= 1
    assert any("6 decimal places" in e for e in r10.evidence)
    assert r10.severity == "high"


def test_identifier_format_anomalies(demo_csv):
    findings = scan_csv(demo_csv, DEMO_CONFIG)
    r13 = [f for f in findings if f.rule_id == "R13"]
    assert {f.resource for f in r13} == {"national_id", "phone_number"}
    assert any("6-digit" in e for f in r13 for e in f.evidence)
    assert any("9-digit" in e for f in r13 for e in f.evidence)


def test_child_data_and_consent_findings(demo_csv):
    findings = scan_csv(demo_csv, DEMO_CONFIG)
    r11 = next(f for f in findings if f.rule_id == "R11")
    assert r11.count == 1
    assert r11.severity == "high"
    r12 = next(f for f in findings if f.rule_id == "R12")
    assert r12.count == 2
    assert r12.severity == "critical"


def test_category_variants_flagged(demo_csv):
    findings = scan_csv(demo_csv, DEMO_CONFIG)
    r14 = [f for f in findings if f.rule_id == "R14"]
    assert {"education_level", "sex"} <= {f.resource for f in r14}


def test_max_rows_limits_scan(tmp_path):
    rows = [["REC-0001", "30", "Yes"], ["REC-0002", "30", "Yes"],
            ["REC-0003", "30", "Yes"], ["REC-0004", "145", "Yes"]]
    path = write_rows(tmp_path / "ages.csv", ["record_id", "age", "consent"], rows)
    limited = scan_csv(
        path, {"ranges": {"age": {"min": 0, "max": 120}}, "max_rows": 3}
    )
    assert [f for f in limited if f.rule_id == "R03"] == []
    full = scan_csv(path, {"ranges": {"age": {"min": 0, "max": 120}}})
    assert any(f.rule_id == "R03" and f.count == 1 for f in full)
    with pytest.raises(ValueError):
        scan_csv(path, {"max_rows": 0})


def test_utf8_bom_and_bad_bytes_tolerated(tmp_path):
    path = tmp_path / "bom.csv"
    path.write_bytes(b"\xef\xbb\xbfrecord_id,age,consent\nREC-0001,30,Yes\n")
    assert scan_csv(path, {}) == []


def test_missing_consent_column_produces_dataset_finding(tmp_path):
    path = write_rows(
        tmp_path / "noconsent.csv",
        ["record_id", "sex", "age"],
        [["REC-0001", "Male", "30"], ["REC-0002", "Female", "41"]],
    )
    findings = scan_csv(path, {})
    r12 = next(f for f in findings if f.rule_id == "R12")
    assert r12.resource == "(dataset)"
    assert r12.severity == "critical"


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        scan_csv("/tmp/definitely-missing-rqe-file.csv")


def test_meets_threshold_semantics():
    high = Finding("R07", "c", "d", 1)
    low = Finding("R13", "c", "d", 1)
    critical = Finding("R08", "c", "d", 1)
    assert meets_threshold([low], "high") is True
    assert meets_threshold([high], "high") is False
    assert meets_threshold([critical], "critical") is False
    assert meets_threshold([high], "critical") is True
    assert meets_threshold([low], "low") is False
    assert meets_threshold([critical], "none") is True
    assert meets_threshold([], "high") is True
    with pytest.raises(ValueError):
        meets_threshold([], "severe")


def test_cost_model_and_r08_criticality():
    finding = Finding("R08", "x", "y", 1)
    assert RULES["R08"].severity == "critical"
    assert finding.severity == "critical"
    assert finding.est_cost(2500.0) == finding.effort_hours * 2500.0
    as_dict = finding.to_dict(rate=1000.0)
    assert as_dict["est_cost_kes"] == finding.effort_hours * 1000.0
    assert as_dict["dpa_ref"] == "sensitive personal data (health)"
    assert as_dict["gdpr_ref"] == "Art. 9"
