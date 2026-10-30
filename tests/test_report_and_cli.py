"""Tests for report builders and the CLI contract."""

import json
from pathlib import Path

import pytest

from rdqe import __version__
from rdqe.cli import main
from rdqe.report import to_html, to_json
from rdqe.rules import Finding


def test_demo_writes_all_artefacts_and_expected_rules(tmp_path):
    exit_code = main(["demo", "--out", str(tmp_path), "--fail-on", "none"])
    assert exit_code == 0
    for name in [
        "synthetic_survey_data.csv",
        "synthetic_form.xlsx",
        "demo_config.json",
        "rdqe_report.json",
        "rdqe_report.html",
    ]:
        assert (tmp_path / name).is_file(), name
    report = json.loads((tmp_path / "rdqe_report.json").read_text(encoding="utf-8"))
    rules = {f["rule_id"] for f in report["findings"]}
    assert {"R01", "R07", "R08", "F01", "F02"} <= rules


def test_demo_covers_all_rules_and_severities(tmp_path):
    main(["demo", "--out", str(tmp_path), "--fail-on", "none"])
    report = json.loads((tmp_path / "rdqe_report.json").read_text(encoding="utf-8"))
    rules = {f["rule_id"] for f in report["findings"]}
    assert all(f"R{n:02d}" in rules for n in range(1, 15))
    assert {"F01", "F02", "F03", "F04", "F05"} <= rules
    severities = {f["severity"] for f in report["findings"]}
    assert {"critical", "high", "medium", "low"} <= severities
    assert report["summary"]["total_findings"] >= 20


def test_demo_default_gate_exits_1(tmp_path):
    assert main(["demo", "--out", str(tmp_path)]) == 1


def test_json_report_structure_and_totals(tmp_path, demo_csv):
    out = tmp_path / "reports"
    assert main(["scan-data", str(demo_csv), "--out", str(out), "--fail-on", "none"]) == 0
    report = json.loads((out / "synthetic_survey_data_report.json").read_text(encoding="utf-8"))
    assert {"tool", "version", "generated_at", "meta", "summary", "findings"} <= set(report)
    assert report["tool"] == "rdqe"
    assert report["version"] == __version__
    summary = report["summary"]
    assert summary["total_findings"] == len(report["findings"])
    hours = sum(f["effort_hours"] for f in report["findings"])
    assert summary["total_effort_hours"] == pytest.approx(hours)
    assert summary["total_est_cost_kes"] == pytest.approx(
        sum(f["est_cost_kes"] for f in report["findings"])
    )


def test_findings_sorted_by_severity(tmp_path, demo_csv):
    out = tmp_path / "reports"
    main(["scan-data", str(demo_csv), "--out", str(out), "--fail-on", "none"])
    report = json.loads((out / "synthetic_survey_data_report.json").read_text(encoding="utf-8"))
    order = ["info", "low", "medium", "high", "critical"]
    ranks = [order.index(f["severity"]) for f in report["findings"]]
    assert ranks == sorted(ranks, reverse=True)
    assert report["findings"][0]["rule_id"] == "R08"


def test_html_escapes_untrusted_content():
    findings = [
        Finding(
            "R01",
            "<script>alert(1)</script>",
            "<script>alert(1)</script>",
            1,
            evidence=["<script>alert(1)</script>"],
        )
    ]
    rendered = to_html(findings, {"sources": ["x.csv"], "scan_type": "test"})
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<script>alert(1)" not in rendered


def test_html_contains_pledges_cards_and_legal_refs(tmp_path, demo_csv):
    out = tmp_path / "reports"
    main(["scan-data", str(demo_csv), "--out", str(out), "--fail-on", "none"])
    rendered = (out / "synthetic_survey_data_report.html").read_text(encoding="utf-8")
    assert "Synthetic data only" in rendered
    assert "Local-only" in rendered
    assert "Masked evidence" in rendered
    assert "#1F3864" in rendered
    assert "07******78" in rendered
    assert "Kenya DPA 2019" in rendered
    assert "sensitive personal data (health)" in rendered


def test_cli_exit_code_contract(tmp_path, demo_csv, clean_csv):
    assert main(["scan-data", str(clean_csv), "--out", str(tmp_path / "a")]) == 0
    assert main(["scan-data", str(demo_csv), "--out", str(tmp_path / "b"), "--fail-on", "high"]) == 1
    assert main(["scan-data", str(demo_csv), "--out", str(tmp_path / "c"), "--fail-on", "none"]) == 0
    assert main(["scan-data", str(tmp_path / "missing.csv"), "--out", str(tmp_path / "d")]) == 2
    assert main(["scan-form", str(tmp_path / "missing.xlsx"), "--out", str(tmp_path / "e")]) == 2


def test_rate_flag_feeds_cost_model(tmp_path, demo_csv):
    assert main(
        ["scan-data", str(demo_csv), "--out", str(tmp_path), "--fail-on", "none",
         "--rate", "1000"]
    ) == 0
    report = json.loads((tmp_path / "synthetic_survey_data_report.json").read_text(encoding="utf-8"))
    expected = sum(f["effort_hours"] for f in report["findings"]) * 1000.0
    assert report["summary"]["total_est_cost_kes"] == pytest.approx(expected)


def test_format_flag_is_repeatable(tmp_path, demo_csv):
    only_json = tmp_path / "json_only"
    main(["scan-data", str(demo_csv), "--out", str(only_json), "--fail-on", "none",
          "--format", "json"])
    assert (only_json / "synthetic_survey_data_report.json").is_file()
    assert not (only_json / "synthetic_survey_data_report.html").exists()

    both = tmp_path / "both"
    main(["scan-data", str(demo_csv), "--out", str(both), "--fail-on", "none",
          "--format", "json", "--format", "html"])
    assert (both / "synthetic_survey_data_report.json").is_file()
    assert (both / "synthetic_survey_data_report.html").is_file()


def test_scan_form_cli(tmp_path, demo_form):
    out = tmp_path / "reports"
    assert main(["scan-form", str(demo_form), "--out", str(out), "--fail-on", "none"]) == 0
    report = json.loads((out / "synthetic_form_report.json").read_text(encoding="utf-8"))
    rules = {f["rule_id"] for f in report["findings"]}
    assert {"F01", "F02", "F05", "R09"} <= rules


def test_usage_errors_exit_2(tmp_path, demo_csv):
    with pytest.raises(SystemExit) as exc:
        main(["scan-data"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main(["bogus-command"])
    assert exc.value.code == 2
    missing_config = tmp_path / "nope.json"
    assert main(["scan-data", str(demo_csv), "--config", str(missing_config)]) == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_to_json_shape_with_meta():
    findings = [Finding("R13", "c", "d", 2, evidence=["e1"], sample_rows=[2, 3])]
    payload = json.loads(to_json(findings, {"sources": ["t.csv"], "scan_type": "data"}))
    assert payload["meta"]["scan_type"] == "data"
    assert payload["findings"][0]["resource"] == "c"
    assert payload["findings"][0]["count"] == 2
