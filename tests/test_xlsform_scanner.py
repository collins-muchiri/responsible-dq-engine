"""Tests for the XLSForm scanner (F01-F05 plus R09)."""

import pytest
from openpyxl import Workbook

from rdqe.xlsform_scanner import scan_xlsform

HEADERS = ["type", "name", "label", "relevant", "constraint", "required"]


def _write_form(path, sheet_name, rows):
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = sheet_name
    sheet.append(HEADERS)
    for row in rows:
        sheet.append(row)
    workbook.save(str(path))
    return path


def test_demo_form_triggers_all_form_rules(demo_form):
    findings = scan_xlsform(demo_form)
    rules = {f.rule_id for f in findings}
    assert {"F01", "F02", "F03", "F04", "F05", "R09"} <= rules


def test_demo_form_group_rows_are_not_fields(demo_form):
    findings = scan_xlsform(demo_form)
    assert "respondent_group" not in {f.resource for f in findings}


def test_clean_form_yields_no_findings(tmp_path):
    path = _write_form(
        tmp_path / "good_form.xlsx",
        "survey",
        [
            ["text", "beneficiary_code", "Beneficiary code", "", "length(.) < 40", "yes"],
            ["encrypt", "hiv_status", "HIV status", "", "", "yes"],
            ["note", "consent_statement", "Do you consent to participate?", "", "", ""],
            ["select_one yes_no", "household_visited", "Was the household visited?",
             "", "", ""],
            ["text", "follow_up_notes", "Follow-up notes",
             "${consent_statement} != 'Yes'", "length(.) <= 200", ""],
        ],
    )
    choices = Workbook()
    choices.save(str(tmp_path / "unused.xlsx"))
    assert scan_xlsform(path) == []


def test_survey_sheet_lookup_is_case_insensitive(tmp_path):
    path = _write_form(
        tmp_path / "upper_form.xlsx",
        "Survey",
        [
            ["text", "beneficiary_code", "Beneficiary code", "", "length(.) < 40", ""],
            ["note", "consent_statement", "Do you consent to participate?", "", "", ""],
        ],
    )
    findings = scan_xlsform(path)
    assert {f.rule_id for f in findings} == set()


def test_missing_survey_sheet_raises(tmp_path):
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "not_survey"
    sheet.append(["type", "name"])
    path = tmp_path / "invalid.xlsx"
    workbook.save(str(path))
    with pytest.raises(ValueError):
        scan_xlsform(path)


def test_relevant_reference_validation(tmp_path):
    path = _write_form(
        tmp_path / "refs.xlsx",
        "survey",
        [
            ["note", "consent_statement", "Do you consent to participate?", "", "", ""],
            ["text", "bad_ref", "Broken reference", "${does_not_exist} = 'x'", "", ""],
            ["text", "good_ref", "Valid reference", "${consent_statement} = 'Yes'",
             "length(.) < 20", ""],
            ["text", "func_ref", "Function reference", "${today} != ''",
             "length(.) < 20", ""],
        ],
    )
    findings = scan_xlsform(path)
    f05 = [f for f in findings if f.rule_id == "F05"]
    assert len(f05) == 1
    assert f05[0].resource == "bad_ref"
    assert "does_not_exist" in f05[0].detail


def test_encrypted_sensitive_field_is_not_flagged(tmp_path):
    path = _write_form(
        tmp_path / "encrypted.xlsx",
        "survey",
        [
            ["note", "consent_statement", "Do you consent to participate?", "", "", ""],
            ["encrypt", "hiv_status", "HIV status", "", "", ""],
        ],
    )
    assert [f for f in scan_xlsform(path) if f.rule_id == "F02"] == []


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        scan_xlsform("/tmp/definitely-missing-rqe-form.xlsx")
