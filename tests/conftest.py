"""Shared fixtures: synthetic demo artefacts and an engineered clean export."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from rdqe.cli import DEMO_CONFIG, write_demo_csv, write_demo_xlsx

CLEAN_HEADERS = [
    "record_id",
    "sex",
    "age",
    "currently_pregnant",
    "anc_facility",
    "visit_start_date",
    "visit_end_date",
    "interview_start",
    "interview_end",
    "consent",
    "education_level",
    "general_notes",
]

# Engineered to produce ZERO findings under DEMO_CONFIG: valid consent
# everywhere, no PII, consistent categories, plausible dates, no minors.
CLEAN_ROWS = [
    ["REC-0001", "Female", "34", "No", "", "2024-02-10", "2024-02-10",
     "2024-02-01", "2024-02-05", "Yes", "Primary",
     "Routine follow-up completed as scheduled."],
    ["REC-0002", "Male", "41", "No", "", "2024-02-11", "2024-02-11",
     "2024-02-02", "2024-02-06", "Yes", "Secondary",
     "Household verified during the visit."],
    ["REC-0003", "Female", "28", "Yes", "Baraka Health Centre", "2024-02-12", "2024-02-12",
     "2024-02-03", "2024-02-07", "Yes", "Primary",
     "Antenatal record verified."],
    ["REC-0004", "Male", "37", "No", "", "2024-02-13", "2024-02-13",
     "2024-02-04", "2024-02-08", "Yes", "Secondary",
     "Referral slip issued."],
    ["REC-0005", "Female", "45", "No", "", "2024-02-14", "2024-02-14",
     "2024-02-05", "2024-02-09", "Yes", "Tertiary",
     "Data entry completed the same day."],
    ["REC-0006", "Male", "52", "No", "", "2024-02-15", "2024-02-15",
     "2024-02-06", "2024-02-10", "Yes", "Primary",
     "Next visit agreed with the household."],
    ["REC-0007", "Female", "31", "Yes", "Baraka Health Centre", "2024-02-16", "2024-02-16",
     "2024-02-07", "2024-02-11", "Yes", "Secondary",
     "Consent form reference filed."],
    ["REC-0008", "Male", "24", "No", "", "2024-02-17", "2024-02-17",
     "2024-02-08", "2024-02-12", "Yes", "Primary",
     "Household roster updated."],
]


@pytest.fixture()
def demo_csv(tmp_path: Path) -> Path:
    path = tmp_path / "synthetic_survey_data.csv"
    write_demo_csv(path)
    return path


@pytest.fixture()
def demo_form(tmp_path: Path) -> Path:
    path = tmp_path / "synthetic_form.xlsx"
    write_demo_xlsx(path)
    return path


@pytest.fixture()
def demo_config() -> dict:
    return dict(DEMO_CONFIG)


@pytest.fixture()
def clean_csv(tmp_path: Path) -> Path:
    path = tmp_path / "clean_survey.csv"
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(CLEAN_HEADERS)
        writer.writerows(CLEAN_ROWS)
    return path


def write_rows(path: Path, headers: list, rows: list) -> Path:
    """Helper for one-off synthetic exports in tests."""
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)
    return path
