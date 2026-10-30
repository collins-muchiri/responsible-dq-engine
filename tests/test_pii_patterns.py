"""Tests for PII and sensitive-data detection helpers."""

from rdqe import pii_patterns as pp


def test_kenya_phone_matches_supported_formats():
    for value in ["0712345678", "+254712345678", "254712345678", "0111234567"]:
        assert pp.KENYA_PHONE_RE.findall(value) == [value], value


def test_kenya_phone_rejects_partial_and_malformed_numbers():
    for value in ["071234567", "07123456789", "1234567890", "0 712345678", "07"]:
        assert pp.KENYA_PHONE_RE.findall(value) == [], value


def test_email_strict_matching():
    assert pp.EMAIL_RE.findall("jane@example.com") == ["jane@example.com"]
    assert pp.EMAIL_RE.findall("a.b+c@sub.example.co.ke") == ["a.b+c@sub.example.co.ke"]
    assert pp.EMAIL_RE.findall("jane@example") == []
    assert pp.EMAIL_RE.findall("not-an-email") == []


def test_national_id_requires_context():
    # Bare digit run without any context must never be treated as an ID.
    assert pp.has_identifier_context("general_notes", "reference 1234567 filed") is False
    assert pp.has_identifier_context("valid_column", "1234567") is False
    # Column-name context.
    assert pp.has_identifier_context("national_id", "1234567") is True
    assert pp.has_identifier_context("huduma_number", "1112223") is True
    assert pp.has_identifier_context("kitambulisho_no", "1112223") is True
    # In-value keyword context.
    assert pp.has_identifier_context("general_notes", "ID 1234567 captured") is True
    assert pp.has_identifier_context("notes", "kitambulisho 1234567") is True


def test_national_id_length_boundaries():
    assert pp.NATIONAL_ID_RE.findall("123456") == []       # 6 digits: too short
    assert pp.NATIONAL_ID_RE.findall("1234567") == ["1234567"]
    assert pp.NATIONAL_ID_RE.findall("12345678") == ["12345678"]
    assert pp.NATIONAL_ID_RE.findall("123456789") == []    # 9 digits: too long
    assert pp.NATIONAL_ID_RE.findall("12345678 87654321") == ["12345678", "87654321"]


def test_sensitive_column_tokens_and_substrings():
    assert pp.is_sensitive_column("hiv_art") is True
    assert pp.is_sensitive_column("TB_screening") is True
    assert pp.is_sensitive_column("vl_result") is True
    assert pp.is_sensitive_column("mental_wellbeing") is True
    assert pp.is_sensitive_column("viral_load") is True
    assert pp.is_sensitive_column("health_status") is True
    assert pp.is_sensitive_column("disability_type") is True
    assert pp.is_sensitive_column("gbv_case") is True
    # Regression guards: whole-token matching, never substrings.
    assert pp.is_sensitive_column("visit_start_date") is False
    assert pp.is_sensitive_column("start_of_programme") is False
    assert pp.is_sensitive_column("smart_start") is False
    assert pp.is_sensitive_column("household_size") is False


def test_sensitive_terms_in_free_text():
    assert pp.matched_sensitive_terms("Programme start date") == []
    assert [t.lower() for t in pp.matched_sensitive_terms("Client on ART")] == ["art"]
    assert pp.matched_sensitive_terms("HIV test booked") == ["HIV"]
    assert pp.matched_sensitive_terms("Tuberculosis screening done") == ["Tuberculosis"]
    assert sorted(t.lower() for t in pp.matched_sensitive_terms("gbv survivor")) == [
        "gbv",
        "survivor",
    ]


def test_helper_predicates_and_masking():
    assert pp.is_name_column("beneficiary_name") is True
    assert pp.is_name_column("date_of_birth") is False
    assert pp.is_sex_column("sex") is True
    assert pp.is_sex_column("gender") is True
    assert pp.is_age_column("age") is True
    assert pp.is_age_column("age_years") is True
    assert pp.is_age_column("vintage") is False
    assert pp.is_location_column("gps_location") is True
    assert pp.is_disability_column("disability_type") is True
    assert pp.is_consent_column("informed_consent") is True
    assert pp.is_consent_column("kubali") is True
    assert pp.decimal_places("-1.292066") == 6
    assert pp.decimal_places("36.82") == 2
    assert pp.decimal_places("36") == 0
    assert pp.decimal_places("not a coordinate") == 0
    assert pp.mask_value("0712345678") == "07******78"
    assert pp.mask_value("jane@example.com") == "ja************om"
    assert pp.mask_value("123") == "***"
    assert pp.mask_text("call 0712345678 today", "notes") == "call 07******78 today"
    assert pp.mask_text("ID 1234567 filed", "notes") == "ID 12***67 filed"
