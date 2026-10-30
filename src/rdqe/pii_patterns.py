"""PII and sensitive-data detection helpers.

Scanned survey values are treated as untrusted input. The patterns here are
deliberately conservative: phone numbers and email addresses use strict
matching in any value (including free text), while national-ID matching is
context-guarded so that a bare seven-digit number is never reported as an
identifier without corroborating column-name or in-value context.

Evidence strings built from scanned values must pass through ``mask_text``
before they are stored on a Finding. Sensitive free-text disclosures are
reported as matched terms only, never as raw values.
"""

from __future__ import annotations

import re
from typing import List, Tuple

# Strict Kenya mobile number: 07XX XXX XXX / 01XX XXX XXX, with the
# international 254 / +254 prefixes accepted. Lookarounds stop partial
# runs inside longer digit sequences from matching.
KENYA_PHONE_RE = re.compile(r"(?<!\d)(?:\+254|254|0)(?:7|1)\d{8}(?!\d)")

# Strict email: local part, @, dotted domain with a 2+ letter TLD.
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# National ID runs of 7 or 8 digits. CONTEXT-GUARDED: only applied when
# has_identifier_context() returns True for the column/value pair.
NATIONAL_ID_RE = re.compile(r"(?<!\d)\d{7,8}(?!\d)")

# Column-name shapes that indicate an identifier column. Tokenised so that
# words merely containing "id" (for example "valid" or "humidity") never match.
_ID_NAME_TOKEN_RE = re.compile(r"(?:^|[^a-z0-9])ids?(?:[^a-z0-9]|$)")
_ID_NAME_KEYWORDS = ("huduma", "kitambulisho", "national_id", "national id")
_ID_VALUE_KEYWORD_RE = re.compile(
    r"\b(?:ids?|i\.d\.|huduma|kitambulisho)\b", re.IGNORECASE
)

# Whole-token sensitive markers for column names. "visit_start_date" is safe
# because its tokens are visit/start/date and "start" is not "art".
SENSITIVE_TOKENS = {
    "hiv",
    "aids",
    "art",
    "arv",
    "vl",
    "tb",
    "tuberculosis",
    "gbv",
    "violence",
    "survivor",
    "rape",
    "defilement",
    "diagnosis",
    "mental",
}
SENSITIVE_SUBSTRINGS = ("viral", "health_status", "disability_type")

# Word-boundary sensitive terms for free-text values. "Programme start date"
# never matches because \bart\b cannot fire inside "start".
SENSITIVE_TERM_RE = re.compile(
    r"\b(?:hiv|aids|art|arv|viral load|tb|tuberculosis|gbv|rape|defilement|survivor)\b",
    re.IGNORECASE,
)

# Consent handling.
AFFIRMATIVE_CONSENT = {"yes", "true", "1", "ndiyo", "accept", "accepted"}


def tokens(name: str) -> List[str]:
    """Lowercase alphanumeric tokens of *name* split on non-alphanumerics."""
    return [t for t in re.split(r"[^a-z0-9]+", name.lower()) if t]


def has_identifier_context(column_name: str, value: str = "") -> bool:
    """Return True when the column name or the value itself provides the
    context needed to treat digit runs as national-ID candidates."""
    low = column_name.lower()
    if _ID_NAME_TOKEN_RE.search(low):
        return True
    if any(keyword in low for keyword in _ID_NAME_KEYWORDS):
        return True
    return bool(_ID_VALUE_KEYWORD_RE.search(value))


def is_sensitive_column(column_name: str) -> bool:
    """True when the column name carries sensitive-data markers."""
    if any(token in SENSITIVE_TOKENS for token in tokens(column_name)):
        return True
    low = column_name.lower()
    return any(marker in low for marker in SENSITIVE_SUBSTRINGS)


def matched_sensitive_terms(value: str) -> List[str]:
    """Matched sensitive terms in a free-text value (terms only, no values)."""
    return [match.group(0) for match in SENSITIVE_TERM_RE.finditer(value)]


_NAME_TOKENS = {
    "name",
    "names",
    "firstname",
    "lastname",
    "fullname",
    "fname",
    "lname",
    "surname",
    "forename",
    "givenname",
    "familyname",
}
_LOCATION_TOKENS = {
    "gps",
    "lat",
    "latitude",
    "lon",
    "lng",
    "long",
    "longitude",
    "location",
    "coordinates",
    "coord",
    "geopoint",
    "geotrace",
    "geoshape",
}
_SEX_TOKENS = {"sex", "gender"}
_AGE_TOKENS = {"age"}
_DISABILITY_TOKENS = {"disability", "disabled"}
_CONSENT_TOKENS = {"consent", "kubali", "ridhaa"}
_NATIONAL_ID_TOKENS = {"huduma", "kitambulisho"}


def is_name_column(column_name: str) -> bool:
    return any(token in _NAME_TOKENS for token in tokens(column_name))


def is_location_column(column_name: str) -> bool:
    return any(token in _LOCATION_TOKENS for token in tokens(column_name))


def is_sex_column(column_name: str) -> bool:
    return any(token in _SEX_TOKENS for token in tokens(column_name))


def is_age_column(column_name: str) -> bool:
    return any(token in _AGE_TOKENS for token in tokens(column_name))


def is_disability_column(column_name: str) -> bool:
    if any(token in _DISABILITY_TOKENS for token in tokens(column_name)):
        return True
    return "disability_type" in column_name.lower()


def is_consent_column(column_name: str) -> bool:
    low = column_name.lower()
    if any(token in _CONSENT_TOKENS for token in tokens(low)):
        return True
    return "consent" in low


def is_phone_column(column_name: str) -> bool:
    return any(token in {"phone", "telephone", "mobile", "simu"} for token in tokens(column_name))


def is_national_id_column(column_name: str) -> bool:
    column_tokens = tokens(column_name)
    if any(token in _NATIONAL_ID_TOKENS for token in column_tokens):
        return True
    return "national" in column_tokens and "id" in column_tokens


def decimal_places(text: str) -> int:
    """Number of digits after the decimal point in a numeric-looking string."""
    text = text.strip()
    if "." not in text:
        return 0
    fraction = text.rsplit(".", 1)[1]
    return len(fraction) if fraction.isdigit() else 0


def mask_value(matched: str) -> str:
    """Mask a matched PII string: first two chars, asterisks, last two chars."""
    if len(matched) <= 4:
        return "*" * len(matched)
    return matched[:2] + "*" * (len(matched) - 4) + matched[-2:]


def mask_text(text: str, column_name: str = "") -> str:
    """Mask every PII match inside *text* before it becomes report evidence."""
    text = KENYA_PHONE_RE.sub(lambda m: mask_value(m.group(0)), text)
    text = EMAIL_RE.sub(lambda m: mask_value(m.group(0)), text)
    if has_identifier_context(column_name, text):
        text = NATIONAL_ID_RE.sub(lambda m: mask_value(m.group(0)), text)
    return text


def find_pii_matches(value: str, column_name: str) -> List[Tuple[str, str]]:
    """Return (kind, matched_text) tuples for PII found in *value*."""
    found: List[Tuple[str, str]] = []
    found.extend(("phone number", m) for m in KENYA_PHONE_RE.findall(value))
    found.extend(("email address", m) for m in EMAIL_RE.findall(value))
    if has_identifier_context(column_name, value):
        found.extend(("national ID", m) for m in NATIONAL_ID_RE.findall(value))
    return found
