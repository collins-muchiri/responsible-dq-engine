# rdqe v0.1.0 - Engineering Specification

This document records the specification that release 0.1.0 implements. It is
the contract between the rule registry, the scanners, the reports, the CLI
and the CI gates.

## Mission

rdqe (Responsible Data Quality Engine) codifies a fourteen-category data
quality audit practice into an open-source CLI so any NGO team can audit
ODK/KoboToolbox survey exports and form definitions for data quality
failures and Kenya DPA 2019 / GDPR privacy risks, with costed remediation.

Audiences:

1. NGO data/MEAL teams running the audit on every export.
2. Security teams reviewing the hardened engineering posture (tests, CI,
   static analysis, secret scanning, escaping, masking, local-only design).

## Hard constraints

- Python >= 3.9. Runtime dependency: `openpyxl` only. Dev extras: `pytest`,
  `bandit`, `pip-audit`.
- Synthetic data only. No real survey, beneficiary, client or personal data
  anywhere in the repository; all fixtures obviously invented.
- No `eval`, `exec`, `subprocess` with `shell=True`, or dynamic imports of
  scanned content anywhere in `src/`.
- Scanned values are untrusted input: every dynamic string in the HTML
  report passes `html.escape`; PII evidence is masked; sensitive free-text
  disclosures are reported as matched terms only, never raw values.
- Zero network calls and zero telemetry at runtime; local-only by design.
- MIT licence, Copyright (c) 2026 Muchiri Collins Kamama.

## Rule registry (`src/rdqe/rules.py`)

- `SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]`.
- Frozen `Rule` dataclass: `rule_id`, `title`, `severity`, `category`,
  `dpa_ref` (Kenya DPA 2019 principle name), `gdpr_ref` (article numbers),
  `remediation`, `effort_hours`.
- `Finding` dataclass: `rule_id`, `resource`, `detail`, `count`, `evidence`
  (list), `sample_rows` (list); properties `severity`, `effort_hours`;
  methods `est_cost(rate)`, `to_dict(rate)`.
- `meets_threshold(findings, fail_on)`: gate semantics for CI exit codes;
  `fail_on="none"` disables the gate.

### Data rules

| ID | Title | Severity | DPA 2019 principle | GDPR |
| --- | --- | --- | --- | --- |
| R01 | Duplicate records | medium | accuracy principle | 5(1)(d) |
| R02 | Missing required values | medium | accuracy principle | 5(1)(d) |
| R03 | Out-of-range values | medium | accuracy principle | 5(1)(d) |
| R04 | Date logic violations | medium | accuracy principle | 5(1)(d) |
| R05 | Skip pattern violations | high | data minimisation | 5(1)(c) |
| R06 | Disaggregation gaps | medium | accuracy principle | 5(1)(d) |
| R07 | PII in values | high | data minimisation | 5(1)(c) |
| R08 | Sensitive category data | critical | sensitive personal data (health) | 9 |
| R09 | Direct identifiers collected | medium | data minimisation | 5(1)(c) |
| R10 | Location precision risk | high | data minimisation | 5(1)(c) |
| R11 | Child data present | high | consent and transparency | 8 |
| R12 | Consent evidence missing | critical | consent and transparency | 7 |
| R13 | Identifier format anomalies | low | accuracy principle | 5(1)(d) |
| R14 | Category inconsistency | low | accuracy principle | 5(1)(d) |

### Form rules

| ID | Title | Severity | DPA 2019 principle | GDPR |
| --- | --- | --- | --- | --- |
| F01 | Form lacks consent/privacy notice | critical | consent and transparency | 7, 12-14 |
| F02 | Sensitive fields not encrypted | high | security of processing | 32 |
| F03 | Unconstrained free text | low | data minimisation | 5(1)(c), 25 |
| F04 | GPS field precision | medium | data minimisation | 5(1)(c) |
| F05 | Broken relevant expression | medium | accuracy principle | 25 |

## PII detection (`src/rdqe/pii_patterns.py`)

- Kenya phone: `(?<!\d)(?:\+254|254|0)(?:7|1)\d{8}(?!\d)`, strict, matches
  in any value including free text.
- Email: strict pattern, any value.
- National ID `\d{7,8}`: CONTEXT-MATCHED only - the column name must carry
  identifier context (`id`, `huduma`, `kitambulisho`, `national_id`) or the
  value itself must contain such a keyword. A bare 7-digit number with no
  context must not match (regression-tested; whole-token matching keeps
  words like `valid` or `humidity` from counting as context).
- Sensitive column detection: whole-token match against
  `{hiv, aids, art, arv, vl, tb, tuberculosis, gbv, violence, survivor,
  rape, defilement, diagnosis, mental}` plus substrings
  `{viral, health_status, disability_type}`. `visit_start_date` must not be
  flagged (token `start`, not `art`) - regression-tested.
- Free-text sensitive terms: word-boundary, case-insensitive
  `\b(hiv|aids|art|arv|viral load|tb|tuberculosis|gbv|rape|defilement|survivor)\b`.
  `Programme start date` must not match `art` - regression-tested.
- Helpers: `is_name_column`, `is_location_column`, `is_sex_column`,
  `is_age_column`, `is_disability_column`, `is_consent_column`,
  `is_phone_column`, `is_national_id_column`, `decimal_places`,
  `mask_value`, `mask_text`, `find_pii_matches`.

## Data scanner (`src/rdqe/data_scanner.py`)

`scan_csv(path, config) -> list[Finding]`. Config keys, all optional:
`primary_key`, `required_fields`, `ranges`, `skip_rules`
(`{"if": {"column", "equals"}, "then_required": [...]}`), `disagg`,
`max_rows` (default 50000).

- Read with `csv.DictReader`, encoding `utf-8-sig`, errors `replace`.
- Implement every R01-R14 check; aggregate findings per rule and resource
  (one finding with a count, not one per row).
- Evidence limited to 3 masked items; `sample_rows` to 5 row numbers,
  1-based and header-aware (data row i, 0-based, is file line i + 2).
- Duplicates: full-row SHA-256 hash plus primary-key collisions when
  configured.
- Date logic: future-dated values in date-named columns and start/end
  inversions via name pairing (`start_x`/`x_start` with `end_x`/`x_end`).
- Location precision: coordinate columns by name; flag values with more
  than 3 decimal places, splitting `lat lon` pair values.
- Child data: age-like columns with `0 <= value < 18`.
- Consent: absence of any consent-like column (`consent`/`kubali`/
  `ridhaa`), or rows whose consent value is not affirmative
  (`yes/true/1/ndiyo/accept/accepted`).
- Category inconsistency: case/spacing variants of the same category in
  low-cardinality columns (<= 12 distinct values).
- PII evidence masking: matched values are rendered as first two
  characters + asterisks + last two characters.

## XLSForm scanner (`src/rdqe/xlsform_scanner.py`)

`scan_xlsform(path) -> list[Finding]` using openpyxl read-only:

- Locate the survey sheet case-insensitively; parse headers lowercased;
  collect field names; skip group/repeat begin/end markers.
- F01 when no field name/label matches consent keywords (`consent`,
  `kubali`, `ridhaa`, `privacy notice`, `informed_consent`,
  `agree_to_participate`).
- F02 for sensitive-named or health-labelled fields whose type does not
  contain `encrypt`.
- R09 for name columns and national-ID columns.
- F04 for `geopoint`/`geotrace`/`geoshape` types.
- F03 for `text` type without a constraint.
- F05 for `${field}` references in relevant expressions pointing to unknown
  fields (XLSForm function names ignored).

## Reports (`src/rdqe/report.py`)

- `to_json`: `{tool, version, generated_at, meta, summary (counts by
  severity, total effort hours, total estimated cost KES at rate),
  findings[]}`.
- `to_html`: self-contained (inline CSS, no external assets, no scripts),
  severity summary cards, findings table sorted by severity, per-finding
  legal references + remediation + cost, methodology footer carrying the
  synthetic-data and local-only pledges.
- Every dynamic value is `html.escape`d. Severity colours: critical
  `#FFC7CE`, high `#FCE4D6`, medium `#FFEB9C`, low `#E2EFDA`, info
  `#DDEBF7`; navy `#1F3864` header.

## CLI (`src/rdqe/cli.py`)

- Subcommands: `scan-data CSV [--config JSON]`, `scan-form XLSX`, `demo`.
- Common flags: `--out DIR` (default `reports`), `--format {html,json}`
  repeatable (default both), `--fail-on {none,low,medium,high,critical}`
  (default `high`), `--rate FLOAT` (default 2500.0 KES/hour).
- Exit codes: 0 clean/below threshold, 1 gate tripped, 2 usage error.
- Entry point: `rdqe = rdqe.cli:entry`.
- `demo` writes `synthetic_survey_data.csv` and `synthetic_form.xlsx`,
  seeded to trigger every rule, then runs both scanners; exit 0 under
  `--fail-on none`.

## Quality gates (all must pass before release)

```
pip install -e ".[dev]"
pytest -q                                  # all green (>= 30 tests)
bandit -c .bandit -r src                   # 0 issues
pip-audit -r <(echo "openpyxl>=3.1")       # no known vulnerabilities
grep -rn -E "eval\(|exec\(|shell=True" src/rdqe/   # zero hits
rdqe demo --out examples --fail-on none    # >= 20 findings across severities
```

## Test requirements

Minimum 30 tests, all passing, explicitly covering: demo artefacts trigger
R01-R14 and F01-F05 + R09; a clean engineered CSV yields zero findings under
the demo config; masking of phone/email/ID evidence; XSS safety of the HTML
report; false-positive guards (bare `1234567`, `visit_start_date`,
`Programme start date`); the CLI exit-code contract; the cost model and
R08 criticality.
