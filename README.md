# rdqe: Responsible Data Quality Engine

[![CI](https://github.com/collins-muchiri/responsible-dq-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/collins-muchiri/responsible-dq-engine/actions/workflows/ci.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-green.svg)](https://github.com/collins-muchiri/responsible-dq-engine/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.11%20%7C%203.12-blue.svg)](https://github.com/collins-muchiri/responsible-dq-engine)

rdqe audits ODK/KoboToolbox-style survey exports and XLSForm definitions for
data quality failures and privacy risks, and prices the clean-up: every
finding carries a severity, the Kenya Data Protection Act (2019) principle
and GDPR article it implicates, a remediation note, an effort estimate and an
estimated cost in KES at an adjustable hourly rate. It packages a
fourteen-category manual audit practice into one CLI so that NGO data and
MEAL teams can run it on every export, and CI can fail a pipeline when the
data is not fit to report.

**The pledges, up front:**

- **Synthetic data only.** rdqe ships only obviously invented fixture data
  (`Test Person 01`, placeholder phone numbers, impossible IDs). Never point
  the demo at real records, and never commit real survey, beneficiary,
  client or personal data to this repository.
- **Local-only.** The engine makes zero network calls and collects zero
  telemetry at runtime. Reports are written to your local disk and nowhere
  else.
- **Masked evidence.** Personal data found in values is masked before it
  reaches a report (for example `07******78`), and sensitive free-text
  disclosures are reported as matched terms only, never as raw values.

## Why

MEAL (monitoring, evaluation, accountability and learning) teams inherit
survey exports that are duplicated, half-filled, mis-skipped and full of
identifiers typed into notes fields, and donor-funded programmes carry legal
duties under the Kenya Data Protection Act (2019) and, for many partners,
GDPR. rdqe turns the manual audit into a repeatable, exit-coded check:
run it after every export, attach the HTML report to the data-handling file,
and let CI block releases when critical findings exist.

## Quickstart

Tested verbatim against a fresh clone:

```bash
git clone https://github.com/collins-muchiri/responsible-dq-engine.git
cd responsible-dq-engine
pip install -e .
rdqe demo --out reports --fail-on none
rdqe scan-data reports/synthetic_survey_data.csv --config reports/demo_config.json
rdqe scan-form reports/synthetic_form.xlsx
```

The demo writes `synthetic_survey_data.csv`, `synthetic_form.xlsx`,
`demo_config.json`, `rdqe_report.json` and `rdqe_report.html` into the
`--out` directory and audits them (34 findings across all severities).

Note the exit codes in the quickstart: the two `scan-*` commands exit `1`
because the seeded findings meet the default `--fail-on high` gate. That is
the CI gate working as designed; add `--fail-on none` to force exit `0`.

## Rules

### Data rules (R01-R14): `rdqe scan-data`

| ID | Rule | Severity | Kenya DPA 2019 | GDPR |
| --- | --- | --- | --- | --- |
| R01 | Duplicate records (full-row and primary-key collisions) | medium | accuracy principle | Art. 5(1)(d) |
| R02 | Missing required values | medium | accuracy principle | Art. 5(1)(d) |
| R03 | Out-of-range values | medium | accuracy principle | Art. 5(1)(d) |
| R04 | Date logic violations (future dates, inverted start/end pairs) | medium | accuracy principle | Art. 5(1)(d) |
| R05 | Skip pattern violations | high | data minimisation | Art. 5(1)(c) |
| R06 | Disaggregation gaps (uncoded or missing categories) | medium | accuracy principle | Art. 5(1)(d) |
| R07 | PII in values (phones, emails, contextual national IDs) | high | data minimisation | Art. 5(1)(c) |
| R08 | Sensitive category data (health/GBV markers in columns or free text) | critical | sensitive personal data (health) | Art. 9 |
| R09 | Direct identifiers collected (name, phone, national-ID columns) | medium | data minimisation | Art. 5(1)(c) |
| R10 | Location precision risk (coordinates beyond 3 decimal places) | high | data minimisation | Art. 5(1)(c) |
| R11 | Child data present (age-like columns with values under 18) | high | consent and transparency | Art. 8 |
| R12 | Consent evidence missing (no consent column, or non-affirmative values) | critical | consent and transparency | Art. 7 |
| R13 | Identifier format anomalies (6-digit IDs, 9-digit phones) | low | accuracy principle | Art. 5(1)(d) |
| R14 | Category inconsistency (case/spacing variants of the same value) | low | accuracy principle | Art. 5(1)(d) |

### Form rules (F01-F05): `rdqe scan-form`

| ID | Rule | Severity | Kenya DPA 2019 | GDPR |
| --- | --- | --- | --- | --- |
| F01 | Form lacks consent/privacy notice | critical | consent and transparency | Art. 7 and Art. 12-14 |
| F02 | Sensitive fields not encrypted | high | security of processing | Art. 32 |
| F03 | Unconstrained free text | low | data minimisation | Art. 5(1)(c) and Art. 25 |
| F04 | GPS field precision (geopoint/geotrace/geoshape) | medium | data minimisation | Art. 5(1)(c) |
| F05 | Broken relevant expression (`${field}` pointing nowhere) | medium | accuracy principle | Art. 25 |

Detection is deliberately conservative: Kenya phone numbers and emails use
strict patterns and match anywhere (including free text); national-ID digit
runs (7-8 digits) only match with identifier context from the column name
(`id`, `huduma`, `kitambulisho`, `national_id`) or the value itself, so a
bare `1234567` never raises a finding; sensitive column names match whole
tokens (`visit_start_date` is safe; `hiv_art` is not); and sensitive terms in
free text use word boundaries (`Programme start date` is safe).

## Configuration

`rdqe scan-data` takes an optional JSON config; every key is optional:

```json
{
  "primary_key": "record_id",
  "required_fields": ["record_id", "visit_start_date", "consent", "sex", "age"],
  "ranges": {"age": {"min": 0, "max": 120}},
  "skip_rules": [
    {
      "if": {"column": "currently_pregnant", "equals": "Yes"},
      "then_required": ["anc_facility"]
    }
  ],
  "disagg": {"sex": ["Male", "Female"]},
  "max_rows": 50000
}
```

| Key | Meaning |
| --- | --- |
| `primary_key` | column checked for duplicate key collisions (R01) |
| `required_fields` | columns that must be non-empty on every row (R02) |
| `ranges` | inclusive `{min, max}` bounds per numeric column (R03) |
| `skip_rules` | when `if.column == if.equals`, each `then_required` field must be filled (R05) |
| `disagg` | allowed coded values per disaggregation column; uncoded values and absent categories are reported (R06) |
| `max_rows` | scan cap, default 50000 |

## CLI and exit codes

```
rdqe scan-data CSV [--config JSON] [--out DIR] [--format html|json]... [--fail-on LEVEL] [--rate FLOAT]
rdqe scan-form XLSX [--out DIR] [--format html|json]... [--fail-on LEVEL] [--rate FLOAT]
rdqe demo [--out DIR] [--format html|json]... [--fail-on LEVEL] [--rate FLOAT]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--out` | `reports` | directory for generated reports (and demo artefacts) |
| `--format` | both | report format; repeatable (`--format json --format html`) |
| `--fail-on` | `high` | severity gate for the exit code; `none` disables the gate |
| `--rate` | `2500.0` | remediation cost rate in KES/hour (`est_cost = effort_hours x rate`) |

| Exit code | Meaning |
| --- | --- |
| `0` | scan completed with no findings at or above the threshold (or gate disabled) |
| `1` | gate tripped: at least one finding at or above `--fail-on` |
| `2` | usage error: missing file, unreadable/invalid config, unknown arguments |

## CI gate

The `security-gates` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
is the template to copy into your own pipeline:

```yaml
security-gates:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    - uses: actions/setup-python@v5
      with:
        python-version: "3.12"
    - run: |
        python -m pip install --upgrade pip
        pip install -e ".[dev]"
    - run: bandit -c .bandit -r src
    - run: |
        pip install semgrep
        semgrep --config .semgrep.yml --error src
    - run: pip-audit -r <(echo "openpyxl>=3.1")
    - uses: gitleaks/gitleaks-action@v2
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

And the data-quality gate itself, in any workflow that produces an export:

```yaml
- run: rdqe scan-data exports/latest.csv --config audit_config.json
```

Exit `1` fails the job when findings meet the threshold.

## Security posture

- **Static analysis**: Bandit (0 issues required), Semgrep with custom ERROR
  guardrails forbidding `eval()`, `exec()` and `shell=True` in `src/`.
- **Dependency audit**: pip-audit on the single runtime dependency
  (`openpyxl`); no known vulnerabilities allowed.
- **Secret scanning**: gitleaks in CI and pre-commit; no tokens, credentials
  or `.env` files are ever committed.
- **Untrusted input handling**: scanned values are treated as hostile. Every
  dynamic string in the HTML report passes through `html.escape`; PII
  evidence is masked (`07******78`); sensitive free-text disclosures are
  reported as matched terms only. An `<script>` payload in a data value
  renders escaped in the report: tested.
- **No network, no telemetry**: zero runtime network calls by design; the
  only runtime dependency is `openpyxl`.
- **Principle of least data**: the tool reports counts, masked evidence and
  row numbers: never raw personal values.

## Project layout

```
responsible-dq-engine/
  pyproject.toml        setuptools, src layout, [project.scripts] rdqe
  README.md  LICENSE  CHANGELOG.md  SECURITY.md  .gitignore
  .bandit               bandit configuration (exclude tests/examples, skip B101)
  .semgrep.yml          custom ERROR rules: no eval, no exec, no shell=True
  .pre-commit-config.yaml   bandit + gitleaks + semgrep hooks
  .github/workflows/ci.yml  pytest matrix (3.9/3.11/3.12) + security gates
  src/rdqe/             rules.py, pii_patterns.py, data_scanner.py,
                        xlsform_scanner.py, report.py, cli.py
  tests/                50 tests covering scanners, reports and the CLI
  examples/             generated by `rdqe demo --out examples`
  docs/SPECIFICATION.md the engineering specification this release implements
```

## Development

```bash
pip install -e ".[dev]"
pytest -q
bandit -c .bandit -r src
pip-audit -r <(echo "openpyxl>=3.1")
rdqe demo --out examples --fail-on none   # >= 20 findings across severities
```

## Roadmap

- PostgreSQL scanner for server-hosted programme databases
- KoboToolbox API integration (pull exports directly, still via a local-only token flow)
- XLSForm auto-fix suggestions (write corrected survey sheets)
- Small-cell suppression reporting for publishable tables
- PyPI release
- DHIS2-specific data-quality profiles

## Origin and attribution

rdqe was built by **Muchiri Collins Kamama**, a MEAL practitioner and data
systems engineer in Nairobi:
[portfolio]( P2 ),
[GitHub](https://github.com/collins-muchiri).

The fourteen-category audit framework comes from real donor-funded programme
audits, including PEPFAR-supported health programmes and UNDP GEF Small
Grants Programme projects. No client-identifying or beneficiary data appears
in this repository: every rule, fixture and example is synthetic, and the
framework is expressed only as generic checks, thresholds and legal
references.

## Licence

[MIT](LICENSE): Copyright (c) 2026 Muchiri Collins Kamama
