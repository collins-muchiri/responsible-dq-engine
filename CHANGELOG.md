# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] (2026-10-30)

### Added

- Fourteen data rules (R01-R14) for CSV survey exports: duplicate records,
  missing required values, out-of-range values, date logic violations, skip
  pattern violations, disaggregation gaps, PII in values, sensitive category
  data, direct identifiers collected, location precision risk, child data
  present, consent evidence missing, identifier format anomalies and
  category inconsistency.
- Five form rules (F01-F05) plus R09 for XLSForm definitions: missing
  consent/privacy notice, unencrypted sensitive fields, unconstrained free
  text, GPS precision and broken relevant expressions.
- CLI with `scan-data`, `scan-form` and `demo` subcommands, JSON and
  self-contained HTML reports, severity summary cards, costed remediation
  totals (default rate 2500.0 KES/hour) and an exit-code gate
  (`--fail-on`, exit 0/1/2).
- Privacy hardening: strict Kenya phone/email detection, context-guarded
  national-ID detection, whole-token sensitive column detection, masked
  evidence (`07******78`), matched-terms-only reporting for sensitive free
  text, and full HTML escaping of untrusted scanned values.
- Security tooling: Bandit (0-issue gate), custom Semgrep ERROR guardrails
  (no `eval`, no `exec`, no `shell=True`), pip-audit, gitleaks, pre-commit
  hooks and a CI workflow running pytest on Python 3.9/3.11/3.12 plus all
  security gates.
- Synthetic demo artefacts seeded to trigger every rule, with no real
  survey, beneficiary or personal data anywhere in the repository.
