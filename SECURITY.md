# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

## Reporting a vulnerability

Please report suspected vulnerabilities privately to
**kamamamuchiri@yahoo.com**. Do not open a public GitHub issue for anything
you believe is exploitable. Include a description, the affected version or
commit, and steps to reproduce. You can expect an acknowledgement within 7
days and a fix or mitigation plan within 30 days for confirmed issues.

## Security design

- **Local-only by design.** rdqe makes zero network calls and collects zero
  telemetry at runtime. Its only runtime dependency is `openpyxl`. Reports
  are written to local disk only.
- **Untrusted input.** Scanned CSV/XLSX content is treated as hostile:
  every dynamic value in the HTML report is `html.escape`d, PII evidence is
  masked before storage (for example `07******78`), and sensitive free-text
  disclosures are reported as matched terms only. Semgrep guardrails forbid
  `eval()`, `exec()` and `shell=True` in `src/`.
- **No secrets in the repository.** gitleaks runs in CI and pre-commit;
  `.gitignore` covers `.env`, `reports/` and local outputs. If you believe a
  credential was committed, rotate it immediately and contact the address
  above.
- **Supply chain.** CI runs pip-audit against the runtime dependency set and
  must come back clean.

## Scope and warranty

rdqe is a planning and audit aid. Severity levels, effort estimates and cost
figures are planning inputs, not legal advice or quotations, and do not by
themselves demonstrate compliance with the Kenya Data Protection Act (2019),
GDPR or any other law. The software is provided under the MIT licence, as
is, without warranty of any kind.
