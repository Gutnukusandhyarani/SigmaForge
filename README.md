# SigmaForge — Detection-as-Code Workbench

**A defensive detection-engineering portfolio project inspired by the Sigma rule ecosystem.** SigmaForge validates YAML detection rules, evaluates supported conditions against JSONL events, runs regression tests, exports queries for common SIEM backends, and generates a constrained rule pack for the companion SentinelOps monitor.

SigmaForge is an original learning implementation. It does not bundle SigmaHQ rules, source code, logos, or claim affiliation with the Sigma project.

## Why this project

Security teams need detections that are reviewable, testable and portable. SigmaForge turns rule authoring into a small detection-as-code workflow:

```text
YAML rule → schema checks → regression tests → ATT&CK metadata
                         ├──> Splunk SPL
                         ├──> Microsoft Sentinel KQL
                         ├──> Elastic query
                         └──> SentinelOps JSON rule pack
```

## Features

| Capability | Included |
|---|---|
| YAML rule validation | Required fields, UUID, status/level, condition references, duplicate-ID detection and metadata warnings |
| Sigma-like condition language | Named selectors, `and`, `or`, `not`, parentheses, `1 of`, `all of` |
| Field matching | Exact, list alternatives, `contains`, `startswith`, `endswith`, `re`, `all`, `exists` |
| Regression tests | Match rules against labelled JSON event fixtures and report unexpected matches/misses |
| Backend export | Splunk SPL, Microsoft Sentinel KQL and Elastic query for the supported subset |
| ATT&CK coverage | Extract ATT&CK technique tags and generate a local coverage report |
| Interoperability | Export simple rules as a SentinelOps-compatible JSON pack |
| Detection quality | Rule linting, duplicate-ID checks, false-positive metadata checks, stable IDs and test fixtures |
| Field mapping | Optional JSON mappings from normalized fields to SIEM-specific field names |
| CI | Unit tests and rule validation on GitHub Actions |

## Quick start

Requires Python 3.10+ and PyYAML.

```bash
python -m venv .venv
# Windows
.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Validate included rules:

```bash
python -m sigmaforge validate --rules rules
```

Run regression cases:

```bash
python -m sigmaforge test --rules rules --cases tests/cases.json
```

Compile a rule to a SIEM query:

```bash
python -m sigmaforge compile rules/linux/ssh_failed_login.yml --backend splunk
python -m sigmaforge compile rules/windows/account_created.yml --backend sentinel
python -m sigmaforge compile rules/windows/privileged_group_change.yml --backend elastic
# Map normalized fields to your SIEM's field names:
python -m sigmaforge compile rules/windows/account_created.yml --backend sentinel --field-map configs/custom-field-map.example.json
```

Launch the local rule-explorer interface:

```bash
python -m sigmaforge serve
```

Open `http://127.0.0.1:8788` to browse detections, inspect ATT&CK tags, review regression results, and compile a selected rule.

Generate ATT&CK coverage:

```bash
python -m sigmaforge coverage --rules rules --output reports/attack-coverage.md
```

Export the subset supported by SentinelOps:

```bash
python -m sigmaforge export --rules rules --format sentinelops --output exports/sentinelops-rules.json
```

Then from the SentinelOps project:

```bash
python -m sentinelops ingest --file samples/sample_events.jsonl --type json \
  --rules ../sigmaforge-project/exports/sentinelops-rules.json
```

## Rule format

Example:

```yaml
title: Windows Security Audit Log Cleared
id: 3a1c8f1d-b7c2-4b5f-9f2d-9a5d18bc7b45
status: test
description: Detects a Windows Security audit log clear event.
author: Detection Engineering Lab
date: 2026-11-22
logsource:
  product: windows
  service: security
detection:
  selection:
    event_id: "1102"
    action: audit_log_cleared
  condition: selection
falsepositives:
  - Authorized log maintenance
level: critical
tags:
  - attack.defense-evasion
  - attack.t1070.001
```

SigmaForge implements a useful subset of the Sigma condition model rather than claiming full specification support. See `docs/supported-syntax.md` and `docs/limitations.md`.

## Repository layout

```text
sigmaforge-project/
├── sigmaforge/          # YAML parsing, validation, matching, compilation and CLI
├── rules/               # Original example rules written for this project
├── web/                 # Local rule explorer and query compiler UI
├── tests/               # Unit tests and regression fixture cases
├── fixtures/            # Clearly labelled synthetic events
├── docs/                # Syntax, workflow, architecture and limitations
├── reports/             # Generated ATT&CK coverage report
└── exports/             # Generated SentinelOps rule pack
```

## Test data and real telemetry

`fixtures/` contains synthetic JSON event examples, clearly labelled for safe repeatable tests. They are not live endpoint records.

For real data, export JSONL from your own or authorized Windows/Linux/security lab environment. Each line should be a JSON object matching the normalized event fields used by SigmaForge. Use the test runner's `--events` option or add labelled cases to `tests/cases.json`. Do not upload private production logs to a public repository.

## Backend support boundaries

The exporters are intentionally scoped to the condition features listed in `docs/supported-syntax.md`. Complex selections, unsupported modifiers or unsupported condition trees are reported as errors. They are never silently flattened into a weaker query.

- **Splunk:** produces SPL search expressions over mapped field names.
- **Sentinel:** produces KQL `where` expressions over mapped field names.
- **Elastic:** produces a Lucene-style expression for the supported scalar conditions.

These exporters are educational starting points. Always validate generated queries against your SIEM's field mappings, parser semantics and test data before operational use.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Credits and relationship to upstream projects

SigmaForge was independently written after reviewing the high-level generic detection-rule approach and repository organization documented by [SigmaHQ](https://github.com/SigmaHQ/sigma). No SigmaHQ source code, rule files, logos or other upstream assets are included. The Sigma project and its maintainers are independent of this portfolio project.


## Public dashboard deployment (Render)

This service is suitable for a public, read-only portfolio dashboard. It exposes the existing rule library, validation results, regression cases, health status and supported query compilation over HTTP GET endpoints. It does not provide rule editing or event ingestion over the public interface.

### Render configuration

A `render.yaml` Blueprint is included. In Render, create a Blueprint from this repository and review the service settings before deploying. The service uses the Python runtime, installs `requirements.txt`, runs `python -m sigmaforge serve --host 0.0.0.0 --port $PORT --rules rules --cases tests/cases.json`, and checks `/api/health`. The free plan can sleep when idle; the first visitor may experience a cold start.

### Safety and limitations

- Public visitors can read the included rule metadata, test outcomes and generated queries.
- Do not add credentials, private detection content, internal hostnames, real production log records or customer data to the public repository.
- The public dashboard is a rule-engine workbench, not a SIEM and not a live endpoint monitor.
- Query generation supports only the documented subset in `docs/supported-syntax.md`. Verify generated queries against the target SIEM before using them.
- The dashboard is served over HTTPS by Render when deployed.
