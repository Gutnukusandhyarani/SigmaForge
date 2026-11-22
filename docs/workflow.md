# Detection-as-code workflow

## 1. Author

Create a `.yml` rule in `rules/`. Keep the rule narrow, describe its intent and document expected benign causes in `falsepositives`.

## 2. Validate

```bash
python -m sigmaforge validate --rules rules
```

Errors block the workflow. Warnings identify missing author, false-positive or ATT&CK metadata.

## 3. Add regression cases

Add a case to `tests/cases.json` with the normalized `event` and exact expected rule IDs in `expect`. Include both positive and negative cases.

## 4. Test

```bash
python -m sigmaforge test --rules rules --cases tests/cases.json
```

A failed case can mean a rule is too broad, too narrow, incorrectly tagged or that the fixture does not match the stated event semantics. Investigate rather than weakening a test blindly.

## 5. Compile and review

```bash
python -m sigmaforge compile rules/windows/audit_log_cleared.yml --backend sentinel
```

Check backend field names, table/source selection and query syntax in your SIEM. Query compilers are not a substitute for a platform-specific validation run.

## 6. Publish or integrate

Generate ATT&CK coverage and export the supported subset to SentinelOps. Keep generated JSON artifacts and review changes in version control.
