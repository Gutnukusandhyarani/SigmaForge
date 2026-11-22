# Architecture

```text
Rule YAML ──> PyYAML parser ──> Validator ──> Condition AST
                                      │             │
                                      │             ├──> Local matcher ──> Regression results
                                      │             ├──> Query compiler ──> SPL / KQL / Elastic
                                      │             ├──> ATT&CK tag analyzer ──> Coverage report
                                      │             └──> SentinelOps exporter ──> JSON rule pack
                                      ▼
                               Rule quality feedback
```

The matcher and compilers use one parsed condition tree. The compiler intentionally rejects constructs it cannot represent faithfully.
