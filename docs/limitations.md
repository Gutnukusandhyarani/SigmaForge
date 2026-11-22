# Limitations and next engineering steps

- This is a Sigma-like educational subset, not a full implementation of the Sigma specification or pySigma.
- YAML validation is structural and semantic only for this project's supported subset.
- The condition parser supports named selectors and basic Boolean logic but not every Sigma feature (for example, field aggregation, correlation rules, pipelines, or advanced quantifiers).
- The local matcher operates on normalized JSON events; it does not parse EVTX, PCAP, XML or vendor-specific log formats directly.
- The SentinelOps exporter requires a single mapping selector referenced directly by the condition and supports only exact/list/contains/exists tests.
- Query exporters need environment-specific field mappings and platform validation.
- ATT&CK coverage counts tags in YAML; it does not assert that the corresponding technique is detected effectively.
- Regression fixtures are synthetic unless the user supplies real, authorized telemetry.
- There is no UI, multi-user review workflow, remote rule registry or threat-intelligence feed in this first version.

Potential next milestones: correlation-rule model, schema validation against SigmaHQ's evolving spec, pluggable backend adapters, test result diffs, reviewer approvals, rule aging and false-positive metrics, and a UI for rule search/review.
