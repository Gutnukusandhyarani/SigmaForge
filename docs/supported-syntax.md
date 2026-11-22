# Supported syntax and semantics

SigmaForge implements a deliberately bounded subset so that matching and query exports are explainable.

## Rule structure

Required fields: `title`, UUID `id`, `status`, `description`, `logsource`, `detection`, and `level`.

Statuses: `stable`, `test`, `experimental`, `deprecated`.

Levels: `informational`, `low`, `medium`, `high`, `critical`.

Recommended metadata: `author`, `date`, `falsepositives`, and `tags`.

## Condition grammar

Supported operators, in precedence order:

1. `not`
2. `and`
3. `or`
4. Parentheses for grouping

Supported selector terms:

- `selection`
- `selection and not filter`
- `(selection_a or selection_b) and filter`
- `1 of selection_*`
- `all of selection_*`

For wildcard `of` expressions, wildcard matching is against selector names. `them` is accepted as a selector pattern and matches all named selectors.

## Field matching

- Mapping keys are ANDed together.
- A list of values for a field means OR.
- A list of selector mappings means OR.
- No modifier means case-insensitive exact string comparison.
- `|contains`, `|startswith`, `|endswith`, `|re`, `|all`, and `|exists` modifiers are supported by the local matcher.
- Keyword-style scalar selectors search the event's `message` field.

The query exporters support a narrower subset:
- Exact values and list alternatives.
- `contains`, `startswith`, `endswith`, and `exists` where stated by each backend.
- Boolean selector combinations, `not`, and `1 of`.
- Regular expressions and `all` value modifiers are not exported in this build.
- Keyword-style selectors are not exported.
- `all of` and numeric thresholds other than `1 of` are intentionally not flattened by the compiler.

## Data mapping

Rules are evaluated against normalized JSON events. The default field map is in `sigmaforge/compiler.py`. Use field names present in your actual telemetry and configure a backend field map before relying on generated queries.
