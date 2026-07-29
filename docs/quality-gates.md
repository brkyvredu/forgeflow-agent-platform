# Finding quality and CI gates

ForgeFlow publishes only findings that pass bounded evidence validation. A file-scoped finding must
reference a repository-relative file, a valid line range, and evidence supported by that range.
Secret-management evidence must contain the `***REDACTED***` marker. Unsupported candidates are
counted in `execution-summary.json` but are not written to `findings.json` or the review body.

## Deduplication

The stable finding fingerprint combines the rule identifier, normalized file, starting line, and
normalized title. Candidates with the same fingerprint are merged, their contributing agents are
retained in `sources`, and the highest confidence is used.

## Engineering score

The score starts at 100 and applies these prioritization deductions:

| Severity | Deduction |
|---|---:|
| Critical | 20 |
| High | 8 |
| Medium | 3 |
| Low | 1 |
| Info | 0 |

The score is bounded at zero. It is an engineering prioritization aid and is not a security
certification, compliance result, or substitute for expert review.

## CLI gates

```bash
forgeflow analyze --repo . --fail-on high
forgeflow analyze --repo . --min-confidence 0.80
forgeflow analyze --repo . --exclude "examples/**" --exclude "vendor/**"
```

`--fail-on` still writes all reports. It returns exit code `1` when a supported finding meets or
exceeds the selected severity, `0` when the gate passes, and `2` for invalid input or analysis
failure. Exclusions are repository-relative glob patterns and may be repeated. When the output directory is inside the analyzed repository, ForgeFlow automatically excludes it to prevent report feedback from becoming a new finding.
