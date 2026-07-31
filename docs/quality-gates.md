# Finding quality and CI gates

ForgeFlow first performs bounded literal evidence validation. A file-scoped finding must reference
a repository-relative file, a valid line range, and evidence supported by that range.
Secret-management evidence must contain the `***REDACTED***` marker. Unsupported candidates are
counted in `execution-summary.json` but are not written to `findings.json` or the review body.

Evidence matching alone does not make an agent claim score-eligible. Specialist findings then pass
through a bounded semantic verifier. The resulting verification levels are documented in
[`finding-quality.md`](finding-quality.md).

## Deduplication

The stable finding fingerprint combines the rule identifier, normalized file, starting line, and
normalized title. Candidates with the same fingerprint are merged, their contributing agents are
retained in `sources`, the strongest verification state is retained, and the highest confidence is
used.

## Engineering score

The score starts at 100 and applies deductions only to findings with `scoring_eligible: true`:

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
forgeflow analyze --repo . --agents security,test --min-agent-coverage 1.0
forgeflow analyze --repo . --exclude "examples/**" --exclude "vendor/**"
```

`--fail-on` still writes all reports. It returns exit code `1` only when a scoring-eligible finding
meets or exceeds the selected severity, `0` when the gate passes, and `2` for invalid input or
analysis failure. Human-review candidates remain visible but cannot fail CI. Exclusions are
repository-relative glob patterns and may be repeated. When the output directory is inside the
analyzed repository, ForgeFlow automatically excludes it to prevent report feedback from becoming
a new finding.

## Specialist coverage gate

`--min-agent-coverage` is independent of finding severity. It compares completed specialist
reviews with the number requested through `--agents`. A value of `1.0` requires every requested
specialist to complete; `0.5` permits half to complete. A failed coverage gate still writes the
reports and returns exit code `1`. Supplying a positive coverage requirement without requesting a
specialist is treated as invalid input and returns exit code `2`.

`--agent-concurrency` bounds simultaneous provider calls from 1 to 4 and defaults to 2. Lowering it
to 1 is useful for quota-constrained environments; it does not change the requested coverage
calculation.
