# Test Agent trust boundary

ForgeFlow's optional Test Agent performs a bounded, read-only review of production and test
artifacts. It does not execute repository code, run tests, calculate coverage, or mutate files.

## Evidence construction

Trusted code prepares the evidence bundle before the model call:

- sensitive, generated, binary, oversized, symlinked, and excluded files are omitted;
- credential-like assignments are redacted;
- production and test files are labeled with explicit roles;
- likely production-to-test relationships are annotated from normalized file names;
- deterministic findings already known to ForgeFlow are summarized;
- the bundle is capped by file, per-file character, and total-character limits;
- prompt-injection indicators are counted and repository instructions remain untrusted data.

Production files and their likely tests are placed next to one another when possible. These
relationships are hints, not proof of coverage.

## Output constraints

The agent returns the same normalized `Finding` structure as deterministic checks and the Security
Agent. Every candidate requires an existing file, valid line range, exact evidence excerpt,
recommendation, confidence value, and bounded severity. Candidates pass through the shared
confidence filter, evidence validation, deduplication, scoring, and reporting pipeline.

The prompt forbids claims that tests were executed or that a coverage percentage was measured. It
also discourages generic "missing tests" findings already covered by deterministic analysis and
reserves high severity for a concrete security, data-loss, or release-critical verification gap.

## Failure isolation

Security and Test Agent reviews run as isolated concurrent jobs. A provider or parsing failure in
one specialist is recorded in `execution-summary.json` and does not discard deterministic findings
or successful results from another specialist.

## CLI examples

```bash
forgeflow analyze --repo . --agents test
forgeflow analyze --repo . --agents security,test --min-confidence 0.80
```
