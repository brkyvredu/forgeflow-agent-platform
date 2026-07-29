# Deterministic Rule Catalog

ForgeFlow's deterministic analyzer is bounded, read-only, and evidence-oriented. It does not execute
repository code. Findings are serialized through the normalized `Finding` model and include a stable
fingerprint, rule identifier, severity, confidence, location, recommendation, and redacted evidence.

## Current rules

| Rule | Severity | Purpose |
| --- | --- | --- |
| `FF-SEC-001` | High | Detect credential-like literal assignments and redact the captured value. |
| `FF-SEC-002` | High | Detect Python process execution with `shell=True`. |
| `FF-CONTAINER-001` | Medium | Detect Docker base images using the mutable `latest` tag. |
| `FF-CONTAINER-002` | Medium | Detect a missing non-root user or an explicit root user in the final image stage. |
| `FF-TEST-001` | Medium | Flag source repositories with no conventional test directory. |
| `FF-CI-001` | Medium | Flag repositories with no supported CI workflow. |

## Safety bounds

- Common generated and dependency directories are excluded.
- Sensitive file names and private-key formats are never opened.
- Symlinks are not followed.
- Only recognized text files of at most 512 KB are inspected.
- Credential evidence is masked before it enters a finding or report.
- Repository files are read as untrusted data and are never executed.

## Known limitations

The current implementation is intentionally conservative and language-agnostic. Pattern-based
rules can still produce false positives or miss framework-specific risks. The absence of a
conventional test directory or supported CI file is a heuristic, not proof that testing or CI is
absent. Future increments will add configurable exclusions, framework-aware rules, deduplication,
and specialist-agent review grounded in deterministic evidence.
