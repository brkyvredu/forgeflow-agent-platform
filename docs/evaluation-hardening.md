# Evaluation Hardening

ForgeFlow treats specialist-agent output as an untrusted candidate stream. The deterministic
scanner remains available when one or more model-backed reviewers fail.

## Provider resilience

Specialist reviewers retry only transient provider failures: HTTP 429, 500, 502, 503, and 504,
plus equivalent rate-limit or temporary-unavailability messages. Retries use exponential backoff
with jitter. The CLI defaults to three attempts and a one-second initial backoff:

```text
forgeflow analyze --repo . --output reports --agents security,test \
  --agent-attempts 3 --agent-backoff 1.0
```

Non-transient validation and structured-output errors are not retried. Each agent run records the
attempt count, retryability, final error type, and provider status code. Provider stack traces are
suppressed during bounded review; the execution summary retains a concise failure record.

## Degraded analysis

When a requested specialist fails, deterministic results and successful specialist results are
preserved. The execution status becomes `degraded`, the engineering score is marked provisional,
and the report includes completed/requested specialist coverage. A provisional score is not a
claim that failed specialist surfaces are clean.

## Report isolation

The active output directory is excluded before discovery. Completed ForgeFlow report directories
are also recognized by the presence of `review.md`, `findings.json`, and
`execution-summary.json`, regardless of directory name. This prevents generated findings from
becoming input to later analyses.

## Candidate verification

Before publication, ForgeFlow:

1. validates exact file, line, and evidence support;
2. rejects observed claim/source contradictions, including vacuous credential-redaction claims;
3. requires repository source evidence for claims about external HTTP route behavior;
4. merges cross-agent candidates that point to the same file, related line range, and shared root
   cause;
5. keeps architecture and release candidates advisory unless a deterministic verifier confirms
   them.

Unsupported candidates are counted in quality metrics but are omitted from published findings and
never affect the engineering score or quality gate.
