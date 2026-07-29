# Security Agent CLI Review

ForgeFlow can supplement deterministic checks with a bounded Google ADK security review:

```bash
forgeflow analyze --repo . --output reports --agents security
```

The mode is opt-in and requires Gemini authentication through `GOOGLE_API_KEY` or Google Cloud
Application Default Credentials. Deterministic analysis remains the default and requires no model
call.

## Trust boundary

The CLI never sends the repository wholesale. Trusted code selects at most 32 scannable text files,
limits each file excerpt to 4,000 characters, and caps the evidence payload at 60,000 characters.
Sensitive files, symlinks, generated directories, prior ForgeFlow reports, and custom exclusions are
omitted. Credential-like assignments are redacted before the evidence bundle is sent to the model.

Repository text is enclosed in an explicit untrusted-data boundary. Prompt-injection patterns are
counted in `execution-summary.json`, but repository text is not followed as instructions.

## Structured output and validation

The ADK agent returns a `SecurityReviewOutput` schema with no more than 20 candidate findings. Every
candidate must identify an exact repository-relative file, line range, evidence excerpt, confidence,
severity, and recommendation. Candidates then enter the same pipeline as deterministic findings:

1. confidence filtering;
2. path and line-range validation;
3. evidence matching against the local file;
4. mandatory secret redaction;
5. deduplication and engineering scoring.

Unsupported candidates are rejected from `findings.json`. If the provider call or structured parsing
fails, deterministic findings are still written and the run is marked `completed_with_warnings`.
