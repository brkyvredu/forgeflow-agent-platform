# Architecture Agent

The Architecture Agent performs a bounded, read-only design review over repository evidence prepared
by trusted code. It is available through:

```bash
forgeflow analyze --repo . --output reports-architecture --agents architecture
```

It can run concurrently with the other specialists:

```bash
forgeflow analyze \
  --repo . \
  --output reports-agents \
  --agents security,test,architecture
```

## Evidence boundary

The reviewer receives at most 32 text files and approximately 60,000 characters. Sensitive files,
generated directories, ForgeFlow reports, binary content, symlinks, and user exclusions are omitted.
Credential-like values are redacted before the model call.

Trusted code adds the following annotations:

- Repository-level module, role, and entry-point summaries
- File roles such as production, test, configuration, and documentation
- A module label for each selected file
- Parsed Python, Java, JavaScript, and TypeScript import summaries
- Exact line numbers for the bounded source excerpts

Repository text remains untrusted and cannot override the reviewer instructions.

## Review scope

The Architecture Agent may identify evidence-grounded concerns involving:

- Dependency direction and module boundaries
- Responsibility placement and excessive coupling
- Entry-point and configuration coupling
- Deployment topology inconsistencies
- Architectural decisions that create a concrete maintenance or reliability risk

It must not invent dependency edges, runtime call paths, business requirements, team ownership, or
dependency cycles. Generic style preferences and framework ideology are excluded.

## Verification and scoring

Architecture advice is inherently policy-dependent. Until a repository declares explicit
architecture rules, Architecture Agent findings are published as `human_review_required`, downgraded
to informational severity, and excluded from the engineering score and `--fail-on` quality gate.

A future increment will support repository-owned architecture policies for deterministic boundary
verification and score eligibility.
