# Threat Model

## Assets

- Source code and architecture information
- Credentials and deployment secrets
- Engineering decisions in semantic memory
- Model prompts and tool results
- Build and release integrity
- Telemetry containing operational metadata

## Primary threats

### Prompt injection in repository content

A malicious README, issue, comment, or source file can instruct the model to ignore policy or call dangerous tools.

Controls: repository content is treated as untrusted evidence; tools are read-only; agent instructions prohibit following embedded commands; adversarial evaluation covers this behavior.

### Path traversal and secret discovery

An attacker may request files outside the configured repository or target `.env`, key stores, and credentials.

Controls: canonical path resolution, root containment checks, sensitive-name and suffix blocks, read-only mount, bounded output.

### Arbitrary code execution

Source code, build scripts, or model-generated commands may be malicious.

Controls: no shell tool; Java analysis is heuristic and never compiles or runs submitted code; future execution must use an isolated ephemeral sandbox with network denial and resource quotas.

### SSRF and confused-deputy behavior

Tools that accept arbitrary URLs can access internal services or cloud metadata.

Controls: v0.1 exposes no generic URL-fetch tool. Future HTTP tools require hostname allowlists, DNS rebinding protection, private-range denial, and redirect validation.

### Memory poisoning

Incorrect or malicious content can become durable and influence future decisions.

Controls: only the release specialist can write memory; content is bounded and should be a summarized decision; future versions add provenance, confidence, review state, expiration, and tenant identity.

### Trace leakage

Prompts or tool results may contain confidential data and be exported to telemetry backends.

Controls: avoid raw prompt logging by default; configure processor-based redaction and access control in production; use sampling appropriate to data sensitivity.

## Residual risks before production

- MCP OAuth and per-user authorization are not implemented in the starter.
- Database row-level tenant isolation is not implemented.
- Container images are not signed or pinned by digest.
- Kubernetes ingress, certificates, workload identity, and managed secret integration are deployment-specific.
- Model-output policy enforcement is primarily instruction- and tool-boundary based; high-risk writes require a formal approval service.
