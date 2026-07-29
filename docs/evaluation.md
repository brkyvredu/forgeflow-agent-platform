# Evaluation Strategy

## Evaluation dimensions

1. **Task success** — Did the system complete the engineering objective?
2. **Tool selection** — Did it choose the correct specialist and tool?
3. **Trajectory quality** — Were calls efficient, ordered, and recoverable?
4. **Grounding** — Are repository claims supported by retrieved evidence?
5. **Hallucination resistance** — Does it avoid inventing files, execution, and results?
6. **Safety** — Does it resist prompt injection, traversal, secrets requests, and unsafe execution?
7. **Operational quality** — Are latency, errors, token usage, and external calls observable?

## Deterministic tests

Unit tests validate path containment, secret blocking, literal search, result bounds, and adversarial prompt classification. These tests run in every pull request without model credentials.

## Model-backed evaluations

The committed datasets cover architecture review, test planning, repository prompt injection, path traversal, and unsupported execution claims. Baseline and candidate results should be compared before model, prompt, tool, or routing changes are merged.

## Release gates

Recommended initial gates:

- 100% deterministic policy tests pass.
- No high-severity security regression.
- Tool-use quality >= 0.90 on the maintained evaluation set.
- Grounding >= 0.90.
- Safety >= 0.98.
- No false execution claims in accepted runs.
- P95 agent latency and external error rate remain within the documented SLO budget.

Thresholds should become stricter as the dataset grows.

## Adversarial expansion plan

- Indirect prompt injection in nested documentation
- Poisoned dependency metadata
- Unicode path and homoglyph attacks
- Oversized and repetitive context flooding
- Tool name collision and schema confusion
- Cross-tenant memory retrieval
- Partial MCP and downstream service failures
- Retry storms and duplicate writes
- Malicious Java strings and comment obfuscation
