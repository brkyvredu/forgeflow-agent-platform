# ForgeFlow Agent Platform

Production-grade, open-source multi-agent engineering assistant built with Google Agent Development Kit (ADK), Model Context Protocol (MCP), PostgreSQL/pgvector, Java, OpenTelemetry, Docker, Kubernetes, and GitHub Actions.

ForgeFlow is designed as a portfolio-quality reference implementation for enterprise agent engineering. It deliberately separates reasoning, tool execution, storage, observability, evaluation, and deployment concerns.

## What it does

The coordinator delegates engineering work to four specialized agents:

- **Architecture Agent** — analyzes repository structure, dependencies, boundaries, and design trade-offs.
- **Test Agent** — produces test plans, identifies missing coverage, and proposes verification commands.
- **Security Agent** — reviews tool usage, dependency risk, secrets exposure, prompt injection, and unsafe changes.
- **Release Agent** — prepares release readiness checks, migration notes, rollout plans, and rollback criteria.

Tools are exposed through two integration paths:

1. A stateless Streamable HTTP **MCP server** for safe repository inspection.
2. A **Java 21 / Spring Boot 4.1** service for source-code metrics and Java-specific analysis.

Long-term engineering memory is stored in PostgreSQL with pgvector. Traces, metrics, and logs are exported through OpenTelemetry using OTLP.

## Architecture

```text
User / API Client
       |
       v
Google ADK Coordinator
       |
       +--> Architecture Agent ----+
       +--> Test Agent ------------+----> MCP Repository Server
       +--> Security Agent --------+          (read-only, allowlisted)
       +--> Release Agent ---------+
       |
       +-------------------------------> Java Analysis Service
       |
       +-------------------------------> PostgreSQL + pgvector
       |
       +-------------------------------> OpenTelemetry Collector
```

See [`docs/architecture.md`](docs/architecture.md) and [`docs/threat-model.md`](docs/threat-model.md).

## Technology choices

- Python 3.12
- Google ADK 2.x
- MCP Python SDK 2.x
- Gemini model configured by environment variable
- Java 21 and Spring Boot 4.1
- PostgreSQL 17 with pgvector
- OpenTelemetry Collector and OTLP
- Docker Compose for local development
- Kubernetes manifests for deployment
- GitHub Actions for CI

## Quick start

### Prerequisites

- Docker with Compose
- A Gemini API key, or Google Cloud application credentials

### 1. Configure

```bash
cp .env.example .env
# Set GOOGLE_API_KEY in .env, or configure Google Cloud credentials.
```

### 2. Start the stack

```bash
docker compose up --build
```

Services:

- ADK API server: `http://localhost:8000`
- ADK Swagger UI: `http://localhost:8000/docs`
- MCP endpoint: `http://localhost:8001/mcp`
- Java analysis service: `http://localhost:8080`
- Jaeger UI: `http://localhost:16686`
- PostgreSQL: `localhost:5432`

### 3. Create an ADK session

```bash
curl -X POST http://localhost:8000/apps/forgeflow/users/demo/sessions/session-1 \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 4. Run the agent

```bash
curl -X POST http://localhost:8000/run \
  -H 'Content-Type: application/json' \
  -d '{
    "appName": "forgeflow",
    "userId": "demo",
    "sessionId": "session-1",
    "newMessage": {
      "role": "user",
      "parts": [{"text": "Review this repository architecture and identify the three highest engineering risks."}]
    }
  }'
```

## Local development without Docker

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env

python -m forgeflow_mcp.server
# another terminal
adk api_server --host 0.0.0.0 --port 8000 .
```

Run a deterministic, read-only repository analysis:

```bash
forgeflow analyze --repo . --output reports
forgeflow analyze --repo . --fail-on high --min-confidence 0.80
forgeflow analyze --repo . --exclude "examples/**"
forgeflow analyze --repo . --agents security
forgeflow analyze --repo . --agents test
forgeflow analyze --repo . --agents security,test
forgeflow analyze --repo . --agents architecture
forgeflow analyze --repo . --agents security,test,architecture
forgeflow analyze --repo . --agents release
forgeflow analyze --repo . --agents security,test,architecture,release
forgeflow analyze --repo . --agents security,test --agent-attempts 3 --agent-backoff 1.0
forgeflow analyze --repo . --agents security,test,architecture,release --agent-concurrency 1
forgeflow analyze --repo . --agents security,test --min-agent-coverage 1.0
```

The command writes `review.md`, `findings.json`, and `execution-summary.json`. It performs bounded
repository discovery and evidence-backed checks for credential-like literals, unsafe shell
execution, mutable Docker base tags, root container execution, missing tests, and missing CI.
Sensitive files, generated directories, oversized text files, symlinks, and configured glob
exclusions are skipped. Findings are evidence-validated, deduplicated, and assigned a bounded
engineering prioritization score. The optional specialist modes run isolated Google ADK reviewers over bounded, line-numbered,
credential-redacted evidence bundles. The Test Agent receives role-labeled production and test files
with likely relationships annotated by trusted code. The Architecture Agent receives a trusted
module, entry-point, and import summary alongside bounded repository excerpts. The Release Agent
receives trusted release-surface and literal version, image, and workflow-reference annotations.
Agent findings pass
through confidence filtering, literal evidence validation, semantic verification, deduplication,
and reporting. Only semantically verified or deterministically confirmed findings affect the
engineering score and `--fail-on`; ambiguous agent candidates remain visible for human review
without failing CI. Specialist reviews run with bounded concurrency. Transient provider failures are retried with bounded
exponential backoff; a final provider failure produces a degraded analysis with a provisional score
without discarding deterministic or other successful results. Specialist calls use bounded
concurrency to reduce provider bursts. `--min-agent-coverage` can turn degraded specialist coverage
into an independent CI failure, even when no scoring-eligible finding crosses `--fail-on`.
Generated ForgeFlow report directories are automatically excluded from later scans. See
[`docs/security-agent.md`](docs/security-agent.md), [`docs/test-agent.md`](docs/test-agent.md),
[`docs/architecture-agent.md`](docs/architecture-agent.md),
[`docs/release-agent.md`](docs/release-agent.md),
[`docs/finding-quality.md`](docs/finding-quality.md), [`docs/rules.md`](docs/rules.md), and
[`docs/quality-gates.md`](docs/quality-gates.md), and
[`docs/evaluation-hardening.md`](docs/evaluation-hardening.md).

Run tests:

```bash
pytest
ruff check .
mypy forgeflow forgeflow_mcp
```

Run Java tests:

```bash
cd services/java-analysis
mvn test
```

## Evaluation

ForgeFlow uses two complementary evaluation layers:

- Deterministic unit and adversarial policy tests, requiring no model call.
- ADK/Agents CLI evaluation datasets for tool-use quality, trajectory quality, task success, grounding, hallucination, and safety.

```bash
agents-cli eval generate --dataset tests/eval/datasets/basic-dataset.json
agents-cli eval grade --metrics multi_turn_tool_use_quality,multi_turn_task_success,grounding,safety
```

See [`docs/evaluation.md`](docs/evaluation.md) and the recorded local checks in [`docs/validation.md`](docs/validation.md).

## Security principles

- No arbitrary shell tool.
- Repository access is restricted to `REPOSITORY_ROOT`.
- Paths are resolved and checked before every file operation.
- Binary files, secrets, oversized files, and known-sensitive paths are blocked.
- Tool results are bounded to reduce context flooding.
- Mutating operations are excluded from the initial release.
- Every external call is traceable through OpenTelemetry.
- Production deployments should add workload identity, OAuth for MCP, network policies, image signing, and secret-manager integration.

## Project status

This repository is a complete **v0.1 foundation**: architecture, working service implementations, tests, containers, Kubernetes resources, CI, evaluation fixtures, documentation, and security controls are present. The remaining roadmap focuses on deeper semantic code understanding, authenticated GitHub integration, human approval workflows, and richer benchmark datasets.

## License

Apache License 2.0.
