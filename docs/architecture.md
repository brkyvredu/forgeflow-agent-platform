# Architecture

## Goals

ForgeFlow is structured to demonstrate senior-level agent platform engineering rather than a single prompt-driven chatbot. The primary goals are modularity, least privilege, testability, observable behavior, and replaceable integrations.

## Components

### ADK application

The coordinator owns user interaction and delegates to specialized agents. Specialists have narrow instructions and narrower tool access. This reduces prompt complexity and makes evaluation results attributable to a defined responsibility.

### MCP repository server

The MCP server exposes read-only repository inspection tools. It is stateless over Streamable HTTP and can therefore scale horizontally. It rejects path traversal, sensitive files, binary files, oversized content, ignored build directories, and unbounded results.

The initial release intentionally excludes shell execution and file mutation. Those capabilities require a separate sandbox, explicit policy evaluation, and human approval.

### Java analysis service

Java-specific analysis is isolated in a Spring Boot service. The initial analyzer computes structural heuristics without compiling or executing untrusted source. This boundary demonstrates cross-language tool integration while preserving a narrow attack surface.

### Semantic memory

PostgreSQL stores decisions and findings with JSONB metadata and pgvector embeddings. The agent writes only concise non-secret engineering knowledge. Production deployments should implement tenant isolation, retention, deletion, and authorization checks.

### Observability

Python HTTP calls and application spans are exported through OTLP. Spring Boot exports Micrometer/OpenTelemetry traces. The collector centralizes routing so backends can change without application changes.

## Trust boundaries

1. User input is untrusted.
2. Repository content is untrusted and may contain prompt injection.
3. MCP tool output is untrusted data.
4. External model providers and APIs are remote dependencies.
5. The database contains durable application data and requires tenant-aware access controls.
6. Deployment configuration and secrets must remain outside repository-readable paths.

## Scaling model

- ADK API server: stateless application replicas with external session/memory storage.
- MCP server: stateless replicas behind a service.
- Java service: stateless replicas.
- PostgreSQL: managed HA service in production.
- OpenTelemetry Collector: agent/gateway topology depending on scale.

## Key architecture decisions

- Read-only tools in v0.1.
- Explicit specialist delegation rather than a single general-purpose agent.
- Tool access scoped per specialist.
- Environment-configurable models and endpoints.
- OTLP instead of direct vendor SDKs.
- Database-backed semantic memory instead of hidden local state.
