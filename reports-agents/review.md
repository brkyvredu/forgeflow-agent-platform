# ForgeFlow Repository Review

## Analysis status

This report contains bounded, read-only deterministic checks and any requested specialist-agent
review. No repository code was executed or modified. Repository content was treated as untrusted
data. Only evidence-supported findings at or above the configured confidence threshold are
published.

## Engineering score

- Score: **83/100**
- Risk level: **Moderate**
- Note: This engineering score is a prioritization aid, not a security certification.

## Repository

- Root: `E:\Projects\forgeflow-agent-platform`
- Files scanned: 94
- Aggregate bytes: 268836
- Sensitive files skipped: 1
- Symlinks skipped: 0
- Custom exclusions skipped: 0

## Languages

- Python: 38 file(s)
- Java: 4 file(s)

## Dependency manifests

- `pyproject.toml`
- `services/java-analysis/pom.xml`

## Engineering surfaces

- Test directories: 2
- CI files: 2
- Container files: 4
- Kubernetes files: 7

## Agent execution

- Security: completed; findings=2; context_files=32; duration_ms=27809
- Test: completed; findings=2; context_files=24; duration_ms=29813

## Finding quality

- Raw findings: 4
- Supported findings: 4
- Unsupported findings rejected: 0
- Findings below confidence threshold: 0
- Duplicate findings merged: 0

## Finding summary

- High: 1
- Medium: 3

## Findings

### [HIGH] Shell command execution with environment variable in Kubernetes initContainer

- Rule: `FF-AGENT-SEC-DC1C36D371`
- Location: `infra/k8s/services.yaml`:23
- Confidence: 0.80
- Evidence status: `supported`
- Sources: `security-agent`

The repository-clone initContainer executes a shell command using `sh -c` with string-interpolated `$REPOSITORY_URL`. If the repository URL configuration is manipulated or contains shell metacharacters, it could lead to arbitrary command execution within the container.

**Recommendation:** Avoid invoking shell scripts with unquoted configuration variables or pass the URL directly as an argument without shell evaluation.

**Evidence:** `args: ['git clone --depth=1 "$REPOSITORY_URL" /workspace/repository']`

### [MEDIUM] Hardcoded default database credentials in Docker Compose configuration

- Rule: `FF-AGENT-SEC-A4952F03F3`
- Location: `docker-compose.yml`:7
- Confidence: 0.85
- Evidence status: `supported`
- Sources: `security-agent`

The Docker Compose configuration provides hardcoded fallback credentials ('forgeflow') for PostgreSQL authentication in POSTGRES_PASSWORD and DATABASE_URL. If services are deployed using docker compose without explicitly setting environment variables, the database will operate with default credentials.

**Recommendation:** Remove default credential fallbacks from docker-compose.yml and enforce setting strong credentials through environment files or a secret manager.

**Evidence:** `POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-forgeflow}`

### [MEDIUM] Untested CLI agent selection validation and error handling

- Rule: `FF-AGENT-TEST-F23C257F83`
- Location: `forgeflow/cli.py`:87
- Confidence: 0.90
- Evidence status: `supported`
- Sources: `test-agent`

The `_normalize_agents` helper in `forgeflow/cli.py` validates requested specialist agent strings or tuples, raising a `ValueError` when `none` is combined with active agents or when unknown agent names are supplied. Although `_normalize_agents` is imported into `tests/unit/test_cli.py`, no test cases verify these validation paths or assert that `ValueError` is raised on invalid agent inputs.

**Recommendation:** Add unit tests in `tests/unit/test_cli.py` that invoke `_normalize_agents` with invalid combinations (such as `none,security`), unknown agent names, and tuple parameters to ensure validation errors are raised as expected.

**Evidence:** `if "none" in requested:
        raise ValueError("--agents none cannot be combined with specialist agents")`

### [MEDIUM] Untested path traversal and line boundary checks in finding validation

- Rule: `FF-AGENT-TEST-38E57A44E2`
- Location: `forgeflow/reporting/quality.py`:30
- Confidence: 0.90
- Evidence status: `supported`
- Sources: `test-agent`

In `forgeflow/reporting/quality.py`, `validate_findings` invokes `_safe_finding_path` to ensure candidate finding paths do not escape the repository root via absolute paths or `..` path traversal sequences. It also checks whether line ranges exceed file lengths. Existing tests in `tests/unit/test_quality.py` verify valid evidence and secret redactions, but do not test findings with path traversal attempts or out-of-bounds line numbers.

**Recommendation:** Extend `tests/unit/test_quality.py` to include candidate findings with path escape attempts (e.g. `../outside.py` or `/etc/passwd`) and line ranges beyond file length to verify they are flagged as `ValidationStatus.UNSUPPORTED` with appropriate validation messages.

**Evidence:** `if relative_path.is_absolute() or ".." in relative_path.parts:`

