# Contributing

Contributions are welcome through focused pull requests.

1. Open an issue describing the problem and expected behavior.
2. Add or update tests before changing behavior.
3. Keep tools narrow, typed, bounded, and documented.
4. Never add arbitrary shell execution to the default deployment.
5. Run `pytest`, `ruff check .`, `mypy forgeflow forgeflow_mcp`, and `mvn test`.
6. Document new trust boundaries and telemetry fields.

Security vulnerabilities must be reported privately according to `SECURITY.md`.
