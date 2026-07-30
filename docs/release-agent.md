# Release Agent

The Release Agent performs a bounded, read-only release-readiness review over repository evidence
prepared by trusted code. It is available through:

```bash
forgeflow analyze --repo . --output reports-release --agents release
```

It can run concurrently with the other specialists:

```bash
forgeflow analyze \
  --repo . \
  --output reports-agents \
  --agents security,test,architecture,release
```

## Evidence boundary

The reviewer receives at most 32 text files and approximately 60,000 characters. Sensitive files,
generated directories, ForgeFlow reports, binary content, symlinks, and user exclusions are omitted.
Credential-like values are redacted before the model call.

Trusted code prioritizes and annotates release surfaces including:

- CI and release workflows
- Dockerfiles and Compose configuration
- Kubernetes and Helm deployment manifests
- Package manifests and lockfiles
- Version files and release notes
- Literal base-image, package-version, image, and workflow-action references

The annotations describe repository text only. They do not prove that a workflow ran, an artifact was
published, an image exists, a migration is safe, or a deployment can be rolled back.

## Review scope

The Release Agent may identify evidence-grounded concerns involving:

- Package and container reproducibility
- Conflicting version declarations
- Release workflow safeguards and provenance
- Deployment configuration consistency
- Migration and rollback risks visible in repository configuration
- Concrete release paths that could affect security, data integrity, or availability

It must not invent organization policy, production topology, published versions, workflow results,
artifact state, migration safety, or rollback capability. Generic absence claims are excluded unless
the repository explicitly declares the missing requirement.

## Verification and scoring

Release readiness often depends on external artifact registries, deployment environments, and
organization policy. Release Agent findings are therefore published as `human_review_required`,
downgraded to informational severity, and excluded from the engineering score and `--fail-on` gate
until a deterministic verifier or repository-owned release policy confirms them.
