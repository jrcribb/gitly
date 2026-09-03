# GitLab capability parity

Gitly is a lightweight forge, while GitLab is a much larger DevSecOps platform. This document keeps the comparison explicit so feature work is prioritized by dependencies instead of implying parity that the code does not yet provide.

## Implemented foundation

- Personal and organization namespaces, public/private repositories, transfer acceptance, and HTTP(S)/OpenSSH Git transport
- User SSH keys with usage/expiry metadata, repository-scoped read-only/read-write deploy keys, explicit protected-branch grants, and forced-command authorization
- Fork networks, personal/organization fork targets, default-branch-only forks, safe upstream synchronization, and cross-fork merge requests
- Scheduled/manual pull and push repository mirrors over HTTPS or SSH, encrypted credentials, pinned SSH host keys, protected-branch filtering, and explicit divergence controls
- Project roles: Reporter (read/clone), Developer (push to permitted branches), and Maintainer (project settings)
- Branch listing, creation, and safe deletion through the UI/API; protected branches with exact or wildcard rules, role-based push and merge access, deletion protection, and force-push rejection
- Merge requests with discussions, line reviews, approvals, approval invalidation after new commits, merge and squash merge
- Editable issues with assignees and project-label CRUD/assignment through the UI/API, plus milestones, project boards, discussions, releases, activity feeds, stars, watches, and webhooks
- Scoped/expiring personal access tokens, sessions, TOTP, security logs, immutable GitHub OAuth identities, SQLite/PostgreSQL, and optional external CI status integration
- Repository-scoped deploy tokens; trusted SSH commit verification and signed-commit push policy; protected tags and releases; snippets; Git LFS; protocol-v2 partial clone; and leased manual/weekly housekeeping
- Nested groups with inherited planning access; nested epics and roadmap views; iterations; issue tasks, time estimates/entries, and relationships; mutually exclusive scoped labels; token-authenticated service desk ingestion; and advanced filtered boards with issue cards and WIP limits
- Generic/npm/Maven/PyPI/NuGet/Composer/Helm package records with immutable coordinates and provenance attestations; an OCI v2 registry with resumable uploads and protected manifests; allowlisted dependency proxying; content-addressed local or HTTP object storage; and scheduled package/container retention
- SAST/DAST/dependency/container/secret/license report ingestion, deduplicated vulnerability state, branch security gates, role-aware merge approval policies, compliance-framework assignment, and append-only project/instance audit export
- Kubernetes agent registration and heartbeat, deterministic environment/target/percentage feature flags, incident discussions, deduplicated alert ingestion, metrics/traces/error retention, and rotating on-call schedules
- Leased retrying background queues, multi-instance heartbeats and health probes, verified SQLite/PostgreSQL backups, namespace quotas, persisted abuse limits, encrypted directory-provider configuration, SCIM provisioning with immutable external identities, and access-checked group/project import-export

The governance and repository model follows GitLab's documented [project roles](https://docs.gitlab.com/user/permissions/), [project members](https://docs.gitlab.com/user/project/members/), [protected branches](https://docs.gitlab.com/user/project/repository/branches/protected/), [merge request approvals](https://docs.gitlab.com/user/project/merge_requests/approvals/), [SSH keys](https://docs.gitlab.com/user/ssh/), [deploy keys](https://docs.gitlab.com/user/project/deploy_keys/), [fork workflows](https://docs.gitlab.com/user/project/repository/forking_workflow/), and [repository mirrors](https://docs.gitlab.com/user/project/repository/mirror/).

## Remaining production-depth areas

The Gitly-side foundations below are implemented, but Gitly intentionally does not claim every protocol extension or managed service shipped by GitLab. The remaining work is production depth rather than missing data models or permission boundaries:

1. Native CI/CD remains in the separate CI repository by design. Isolated runners, pipelines/DAGs, logs, artifacts, cache, schedules, variables/secrets, manual jobs, environments, deployments, and merge trains must not be moved into this open-source repository.
2. Package clients can use the Gitly package API and OCI v2 distribution endpoints. Registry-specific metadata endpoints beyond the implemented package formats, remote object-store vendor SDK features, replication, and signing-authority integrations remain deployment-specific.
3. Gitly ingests and enforces scanner results; scanner engines and vulnerability feeds run externally. Automatic remediation, organization-wide policy inheritance, and third-party compliance evidence collection remain outside the lightweight core.
4. The agent API provides token-authenticated desired configuration, inventory, and heartbeat state. A Kubernetes reverse tunnel, managed Prometheus/Jaeger/Sentry services, paging delivery, and full incident timeline automation remain external integrations.
5. Gitly provides the shared-storage/DB control plane, backups, identity-provider configuration, SCIM, and imports/exports. Multi-region replication/failover orchestration and native LDAP bind/SAML assertion handling should be supplied by deployment infrastructure or a hardened identity gateway.

## Implementation notes

The platform surface, operational boundaries, API examples, and production configuration are documented in [platform.md](platform.md). Permission and policy enforcement lives in the service layer and transport routes rather than only in templates.
