# Platform services

Gitly keeps CI execution in its separate CI repository, but provides the repository-side platform services described here. Every project mutation uses the existing Reporter, Developer, Maintainer, or owner access model. Administrator APIs additionally require an administrator session or personal access token.

## Package delivery

The package API stores immutable coordinates for generic, npm, Maven, PyPI, NuGet, Composer, and Helm artifacts. A publish may include a provenance statement, signature, and key identifier. Artifacts are content-addressed and verified again when read. Maintainers can yank packages and configure cleanup by age, latest-version count, and yanked status.

OCI clients can use `/v2/` and the project-scoped `/v2/{namespace}/{project}` endpoints. Monolithic and resumable blob uploads, digest checks, blob/manifest `HEAD` and `GET`, and manifest `PUT` are supported. Maintainers can protect a manifest from replacement/deletion and configure retention. Basic authentication accepts a user credential/PAT or a repository deploy token with the corresponding repository scope.

Dependency proxy requests require Reporter access, an explicit `dependency_proxy_allowed_hosts` entry, and a destination that resolves only to public addresses. Redirects are disabled. Responses are size-limited, cached, and integrity checked.

Useful API roots:

- `/api/v1/repos/{namespace}/{project}/packages`
- `/api/v1/repos/{namespace}/{project}/container/manifests`
- `/api/v1/repos/{namespace}/{project}/dependency-proxy`

## Security and compliance

External scanners submit a scan for an exact ref and commit, add fingerprinted findings, then mark the scan successful or failed. Supported report categories are SAST, DAST, dependency, container, secret, and license. Repeated fingerprints update one vulnerability record; resolution or dismissal is auditable.

Maintainers can create branch-pattern policies requiring fresh successful scan categories, blocking selected unresolved severities, or restricting detected licenses. Merge and squash routes evaluate these gates against the merge-request head. Role-aware approval policies are evaluated alongside the project-wide approval count, and existing approval invalidation still applies when the head changes.

Compliance frameworks can be assigned to projects. Project and instance audit events are append-only through the application API and export in stable ID order.

## Operations

Cluster-agent and alert-integration secrets are shown once and stored only as hashes. Agents heartbeat with version/inventory data and receive their desired configuration. Feature flags support all-users, deterministic percentage, and explicit-target strategies, optionally restricted by environment.

Alerts deduplicate on integration plus fingerprint and open an incident once. Incidents support state, severity, assignment, and notes. The telemetry API stores bounded metric, trace, and error events with retention jobs. On-call schedules rotate eligible project members using fixed-duration shifts.

These APIs are a control plane: Kubernetes tunnels, metrics/tracing storage clusters, notification delivery, and scanner execution are deliberately external integrations.

## Administration and recovery

`/admin/platform` exposes namespace quotas, leased background jobs, active instance heartbeats, directory providers, compliance frameworks, and backups. `/health/live` is process liveness; `/health/ready` verifies database readiness.

Backups use SQLite `VACUUM INTO` or `pg_dump`, include repositories and local object storage, create a compressed archive, calculate SHA-256, and verify the stored archive on request. When an external HTTP object store is configured, that service must have its own versioning and replication policy; Gitly's archive records still reside there but cannot enumerate the vendor store.

LDAP/SAML/SCIM provider configuration is encrypted with `GITLY_STORAGE_SECRET`. SCIM bearer tokens are hashed, scoped to one provider, optional-expiry, and returned only once. Provisioned `(provider, external ID)` mappings are immutable; later updates change profile/block state without silently relinking the identity. Native LDAP bind and SAML assertion validation belong in a hardened identity gateway in front of this control plane.

Project exports contain a verified Git bundle plus labels, milestones, and issues. Imports require Maintainer access to the empty target and read access to the source export, preserve target visibility, and restore the default branch and project metadata. Group exports/imports similarly require administrator access on both source and target.

## Configuration

Configuration keys have equivalent uppercase `GITLY_` environment variables:

- `object_storage_path`: local artifact volume; defaults to `.gitly-objects` below repository storage.
- `object_storage_url` and `object_storage_token`: authenticated HTTP `GET`/`PUT`/`DELETE` adapter. The configured service must provide durable atomic object semantics.
- `max_package_size_bytes`: maximum in-memory package, OCI, proxy, or export object size; defaults to 500 MiB.
- `dependency_proxy_allowed_hosts`: exact hosts or parent domains allowed for outbound dependency fetches.
- `instance_id`: stable process identifier used for job leases and HA visibility.

All HA instances must share PostgreSQL (recommended for multi-instance operation), repository storage, object storage, and the same storage/session secrets. Quotas are namespace-level and account for repository files, LFS objects, packages, and container manifests. Persisted abuse buckets protect SCIM, agents, alerts, and telemetry independently of a single process.
