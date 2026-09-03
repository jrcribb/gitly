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

The governance and repository model follows GitLab's documented [project roles](https://docs.gitlab.com/user/permissions/), [project members](https://docs.gitlab.com/user/project/members/), [protected branches](https://docs.gitlab.com/user/project/repository/branches/protected/), [merge request approvals](https://docs.gitlab.com/user/project/merge_requests/approvals/), [SSH keys](https://docs.gitlab.com/user/ssh/), [deploy keys](https://docs.gitlab.com/user/project/deploy_keys/), [fork workflows](https://docs.gitlab.com/user/project/repository/forking_workflow/), and [repository mirrors](https://docs.gitlab.com/user/project/repository/mirror/).

## Remaining platform areas

These are not small checkboxes; each requires storage, permissions, APIs, background workers, operational controls, and tests.

1. Native CI/CD: isolated runners (the separate shell runner is not a safe production sandbox for untrusted repository jobs), pipelines and DAGs, job logs/artifacts/cache, schedules, variables/secrets, manual jobs, environments, deployments, and merge trains.
2. Package delivery: package, container, and dependency-proxy registries with retention, authentication, and provenance.
3. Security and compliance: SAST/DAST/dependency/container/secret scanning, vulnerability management, policies, audit-event export, compliance frameworks, and approval-policy controls.
4. Operations: Kubernetes and agent integration, feature flags, incidents, alerting, metrics, tracing, error tracking, and on-call schedules.
5. Scale and administration: background job queues, object storage, high availability, disaster recovery, quotas, abuse controls, LDAP/SAML/SCIM, and group/project import-export.

## Implementation order

The next dependency-safe order is package registry foundations, security and compliance suites, operational integrations, then scale and enterprise administration. Every slice should include its permission model and API at the same time as its UI; transport or policy enforcement must never exist only in templates.
