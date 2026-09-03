# Repository forks and mirrors

## Forks

Forks copy Git objects, branches, and tags into a personal namespace or an organization the user administers. Issues, merge requests, members, approvals, webhooks, deploy keys, CI secrets, and mirrors are intentionally not copied. A private source always produces a private fork.

Each fork records both its immediate upstream and root fork-network repository. Network listings include nested forks and are available from every member of the network; a namespace can contain at most one active repository from a network. Deleting an upstream does not erase its descendants' lineage, and deleting an intermediate fork reconnects its children to the nearest surviving ancestor. Users can include every branch or only the default branch. “Sync fork” follows the current upstream default branch when default-only mode is selected and advances branches only when the update is a fast-forward; diverged fork branches are listed as skipped and are never overwritten. This matches the safety expectation of GitLab's [forking workflow](https://docs.gitlab.com/user/project/repository/forking_workflow/).

The “Contribute upstream” action compares a fork branch against an upstream base. Gitly fetches the branch into an isolated `refs/merge-requests/<id>/head` reference in the target repository. Reviews, diffs, merge/squash operations, and approval invalidation use that reference while retaining the source repository and branch identity.

Fork creation, listing, synchronization, and lineage are also available under `/api/v1/repos/:owner/:repo/forks`.

## Mirrors

Repository settings support pull and push mirrors, modeled after GitLab's [repository mirroring](https://docs.gitlab.com/user/project/repository/mirror/) and [pull mirroring](https://docs.gitlab.com/user/project/repository/mirror/pull/):

- Manual updates and a background scheduler, with intervals from 5 to 1440 minutes and explicit pause/resume controls.
- HTTPS basic/token authentication through an ephemeral `GIT_ASKPASS` helper.
- SSH authentication through an ephemeral private-key file and wrapper. SSH mirrors require a pinned `known_hosts` entry and strict host-key checking.
- AES-256-GCM encryption at rest for usernames, passwords/tokens, and SSH private keys, derived from `GITLY_STORAGE_SECRET` with a fresh nonce for every field.
- Optional protected-branch-only operation.
- Fast-forward-only pull behavior by default. Diverged tags also fail explicitly. “Overwrite diverged branches” enables ref replacement, and each fetched set of local refs is published atomically.
- Push mirrors run immediately after accepted HTTP or SSH pushes as well as on schedule.
- Synchronization uses a database lease to prevent overlapping scheduled, manual, and push-triggered runs; abandoned leases are recovered automatically. Push refsets request atomic remote updates.
- Status, last error, failure count, next update, pause/resume, manual update, and deletion through both settings and API.

Mirror endpoints are revalidated before every network operation. By default they must resolve entirely to public addresses, which blocks loopback, private, link-local, metadata, multicast, and other internal targets. To mirror or import from an explicitly trusted internal Git server, list its exact lowercase hostname in `mirror_allowed_hosts` or `GITLY_MIRROR_ALLOWED_HOSTS` (comma-separated). Do not add broad or user-controlled domains.

HTTPS URL query strings and fragments are rejected so credentials cannot be hidden in logged URLs. Embedded HTTPS user information is removed and encrypted separately. SSH URL passwords are rejected; use a private key instead.
