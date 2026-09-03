# OpenSSH transport

Gitly delegates the network protocol, host keys, ciphers, rate limiting, and connection lifecycle to the operating system's OpenSSH server. Gitly owns repository authorization and runs `git-upload-pack` or `git-receive-pack` through restricted forced commands. This follows the same user-facing key and deploy-key concepts documented by GitLab for [SSH access](https://docs.gitlab.com/user/ssh/) and [deploy keys](https://docs.gitlab.com/user/project/deploy_keys/).

## Setup

1. Create a dedicated operating-system account such as `git`. Do not give it an interactive password or administrative access.
2. Create its `.ssh` directory with mode `0700` and `authorized_keys` with mode `0600`.
3. Run Gitly as that account, or grant the Gitly process narrowly scoped write access to the configured `authorized_keys` file. OpenSSH must still accept the final ownership and mode.
4. Configure `GITLY_SSH_ENABLED`, `GITLY_SSH_HOSTNAME`, `GITLY_SSH_PORT`, `GITLY_SSH_USER`, and `GITLY_SSH_AUTHORIZED_KEYS_PATH` as shown in the README.
5. Ensure the Gitly executable, `config.json`, database, and repository storage paths remain available at the same absolute paths to forced-command processes.
6. Restart Gitly once. Startup migrations backfill key fingerprints, convert legacy broad protected-branch access into grants for the rules that currently exist, and synchronize the managed key block.

Gitly preserves every line outside:

```text
# BEGIN GITLY MANAGED KEYS
# END GITLY MANAGED KEYS
```

Do not manually edit inside that block. Authentication keys use OpenSSH's `restrict` option plus explicit forwarding, PTY, user-rc, and X11 denials. A forced Gitly command accepts only `git-upload-pack` and `git-receive-pack`, resolves the requested repository through Gitly authorization, and launches Git with a clean allowlisted environment. Client-provided loader, Git configuration, and arbitrary command variables are not inherited.

## Authorization

- Public repositories can be fetched by any active Gitly user key. Private repositories require Reporter or greater access.
- Push requires Developer or greater access and is checked again against protected-branch rules in a pre-receive hook.
- Protected branches cannot be deleted or force-pushed. Their configured role threshold applies to SSH just as it does to HTTP.
- Deploy keys are scoped to one repository. They are read-only unless a Maintainer explicitly enables write access. Write keys run with Developer access by default; a Maintainer must grant the key access to each protected-branch rule it needs. A later rule is never implicitly granted, and overlapping protected rules all remain enforceable.
- Expired, disabled, signing-only, duplicate, malformed, and blocked-user keys are not written to the managed block.
- Successful use updates the key's `last_used_at` and validated client-IP metadata. The UI and API expose that metadata together with key usage type and expiry.

User-key usage values are `auth`, `signing`, and `auth_and_signing`. Upgrades normalize the former `both` value to `auth_and_signing`.

The post-receive hook refreshes repository caches, invalidates merge-request approvals for changed heads, triggers configured CI, and starts push mirrors.

## Operational checks

Use `ssh -T git@git.example.com` to verify that interactive access is rejected. Then clone an allowed repository with the SSH URL shown in its Code menu. OpenSSH logs remain the authoritative source for handshake and host-key failures; Gitly's security and application logs cover account/repository authorization failures.
