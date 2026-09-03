// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import time
import os
import git

const protected_branch_pre_receive_hook = '#!/bin/sh
rules="\${GITLY_PROTECTED_BRANCH_RULES:-}"
grants="\${GITLY_PROTECTED_BRANCH_GRANTS:-}"
tag_rules="\${GITLY_PROTECTED_TAG_RULES:-}"
access="\${GITLY_USER_ACCESS_LEVEL:-0}"
require_signed="\${GITLY_REQUIRE_SIGNED_COMMITS:-0}"
allowed_signers="\${GITLY_SSH_ALLOWED_SIGNERS:-}"
while read old_hash new_hash ref_name; do
	case "\$ref_name" in
		refs/heads/*) branch="\${ref_name#refs/heads/}" ;;
		refs/tags/*)
			tag="\${ref_name#refs/tags/}"
			remaining="\$tag_rules"
			while [ -n "\$remaining" ]; do
				rule="\${remaining%%;*}"
				if [ "\$remaining" = "\$rule" ]; then remaining=""; else remaining="\${remaining#*;}"; fi
				rest="\${rule#*|}"
				pattern="\${rest%%|*}"
				create_access="\${rest#*|}"
				case "\$tag" in
					\$pattern)
						case "\$old_hash" in
							0000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000)
								if [ "\$create_access" -ge 100 ] || [ "\$access" -lt "\$create_access" ]; then
									echo "Gitly: you are not allowed to create protected tag \$tag" >&2; exit 1
								fi ;;
							*) echo "Gitly: protected tag \$tag cannot be changed or deleted" >&2; exit 1 ;;
						esac ;;
				esac
				done
			if [ "\$require_signed" = "1" ]; then
				case "\$new_hash" in
					0000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000) continue ;;
				esac
				if [ -z "\$allowed_signers" ] || [ ! -f "\$allowed_signers" ]; then
					echo "Gitly: signed-commit policy is unavailable" >&2; exit 1
				fi
				case "\$old_hash" in
					0000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000)
						commits="\$(git rev-list "\$new_hash" --not --all)" ;;
					*) commits="\$(git rev-list "\$new_hash" "^\$old_hash")" ;;
				esac
				for commit in \$commits; do
					if ! git -c "gpg.ssh.allowedSignersFile=\$allowed_signers" verify-commit "\$commit" >/dev/null 2>&1; then
						echo "Gitly: commit \$commit does not have a trusted signature" >&2; exit 1
					fi
				done
			fi
			continue ;;
		*) continue ;;
	esac
	if [ "\$access" -lt 30 ]; then
		echo "Gitly: Developer access is required to push" >&2
		exit 1
	fi
	protected=0
	required=0
	remaining="\$rules"
	while [ -n "\$remaining" ]; do
		rule="\${remaining%%;*}"
		if [ "\$remaining" = "\$rule" ]; then
			remaining=""
		else
			remaining="\${remaining#*;}"
		fi
		rule_id="\${rule%%|*}"
		rest="\${rule#*|}"
		pattern="\${rest%%|*}"
		rest="\${rest#*|}"
		push_access="\${rest%%|*}"
		case "\$branch" in
			\$pattern)
				protected=1
				case ",\$grants," in
					*,"\$rule_id",*) ;;
					*) if [ "\$push_access" -gt "\$required" ]; then required="\$push_access"; fi ;;
				esac
				;;
		esac
	done
	if [ "\$protected" -eq 1 ]; then
		if [ "\$required" -ge 100 ] || [ "\$access" -lt "\$required" ]; then
			echo "Gitly: you are not allowed to push to protected branch \$branch" >&2
			exit 1
		fi
	fi
	case "\$new_hash" in
		0000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000)
			if [ "\$protected" -eq 1 ]; then
				echo "Gitly: protected branch \$branch cannot be deleted" >&2
				exit 1
			fi
			continue ;;
	esac
	if [ "\$protected" -eq 1 ] && git cat-file -e "\${old_hash}^{commit}" 2>/dev/null
	then
		git cat-file -e "\${new_hash}^{commit}" 2>/dev/null || exit 1
		if ! git merge-base --is-ancestor "\$old_hash" "\$new_hash"; then
		echo "Gitly: force-pushing to protected branch \$branch is not allowed" >&2
		exit 1
		fi
	fi
	if [ "\$require_signed" = "1" ]; then
		if [ -z "\$allowed_signers" ] || [ ! -f "\$allowed_signers" ]; then
			echo "Gitly: signed-commit policy is unavailable" >&2; exit 1
		fi
		case "\$old_hash" in
			0000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000)
				commits="\$(git rev-list "\$new_hash" --not --all)" ;;
			*) commits="\$(git rev-list "\$new_hash" "^\$old_hash")" ;;
		esac
		for commit in \$commits; do
			if ! git -c "gpg.ssh.allowedSignersFile=\$allowed_signers" verify-commit "\$commit" >/dev/null 2>&1; then
				echo "Gitly: commit \$commit does not have a trusted signature" >&2; exit 1
			fi
		done
	fi
done
exit 0
'

const gitly_post_receive_hook = '#!/bin/sh
if [ "\${GITLY_RUN_POST_RECEIVE:-0}" = "1" ] && [ -n "\${GITLY_EXECUTABLE:-}" ]; then
	exec "\$GITLY_EXECUTABLE" ssh-post-receive "\$GITLY_REPO_ID" "\$GITLY_CONFIG_PATH"
fi
cat >/dev/null
exit 0
'

struct ProtectedBranch {
	id           int @[primary; sql: serial]
	repo_id      int @[unique: 'protected_branch']
	pattern      string @[unique: 'protected_branch']
	push_access  int
	merge_access int
	created_at   int
}

fn valid_protected_branch_pattern(pattern string) bool {
	value := pattern.trim_space()
	if value == '' || value == '@' || value.len > 255 || value.starts_with('-')
		|| value.contains_any(';|?[]\\~^:') || value.contains(' ') || value.contains('..')
		|| value.contains('@{') {
		return false
	}
	for ch in value.bytes() {
		if ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	for segment in value.split('/') {
		if segment == '' || segment.starts_with('.') || segment.ends_with('.')
			|| segment.ends_with('.lock') {
			return false
		}
	}
	return true
}

fn valid_branch_access_level(level int) bool {
	return level in [project_access_developer, project_access_maintainer, project_access_no_one]
}

// branch_pattern_matches implements the wildcard form GitLab exposes for
// protected branches. `*` can match any number of bytes (including `/`), while
// every other character is literal.
fn branch_pattern_matches(pattern string, branch string) bool {
	mut p := 0
	mut b := 0
	mut star := -1
	mut retry := 0
	for b < branch.len {
		if p < pattern.len && pattern[p] == branch[b] {
			p++
			b++
		} else if p < pattern.len && pattern[p] == `*` {
			star = p
			p++
			retry = b
		} else if star >= 0 {
			p = star + 1
			retry++
			b = retry
		} else {
			return false
		}
	}
	for p < pattern.len && pattern[p] == `*` {
		p++
	}
	return p == pattern.len
}

fn (app &App) find_protected_branches(repo_id int) []ProtectedBranch {
	return sql app.db {
		select from ProtectedBranch where repo_id == repo_id order by pattern
	} or { []ProtectedBranch{} }
}

fn (app &App) find_protected_branch_by_id(repo_id int, rule_id int) ?ProtectedBranch {
	rows := sql app.db {
		select from ProtectedBranch where id == rule_id && repo_id == repo_id limit 1
	} or { []ProtectedBranch{} }
	if rows.len == 0 {
		return none
	}
	return rows.first()
}

fn (app &App) protected_branch_rules_env(repo_id int) string {
	return app.find_protected_branches(repo_id).map('${it.id}|${it.pattern}|${it.push_access}|${it.merge_access}').join(';')
}

fn (app &App) ensure_protected_branch_hook(repo Repo) ! {
	if repo.git_dir == '' || !os.exists(repo.git_dir) {
		return error('repository directory is unavailable')
	}
	hook_dir := os.join_path(repo.git_dir, '.gitly-hooks')
	os.mkdir_all(hook_dir)!
	hook_path := os.join_path(hook_dir, 'pre-receive')
	current := os.read_file(hook_path) or { '' }
	if current != protected_branch_pre_receive_hook {
		os.write_file(hook_path, protected_branch_pre_receive_hook)!
	}
	os.chmod(hook_path, 0o700)!
	post_hook_path := os.join_path(hook_dir, 'post-receive')
	post_current := os.read_file(post_hook_path) or { '' }
	if post_current != gitly_post_receive_hook {
		os.write_file(post_hook_path, gitly_post_receive_hook)!
	}
	os.chmod(post_hook_path, 0o700)!
	app.write_ssh_allowed_signers(repo)!
	// Keep this relative to the bare repository so repository transfers do not
	// leave Git pointing at a hook directory under the old namespace.
	config_result := git.Git.exec_in_dir(repo.git_dir, ['config', 'core.hooksPath', '.gitly-hooks'])
	if config_result.exit_code != 0 {
		return error('could not configure protected branch hook')
	}
	app.ensure_partial_clone_config(repo)!
}

fn (app &App) matching_protected_branches(repo_id int, branch string) []ProtectedBranch {
	return app.find_protected_branches(repo_id).filter(branch_pattern_matches(it.pattern, branch))
}

fn (app &App) branch_is_protected(repo_id int, branch string) bool {
	return app.matching_protected_branches(repo_id, branch).len > 0
}

fn (app &App) required_branch_access(repo_id int, branch string, operation string) int {
	mut required := 0
	for rule in app.matching_protected_branches(repo_id, branch) {
		level := if operation == 'merge' { rule.merge_access } else { rule.push_access }
		if level > required {
			required = level
		}
	}
	return required
}

fn (app &App) user_can_push_branch(user_id int, repo Repo, branch string) bool {
	level := app.repo_access_level(user_id, repo)
	return app.access_level_can_push_branch(level, repo.id, branch)
}

fn (app &App) access_level_can_push_branch(level int, repo_id int, branch string) bool {
	if level < project_access_developer {
		return false
	}
	required := app.required_branch_access(repo_id, branch, 'push')
	return required < project_access_no_one && level >= required
}

fn (app &App) access_level_can_create_tag(level int, repo_id int, tag_name string) bool {
	if level < project_access_developer {
		return false
	}
	mut required := project_access_developer
	for rule in app.matching_protected_tags(repo_id, tag_name) {
		if rule.create_access > required {
			required = rule.create_access
		}
	}
	return required < project_access_no_one && level >= required
}

fn (app &App) user_can_merge_branch(user_id int, repo Repo, branch string) bool {
	level := app.repo_access_level(user_id, repo)
	if level < project_access_developer {
		return false
	}
	required := app.required_branch_access(repo.id, branch, 'merge')
	return required < project_access_no_one && level >= required
}

fn (mut app App) protect_branch(repo_id int, pattern string, push_access int, merge_access int) !int {
	clean_pattern := pattern.trim_space()
	if repo_id <= 0 || !valid_protected_branch_pattern(clean_pattern)
		|| !valid_branch_access_level(push_access) || !valid_branch_access_level(merge_access) {
		return error('invalid protected branch rule')
	}
	return db_insert_returning_id(mut app.db, 'ProtectedBranch', ['repo_id', 'pattern', 'push_access',
		'merge_access', 'created_at'], [repo_id.str(), clean_pattern, push_access.str(),
		merge_access.str(), int(time.now().unix()).str()])
}

fn (mut app App) update_protected_branch(repo_id int, rule_id int, push_access int, merge_access int) ! {
	if repo_id <= 0 || rule_id <= 0 || !valid_branch_access_level(push_access)
		|| !valid_branch_access_level(merge_access) {
		return error('invalid protected branch rule')
	}
	sql app.db {
		update ProtectedBranch set push_access = push_access, merge_access = merge_access
		where id == rule_id && repo_id == repo_id
	}!
}

fn (mut app App) unprotect_branch(repo_id int, rule_id int) ! {
	if repo_id <= 0 || rule_id <= 0 {
		return error('invalid protected branch rule')
	}
	mut tx := db_begin_transaction(mut app.db)!
	mut committed := false
	defer {
		if !committed {
			tx.rollback() or {}
		}
	}
	sql tx {
		delete from ProtectedBranch where id == rule_id && repo_id == repo_id
	}!
	sql tx {
		delete from DeployKeyProtectedBranchGrant where repo_id == repo_id
		&& protected_branch_id == rule_id
	}!
	tx.commit()!
	committed = true
}

fn (mut app App) ensure_default_branch_protection(repo_id int, branch string) ! {
	if repo_id <= 0 || !valid_protected_branch_pattern(branch) {
		return
	}
	count := sql app.db {
		select count from ProtectedBranch where repo_id == repo_id && pattern == branch
	} or { 0 }
	if count > 0 {
		return
	}
	app.protect_branch(repo_id, branch, project_access_maintainer, project_access_maintainer)!
}

fn (mut app App) backfill_default_branch_protection_once() ! {
	settings := sql app.db {
		select from Settings limit 1
	} or { []Settings{} }
	if settings.len > 0 && settings.first().governance_backfilled {
		return
	}
	repos := sql app.db {
		select from Repo where is_deleted == false
	} or { []Repo{} }
	for repo in repos {
		app.ensure_default_branch_protection(repo.id, repo.primary_branch)!
	}
	completed := true
	if settings.len == 0 {
		row := Settings{
			governance_backfilled: true
		}
		sql app.db {
			insert row into Settings
		}!
	} else {
		id := settings.first().id
		sql app.db {
			update Settings set governance_backfilled = completed where id == id
		}!
	}
}

fn (mut app App) delete_repo_protected_branches(repo_id int) ! {
	mut tx := db_begin_transaction(mut app.db)!
	mut committed := false
	defer {
		if !committed {
			tx.rollback() or {}
		}
	}
	sql tx {
		delete from ProtectedBranch where repo_id == repo_id
	}!
	sql tx {
		delete from DeployKeyProtectedBranchGrant where repo_id == repo_id
	}!
	tx.commit()!
	committed = true
}
