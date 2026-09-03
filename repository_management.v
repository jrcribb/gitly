// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import crypto.rand
import crypto.sha256
import encoding.hex
import config
import git
import os
import time

const deploy_token_scope_read_repository = 'read_repository'
const deploy_token_scope_write_repository = 'write_repository'
const deploy_token_scope_read_lfs = 'read_lfs'
const deploy_token_scope_write_lfs = 'write_lfs'
const max_lfs_object_size = i64(1024) * 1024 * 1024

struct DeployToken {
	id int @[primary; sql: serial]
mut:
	repo_id      int
	created_by   int
	name         string
	username     string @[unique]
	token_hash   string @[unique]
	scopes       string
	expires_at   int
	revoked      bool
	created_at   int
	last_used_at int
	last_used_ip string
}

struct ProtectedTag {
	id int @[primary; sql: serial]
mut:
	repo_id       int @[unique: 'protected_tag']
	pattern       string @[unique: 'protected_tag']
	create_access int
	created_at    int
}

struct Snippet {
	id int @[primary; sql: serial]
mut:
	repo_id     int
	author_id   int
	title       string
	description string
	file_name   string
	content     string
	is_public   bool
	created_at  int
	updated_at  int
}

struct LfsObject {
	id int @[primary; sql: serial]
mut:
	oid        string @[unique]
	size       i64
	created_at int
}

struct RepoLfsObject {
	id int @[primary; sql: serial]
mut:
	repo_id       int @[unique: 'repo_lfs_object']
	lfs_object_id int @[unique: 'repo_lfs_object']
	created_at    int
}

struct RepoHousekeeping {
	id int @[primary; sql: serial]
mut:
	repo_id           int @[unique]
	is_running        bool
	last_started_at   int
	last_completed_at int
	last_error        string
}

fn (state RepoHousekeeping) completed_description() string {
	return if state.last_completed_at > 0 {
		time.unix(state.last_completed_at).format_ss()
	} else {
		'Never'
	}
}

struct CommitSignatureVerification {
	commit_hash string
	verified    bool
	signer_id   int
	signer      string
	fingerprint string
	details     string
}

fn deploy_token_scope_is_known(scope string) bool {
	return scope in [deploy_token_scope_read_repository, deploy_token_scope_write_repository,
		deploy_token_scope_read_lfs, deploy_token_scope_write_lfs]
}

fn normalize_deploy_token_scopes(requested []string) !string {
	mut selected := map[string]bool{}
	for raw in requested {
		scope := raw.trim_space().to_lower()
		if !deploy_token_scope_is_known(scope) {
			return error('invalid deploy token scope')
		}
		selected[scope] = true
	}
	mut scopes := []string{}
	for scope in [deploy_token_scope_read_repository, deploy_token_scope_write_repository,
		deploy_token_scope_read_lfs, deploy_token_scope_write_lfs] {
		if selected[scope] {
			scopes << scope
		}
	}
	if scopes.len == 0 {
		return error('at least one deploy token scope is required')
	}
	return scopes.join(',')
}

fn (token DeployToken) allows_scope(scope string, now int) bool {
	if token.revoked || (token.expires_at > 0 && token.expires_at <= now) {
		return false
	}
	scopes := token.scopes.split(',').map(it.trim_space())
	return match scope {
		deploy_token_scope_read_repository {
			deploy_token_scope_read_repository in scopes || deploy_token_scope_write_repository in scopes
		}
		deploy_token_scope_write_repository { deploy_token_scope_write_repository in scopes }
		deploy_token_scope_read_lfs {
			deploy_token_scope_read_lfs in scopes || deploy_token_scope_write_lfs in scopes
				|| deploy_token_scope_read_repository in scopes || deploy_token_scope_write_repository in scopes
		}
		deploy_token_scope_write_lfs { deploy_token_scope_write_lfs in scopes }
		else { false }
	}
}

fn generate_deploy_token_secret() !(string, string) {
	username_bytes := rand.bytes(6)!
	token_bytes := rand.bytes(24)!
	return 'deploy-' + hex.encode(username_bytes), 'gldt_' + hex.encode(token_bytes)
}

fn (mut app App) add_deploy_token(repo_id int, created_by int, name string, requested_scopes []string,
	expires_at int) !(int, string, string) {
	if repo_id <= 0 || created_by <= 0 || !valid_short_name(name) {
		return error('invalid deploy token')
	}
	now := int(time.now().unix())
	if expires_at != 0 && (expires_at <= now || expires_at > now + api_token_max_expiry_days * 86400) {
		return error('deploy token expiry must be within the next ${api_token_max_expiry_days} days')
	}
	scopes := normalize_deploy_token_scopes(requested_scopes)!
	username, secret := generate_deploy_token_secret()!
	id := db_insert_returning_id(mut app.db, 'DeployToken', ['repo_id', 'created_by', 'name',
		'username', 'token_hash', 'scopes', 'expires_at', 'revoked', 'created_at', 'last_used_at',
		'last_used_ip'], [repo_id.str(), created_by.str(), name.trim_space(), username,
		hash_api_token(secret), scopes, expires_at.str(), db_bool_value(false), now.str(), '0',
		''])!
	return id, username, secret
}

fn (app &App) find_repo_deploy_tokens(repo_id int) []DeployToken {
	return sql app.db {
		select from DeployToken where repo_id == repo_id order by id desc
	} or { []DeployToken{} }
}

fn (mut app App) authenticate_deploy_token(repo_id int, username string, secret string,
	required_scope string, client_ip string) ?DeployToken {
	if repo_id <= 0 || !secret.starts_with('gldt_') || secret.len > max_password_len
		|| !deploy_token_scope_is_known(required_scope) {
		return none
	}
	hashed := hash_api_token(secret)
	rows := sql app.db {
		select from DeployToken where repo_id == repo_id && username == username
		&& token_hash == hashed limit 1
	} or { []DeployToken{} }
	if rows.len != 1 || !rows.first().allows_scope(required_scope, int(time.now().unix())) {
		return none
	}
	token := rows.first()
	now := int(time.now().unix())
	safe_ip := client_ip.trim_space()[..if client_ip.trim_space().len < 255 {
		client_ip.trim_space().len
	} else {
		255
	}]
	id := token.id
	sql app.db {
		update DeployToken set last_used_at = now, last_used_ip = safe_ip where id == id
	} or {}
	return token
}

fn (mut app App) revoke_deploy_token(repo_id int, token_id int) ! {
	if repo_id <= 0 || token_id <= 0 {
		return error('invalid deploy token')
	}
	revoked := true
	sql app.db {
		update DeployToken set revoked = revoked where id == token_id && repo_id == repo_id
	}!
}

fn valid_protected_tag_pattern(pattern string) bool {
	return valid_protected_branch_pattern(pattern)
}

fn (app &App) find_protected_tags(repo_id int) []ProtectedTag {
	return sql app.db {
		select from ProtectedTag where repo_id == repo_id order by pattern
	} or { []ProtectedTag{} }
}

fn (app &App) find_protected_tag_by_id(repo_id int, id int) ?ProtectedTag {
	rows := sql app.db {
		select from ProtectedTag where repo_id == repo_id && id == id limit 1
	} or { []ProtectedTag{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) protected_tag_rules_env(repo_id int) string {
	return app.find_protected_tags(repo_id).map('${it.id}|${it.pattern}|${it.create_access}').join(';')
}

fn (app &App) matching_protected_tags(repo_id int, tag_name string) []ProtectedTag {
	return app.find_protected_tags(repo_id).filter(branch_pattern_matches(it.pattern, tag_name))
}

fn (app &App) tag_is_protected(repo_id int, tag_name string) bool {
	return app.matching_protected_tags(repo_id, tag_name).len > 0
}

fn (app &App) user_can_create_tag(user_id int, repo Repo, tag_name string) bool {
	level := app.repo_access_level(user_id, repo)
	if level < project_access_developer {
		return false
	}
	mut required := project_access_developer
	for rule in app.matching_protected_tags(repo.id, tag_name) {
		if rule.create_access > required {
			required = rule.create_access
		}
	}
	return required < project_access_no_one && level >= required
}

fn (mut app App) protect_tag(repo_id int, pattern string, create_access int) !int {
	clean := pattern.trim_space()
	if repo_id <= 0 || !valid_protected_tag_pattern(clean) || !valid_branch_access_level(create_access) {
		return error('invalid protected tag rule')
	}
	return db_insert_returning_id(mut app.db, 'ProtectedTag', ['repo_id', 'pattern', 'create_access',
		'created_at'], [repo_id.str(), clean, create_access.str(), int(time.now().unix()).str()])
}

fn (mut app App) unprotect_tag(repo_id int, id int) ! {
	sql app.db {
		delete from ProtectedTag where repo_id == repo_id && id == id
	}!
}

fn safe_snippet_file_name(value string) bool {
	clean := value.trim_space()
	return clean != '' && clean.len <= 255 && !clean.contains('/') && !clean.contains('\\')
		&& clean != '.' && clean != '..'
}

fn (mut app App) add_snippet(repo_id int, author_id int, title string, description string,
	file_name string, content string, is_public bool) !int {
	if repo_id <= 0 || author_id <= 0 || !valid_title(title) || !valid_body(description)
		|| !safe_snippet_file_name(file_name) || content.len > max_body_len {
		return error('invalid snippet')
	}
	now := int(time.now().unix())
	return db_insert_returning_id(mut app.db, 'Snippet', ['repo_id', 'author_id', 'title',
		'description', 'file_name', 'content', 'is_public', 'created_at', 'updated_at'], [
		repo_id.str(),
		author_id.str(),
		title.trim_space(),
		description,
		file_name.trim_space(),
		content,
		db_bool_value(is_public),
		now.str(),
		now.str(),
	])
}

fn (app &App) find_repo_snippets(repo_id int) []Snippet {
	return sql app.db {
		select from Snippet where repo_id == repo_id order by updated_at desc
	} or { []Snippet{} }
}

fn (app &App) find_snippet(repo_id int, id int) ?Snippet {
	rows := sql app.db {
		select from Snippet where repo_id == repo_id && id == id limit 1
	} or { []Snippet{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) user_can_read_snippet(user_id int, repo Repo, snippet Snippet) bool {
	return snippet.repo_id == repo.id
		&& (snippet.is_public || app.repo_access_level(user_id, repo) >= project_access_reporter)
}

fn (mut app App) update_snippet(repo_id int, id int, title string, description string,
	file_name string, content string, is_public bool) ! {
	if !valid_title(title) || !valid_body(description) || !safe_snippet_file_name(file_name)
		|| content.len > max_body_len {
		return error('invalid snippet')
	}
	now := int(time.now().unix())
	sql app.db {
		update Snippet set title = title, description = description, file_name = file_name,
		content = content, is_public = is_public, updated_at = now where repo_id == repo_id && id == id
	}!
}

fn (mut app App) delete_snippet(repo_id int, id int) ! {
	sql app.db {
		delete from Snippet where repo_id == repo_id && id == id
	}!
}

fn valid_lfs_oid(oid string) bool {
	if oid.len != 64 {
		return false
	}
	for ch in oid.bytes() {
		if !ch.is_digit() && (ch < `a` || ch > `f`) {
			return false
		}
	}
	return true
}

fn (app &App) lfs_object_path(oid string) string {
	return os.join_path(app.config.repo_storage_path, '.gitly-lfs', 'objects', oid[..2], oid[2..4], oid)
}

fn (app &App) find_lfs_object(oid string) ?LfsObject {
	rows := sql app.db {
		select from LfsObject where oid == oid limit 1
	} or { []LfsObject{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) repo_has_lfs_object(repo_id int, oid string) bool {
	object := app.find_lfs_object(oid) or { return false }
	count := sql app.db {
		select count from RepoLfsObject where repo_id == repo_id && lfs_object_id == object.id
	} or { 0 }
	return count > 0 && os.exists(app.lfs_object_path(oid))
}

fn (mut app App) store_lfs_object(repo_id int, oid string, expected_size i64, data []u8) ! {
	if repo_id <= 0 || !valid_lfs_oid(oid) || expected_size < 0 || expected_size > max_lfs_object_size
		|| i64(data.len) != expected_size || sha256.sum(data).hex() != oid {
		return error('LFS object checksum or size is invalid')
	}
	path := app.lfs_object_path(oid)
	os.mkdir_all(os.dir(path))!
	if !os.exists(path) {
		os.write_file_array(path, data)!
	}
	object := app.find_lfs_object(oid) or {
		id := db_insert_returning_id(mut app.db, 'LfsObject', ['oid', 'size', 'created_at'], [
			oid,
			expected_size.str(),
			int(time.now().unix()).str(),
		])!
		LfsObject{
			id: id
			oid: oid
			size: expected_size
		}
	}
	if object.size != expected_size {
		return error('stored LFS object size does not match its object id')
	}
	existing := sql app.db {
		select count from RepoLfsObject where repo_id == repo_id && lfs_object_id == object.id
	} or { 0 }
	if existing == 0 {
		link := RepoLfsObject{
			repo_id: repo_id
			lfs_object_id: object.id
			created_at: int(time.now().unix())
		}
		sql app.db {
			insert link into RepoLfsObject
		}!
	}
}

fn (app &App) ensure_partial_clone_config(repo Repo) ! {
	for key in ['uploadpack.allowFilter', 'uploadpack.allowAnySHA1InWant'] {
		result := git.Git.exec_in_dir(repo.git_dir, ['config', key, 'true'])
		if result.exit_code != 0 {
			return error('could not enable partial clone support: ${result.output}')
		}
	}
}

fn (mut app App) run_repository_housekeeping(repo Repo) !RepoHousekeeping {
	if repo.id <= 0 || !os.exists(repo.git_dir) {
		return error('repository is unavailable')
	}
	now := int(time.now().unix())
	rows := sql app.db {
		select from RepoHousekeeping where repo_id == repo.id limit 1
	} or { []RepoHousekeeping{} }
	if rows.len == 0 {
		row := RepoHousekeeping{
			repo_id: repo.id
		}
		sql app.db {
			insert row into RepoHousekeeping
		}!
	}
	stale_before := now - 3600
	claimed := db_exec_values(mut app.db, 'update ${sql_table('RepoHousekeeping')}
		set ${sql_table('is_running')} = ${db_bool_value(true)},
			${sql_table('last_started_at')} = ${now}, ${sql_table('last_error')} = \'\'
		where ${sql_table('repo_id')} = ${repo.id}
		and (${sql_table('is_running')} is false or ${sql_table('last_started_at')} <= ${stale_before})
		returning ${sql_table('id')}')!
	if claimed.len != 1 {
		return error('repository housekeeping is already running')
	}
	app.ensure_partial_clone_config(repo) or {
		app.finish_repository_housekeeping(repo.id, err.msg())
		return err
	}
	for args in [['maintenance', 'run', '--auto'], ['commit-graph', 'write', '--reachable',
		'--changed-paths'], ['fsck', '--connectivity-only']] {
		result := git.Git.exec_in_dir(repo.git_dir, args)
		if result.exit_code != 0 {
			message := result.output.trim_space()
			app.finish_repository_housekeeping(repo.id, message)
			return error('repository housekeeping failed: ${message}')
		}
	}
	app.prune_unreferenced_lfs_objects() or {
		app.finish_repository_housekeeping(repo.id, err.msg())
		return err
	}
	app.finish_repository_housekeeping(repo.id, '')
	return app.repository_housekeeping(repo.id) or { return error('housekeeping state was not saved') }
}

fn (mut app App) prune_unreferenced_lfs_objects() ! {
	cutoff := int(time.now().unix()) - 86400
	objects := sql app.db {
		select from LfsObject where created_at < cutoff
	}!
	for object in objects {
		links := sql app.db {
			select count from RepoLfsObject where lfs_object_id == object.id
		}!
		if links > 0 {
			continue
		}
		path := app.lfs_object_path(object.oid)
		if os.exists(path) {
			os.rm(path)!
		}
		id := object.id
		sql app.db {
			delete from LfsObject where id == id
		}!
	}
}

fn (mut app App) finish_repository_housekeeping(repo_id int, message string) {
	finished := int(time.now().unix())
	running := false
	sql app.db {
		update RepoHousekeeping set is_running = running, last_completed_at = finished,
		last_error = message where repo_id == repo_id
	} or {}
}

fn (app &App) repository_housekeeping(repo_id int) ?RepoHousekeeping {
	rows := sql app.db {
		select from RepoHousekeeping where repo_id == repo_id limit 1
	} or { []RepoHousekeeping{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (key SshKey) usable_for_signing(now int) bool {
	return key.usage_type in ['signing', 'auth_and_signing', 'both']
		&& (key.expires_at == 0 || key.expires_at > now)
}

fn (app &App) write_ssh_allowed_signers(repo Repo) !string {
	dir := os.join_path(repo.git_dir, '.gitly-hooks')
	os.mkdir_all(dir)!
	path := os.join_path(dir, 'allowed_signers')
	now := int(time.now().unix())
	keys := sql app.db {
		select from SshKey order by id
	} or { []SshKey{} }
	mut lines := []string{}
	for key in keys {
		user := app.get_user_by_id(key.user_id) or { continue }
		if user.is_registered && !user.is_blocked && key.usable_for_signing(now) {
			lines << '* ${key.key}'
		}
	}
	os.write_file(path, if lines.len > 0 { lines.join('\n') + '\n' } else { '' })!
	os.chmod(path, 0o600)!
	return path
}

fn extract_signature_fingerprint(output string) string {
	for word in output.replace('\n', ' ').fields() {
		if word.starts_with('SHA256:') {
			return word.trim_right('.,)')
		}
	}
	return ''
}

fn (app &App) verify_commit_ssh_signature(repo Repo, commit_hash string) CommitSignatureVerification {
	if !is_git_object_id(commit_hash) {
		return CommitSignatureVerification{
			commit_hash: commit_hash
			details: 'invalid commit id'
		}
	}
	allowed_signers := app.write_ssh_allowed_signers(repo) or {
		return CommitSignatureVerification{
			commit_hash: commit_hash
			details: err.msg()
		}
	}
	result := git.Git.exec_in_dir(repo.git_dir, ['-c',
		'gpg.ssh.allowedSignersFile=${allowed_signers}', 'verify-commit', commit_hash])
	fingerprint := extract_signature_fingerprint(result.output)
	if result.exit_code != 0 || fingerprint == '' {
		return CommitSignatureVerification{
			commit_hash: commit_hash
			fingerprint: fingerprint
			details: result.output.trim_space()
		}
	}
	keys := sql app.db {
		select from SshKey where fingerprint == fingerprint limit 1
	} or { []SshKey{} }
	if keys.len != 1 || !keys.first().usable_for_signing(int(time.now().unix())) {
		return CommitSignatureVerification{
			commit_hash: commit_hash
			fingerprint: fingerprint
			details: 'signature key is not an active Gitly signing key'
		}
	}
	user := app.get_user_by_id(keys.first().user_id) or { User{} }
	if !user.is_registered || user.is_blocked {
		return CommitSignatureVerification{
			commit_hash: commit_hash
			fingerprint: fingerprint
			details: 'signature owner is not an active Gitly user'
		}
	}
	return CommitSignatureVerification{
		commit_hash: commit_hash
		verified: true
		signer_id: user.id
		signer: user.username
		fingerprint: fingerprint
		details: result.output.trim_space()
	}
}

fn (app &App) verify_commit_range_for_policy(repo Repo, old_hash string, new_hash string) ! {
	if !repo.require_signed_commits {
		return
	}
	allowed_signers := app.write_ssh_allowed_signers(repo)!
	mut args := ['rev-list', new_hash]
	if is_git_object_id(old_hash) && old_hash.trim('0') != '' {
		args << '^${old_hash}'
	} else {
		args << ['--not', '--glob=refs/heads/*', '--glob=refs/tags/*']
	}
	commits := git.Git.exec_in_dir(repo.git_dir, args)
	if commits.exit_code != 0 {
		return error('could not inspect commits for the signed-commit policy')
	}
	for commit_hash in commits.output.split_into_lines().map(it.trim_space()).filter(it != '') {
		result := git.Git.exec_in_dir(repo.git_dir, ['-c',
			'gpg.ssh.allowedSignersFile=${allowed_signers}', 'verify-commit', commit_hash])
		if result.exit_code != 0 {
			return error('commit ${commit_hash} does not have a trusted signature')
		}
	}
}

fn is_git_object_id(value string) bool {
	if value.len !in [40, 64] {
		return false
	}
	for ch in value.bytes() {
		if !ch.is_digit() && (ch < `a` || ch > `f`) {
			return false
		}
	}
	return true
}

fn (mut app App) set_signed_commit_policy(repo_id int, required bool) ! {
	sql app.db {
		update Repo set require_signed_commits = required where id == repo_id
	}!
}

fn run_housekeeping_scheduler(conf config.Config) {
	for {
		mut app := App{
			db: connect_db(conf) or {
				time.sleep(time.hour)
				continue
			}
			config: conf
		}
		now := int(time.now().unix())
		repos := sql app.db {
			select from Repo where is_deleted == false order by id
		} or { []Repo{} }
		for repo in repos {
			state := app.repository_housekeeping(repo.id) or { RepoHousekeeping{} }
			if (state.is_running && state.last_started_at > now - 3600)
				|| state.last_completed_at > now - 7 * 86400 {
				continue
			}
			app.run_repository_housekeeping(repo) or {
				app.warn('Scheduled repository housekeeping failed for ${repo.id}: ${err}')
			}
			break
		}
		app.db.close() or {}
		time.sleep(time.hour)
	}
}
