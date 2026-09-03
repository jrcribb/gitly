// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import veb
import validation
import git
import rand

struct ApiSshKeyView {
	id           int
	title        string
	key          string
	fingerprint  string
	usage_type   string
	expires_at   int
	last_used_at int
	last_used_ip string
	created_at   i64
}

struct ApiDeployKeyView {
	id                   int
	title                string
	key                  string
	fingerprint          string
	can_push             bool
	can_push_protected   bool
	protected_branch_ids []int
	enabled              bool
	expires_at           int
	last_used_at         int
	last_used_ip         string
	created_at           int
}

struct ApiMirrorView {
	id                   int
	direction            string
	url                  string
	enabled              bool
	overwrite_diverged   bool
	only_protected       bool
	interval_minutes     int
	last_update_at       int
	next_update_at       int
	last_error           string
	consecutive_failures int
	is_syncing           bool
	sync_started_at      int
}

struct ApiForkSyncView {
	updated []string
	skipped []string
}

@['/api/v1/repos/:username/:repo_name/pulls'; post]
pub fn (mut app App) api_v1_create_cross_repo_pull(mut ctx Context, username string, repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	target := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if !app.user_has_repo_read_access(user.id, target) {
		return ctx.api_not_found()
	}
	head_repo_id := if ctx.form['head_repo_id'].int() > 0 {
		ctx.form['head_repo_id'].int()
	} else {
		target.id
	}
	source := app.find_repo_by_id(head_repo_id) or { return ctx.api_not_found() }
	if !app.repos_share_fork_network(target.id, source.id)
		|| !app.user_has_repo_read_access(user.id, source) {
		return ctx.api_not_found()
	}
	title := ctx.form['title']
	description := ctx.form['description']
	head := ctx.form['head'].trim_space()
	base := ctx.form['base'].trim_space()
	if !valid_title(title) || !valid_body(description) || !is_safe_ref(head)
		|| !is_safe_ref(base) || (source.id == target.id && head == base)
		|| !app.contains_repo_branch(source.id, head)
		|| !app.contains_repo_branch(target.id, base) {
		return ctx.transport_api_error(400, 'Invalid merge request branches or content')
	}
	mut compare_ref := head
	if source.id != target.id {
		compare_ref = 'refs/gitly-comparisons/${user.id}/${source.id}/${rand.ulid()}'
		fetch_fork_branch_into(target, source, head, compare_ref) or {
			return ctx.transport_api_error(409, err.str())
		}
		defer {
			git.Git.exec_in_dir(target.git_dir, ['update-ref', '-d', compare_ref])
		}
	}
	if target.list_commits_between(base, compare_ref).len == 0 {
		return ctx.transport_api_error(409, 'No commits exist between base and head')
	}
	stored_source_id := if source.id == target.id { 0 } else { source.id }
	if app.pull_request_exists_for_source(target.id, stored_source_id, head) {
		return ctx.transport_api_error(409,
			'An open merge request already exists for this source branch')
	}
	pr_id := app.add_pull_request_from_repo(target.id, stored_source_id, user.id, title,
		description, head, base) or {
		return ctx.transport_api_error(500, 'Could not create merge request')
	}
	pr := app.find_pull_request_by_id(pr_id) or { return ctx.api_not_found() }
	app.refresh_cross_fork_pr_head(target, pr) or {
		app.set_pr_status(pr.id, .closed) or {}
		return ctx.transport_api_error(409, err.str())
	}
	app.increment_repo_open_prs(target.id) or {}
	app.dispatch_webhook(target.id, 'pr', WebhookPrPayload{
		action: 'opened'
		repo:   '${username}/${repo_name}'
		number: pr_id
		title:  title
		author: user.username
		head:   head
		base:   base
	})
	return ctx.json(app.pr_to_api(pr))
}

fn (key SshKey) to_api() ApiSshKeyView {
	return ApiSshKeyView{
		id:           key.id
		title:        key.title
		key:          key.key
		fingerprint:  key.fingerprint
		usage_type:   key.usage_type
		expires_at:   key.expires_at
		last_used_at: key.last_used_at
		last_used_ip: key.last_used_ip
		created_at:   key.created_at.unix()
	}
}

fn (app &App) deploy_key_to_api(key DeployKey) ApiDeployKeyView {
	protected_branch_ids := app.find_deploy_key_protected_branch_grants(key.repo_id,
		key.id).map(it.protected_branch_id)
	protected_branches := app.find_protected_branches(key.repo_id)
	return ApiDeployKeyView{
		id:                   key.id
		title:                key.title
		key:                  key.key
		fingerprint:          key.fingerprint
		can_push:             key.can_push
		// Compatibility field: true only when every current rule is granted.
		can_push_protected:   key.can_push && protected_branches.len > 0
			&& protected_branches.all(protected_branch_ids.contains(it.id))
		protected_branch_ids: protected_branch_ids
		enabled:              key.enabled
		expires_at:           key.expires_at
		last_used_at:         key.last_used_at
		last_used_ip:         key.last_used_ip
		created_at:           key.created_at
	}
}

fn (app &App) repo_deploy_keys_to_api(repo_id int) []ApiDeployKeyView {
	return app.find_repo_deploy_keys(repo_id).map(app.deploy_key_to_api(it))
}

fn (mirror RepoMirror) to_api() ApiMirrorView {
	return ApiMirrorView{
		id:                   mirror.id
		direction:            mirror.direction
		url:                  mirror.url
		enabled:              mirror.enabled
		overwrite_diverged:   mirror.overwrite_diverged
		only_protected:       mirror.only_protected
		interval_minutes:     mirror.interval_minutes
		last_update_at:       mirror.last_update_at
		next_update_at:       mirror.next_update_at
		last_error:           mirror.last_error
		consecutive_failures: mirror.consecutive_failures
		is_syncing:           mirror.is_syncing
		sync_started_at:      mirror.sync_started_at
	}
}

fn (mut ctx Context) transport_api_error(code int, message string) veb.Result {
	status_text := match code {
		400 { 'Bad Request' }
		401 { 'Unauthorized' }
		403 { 'Forbidden' }
		404 { 'Not Found' }
		409 { 'Conflict' }
		else { 'Internal Server Error' }
	}
	return ctx.api_error_response(code, status_text, message)
}

@['/api/v1/user/ssh-keys']
pub fn (mut app App) api_v1_user_ssh_keys(mut ctx Context) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	return ctx.json(app.find_ssh_keys(user.id).map(it.to_api()))
}

@['/api/v1/user/ssh-keys'; post]
pub fn (mut app App) api_v1_add_user_ssh_key(mut ctx Context) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	expires_value := ctx.form['expires_at'].trim_space()
	expires_at := parse_yyyy_mm_dd(expires_value)
	usage_type := ctx.form['usage_type'].trim_space()
	if !valid_short_name(ctx.form['title']) || ctx.form['key'].len > 16_384
		|| !is_valid_ssh_public_key(ctx.form['key'])
		|| !valid_ssh_usage_type(usage_type)
		|| (expires_value != '' && expires_at <= 0) {
		return ctx.transport_api_error(400, 'Invalid SSH key')
	}
	app.add_ssh_key(user.id, ctx.form['title'], ctx.form['key'], usage_type, expires_at) or {
		return ctx.transport_api_error(409, err.str())
	}
	keys := app.find_ssh_keys(user.id)
	return ctx.json(keys.first().to_api())
}

@['/api/v1/user/ssh-keys/:id'; 'delete']
pub fn (mut app App) api_v1_delete_user_ssh_key(mut ctx Context, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	key := app.find_ssh_key_by_id(id.int()) or { return ctx.api_not_found() }
	if key.user_id != user.id {
		return ctx.api_not_found()
	}
	app.remove_ssh_key(user.id, key.id) or {
		return ctx.transport_api_error(500, 'Could not delete SSH key')
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/deploy-keys']
pub fn (mut app App) api_v1_repo_deploy_keys(mut ctx Context, username string, repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.transport_api_error(403, 'Maintainer access is required')
	}
	return ctx.json(app.repo_deploy_keys_to_api(repo.id))
}

@['/api/v1/repos/:username/:repo_name/deploy-keys'; post]
pub fn (mut app App) api_v1_add_repo_deploy_key(mut ctx Context, username string, repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.transport_api_error(403, 'Maintainer access is required')
	}
	expires_value := ctx.form['expires_at'].trim_space()
	expires_at := parse_yyyy_mm_dd(expires_value)
	if !valid_short_name(ctx.form['title']) || ctx.form['key'].len > 16_384
		|| !is_valid_ssh_public_key(ctx.form['key'])
		|| (expires_value != '' && expires_at <= 0) {
		return ctx.transport_api_error(400, 'Invalid deploy key')
	}
	can_push := ctx.form['can_push'] == 'true' || ctx.form['can_push'] == '1'
	if ctx.form['can_push_protected'] in ['true', '1'] {
		return ctx.transport_api_error(400,
			'Protected branch access must be granted to an explicit protected branch rule')
	}
	app.add_deploy_key(repo.id, user.id, ctx.form['title'], ctx.form['key'], can_push,
		expires_at) or { return ctx.transport_api_error(409, err.str()) }
	keys := app.find_repo_deploy_keys(repo.id)
	return ctx.json(app.deploy_key_to_api(keys.first()))
}

@['/api/v1/repos/:username/:repo_name/deploy-keys/:key_id/protected-branches/:rule_id'; post]
pub fn (mut app App) api_v1_grant_deploy_key_protected_branch(mut ctx Context, username string,
	repo_name string, key_id string, rule_id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.transport_api_error(403, 'Maintainer access is required')
	}
	app.grant_deploy_key_protected_branch(repo.id, key_id.int(), rule_id.int(), user.id) or {
		return ctx.transport_api_error(400, err.str())
	}
	key := app.find_deploy_key_by_id(key_id.int()) or { return ctx.api_not_found() }
	return ctx.json(app.deploy_key_to_api(key))
}

@['/api/v1/repos/:username/:repo_name/deploy-keys/:key_id/protected-branches/:rule_id'; 'delete']
pub fn (mut app App) api_v1_revoke_deploy_key_protected_branch(mut ctx Context, username string,
	repo_name string, key_id string, rule_id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.transport_api_error(403, 'Maintainer access is required')
	}
	key := app.find_deploy_key_by_id(key_id.int()) or { return ctx.api_not_found() }
	rule := app.find_protected_branch_by_id(repo.id, rule_id.int()) or {
		return ctx.api_not_found()
	}
	if key.repo_id != repo.id {
		return ctx.api_not_found()
	}
	app.revoke_deploy_key_protected_branch(repo.id, key.id, rule.id) or {
		return ctx.transport_api_error(500, 'Could not revoke protected branch grant')
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/deploy-keys/:id'; 'delete']
pub fn (mut app App) api_v1_delete_repo_deploy_key(mut ctx Context, username string, repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.transport_api_error(403, 'Maintainer access is required')
	}
	key := app.find_deploy_key_by_id(id.int()) or { return ctx.api_not_found() }
	if key.repo_id != repo.id {
		return ctx.api_not_found()
	}
	app.remove_deploy_key(repo.id, key.id) or {
		return ctx.transport_api_error(500, 'Could not delete deploy key')
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/forks']
pub fn (mut app App) api_v1_repo_forks(mut ctx Context, username string, repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	visible := app.find_repo_forks(repo.id).filter(it.is_public
		|| app.user_has_repo_read_access(caller.id, it))
	return ctx.json(visible.map(app.repo_to_api(it)))
}

@['/api/v1/repos/:username/:repo_name/forks'; post]
pub fn (mut app App) api_v1_create_repo_fork(mut ctx Context, username string, repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	source := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if !app.user_has_repo_read_access(user.id, source) {
		return ctx.api_not_found()
	}
	requested_namespace := ctx.form['namespace'].trim_space()
	mut owner_name := user.username
	if requested_namespace != '' && requested_namespace != user.username {
		org := app.get_org_by_name(requested_namespace) or { return ctx.api_not_found() }
		if (app.org_member_role(org.id, user.id) or { '' }) != 'admin' {
			return ctx.api_not_found()
		}
		owner_name = org.name
	}
	name := if ctx.form['name'].trim_space() == '' {
		source.name
	} else {
		ctx.form['name'].trim_space()
	}
	if !validation.is_repository_name_valid(name) || name.len > max_repo_name_len {
		return ctx.transport_api_error(400, 'Invalid fork name')
	}
	if _ := app.find_repo_by_name_and_username(name, owner_name) {
		return ctx.transport_api_error(409, 'A repository with that name already exists')
	}
	if app.namespace_has_fork_in_network(source.id, owner_name) {
		return ctx.transport_api_error(409,
			'The destination namespace already contains a repository in this fork network')
	}
	if owner_name == user.username && !user.is_admin
		&& app.get_count_user_repos(user.id) >= max_user_repos {
		return ctx.transport_api_error(409, 'Repository limit reached')
	}
	is_public := ctx.form['visibility'] != 'private' && source.is_public
	created := app.create_fork(source, owner_name, user.id, name, source.description, is_public,

		ctx.form['default_branch_only'] == 'true' || ctx.form['default_branch_only'] == '1',
		user.id) or { return ctx.transport_api_error(500, err.str()) }
	return ctx.json(app.repo_to_api(created))
}

@['/api/v1/repos/:username/:repo_name/fork/sync'; post]
pub fn (mut app App) api_v1_sync_repo_fork(mut ctx Context, username string, repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.transport_api_error(403, 'Maintainer access is required')
	}
	relation := app.find_fork_by_repo(repo.id) or { return ctx.api_not_found() }
	source := app.find_repo_by_id(relation.source_repo_id) or { return ctx.api_not_found() }
	if !app.user_has_repo_read_access(user.id, source) {
		return ctx.api_not_found()
	}
	result := app.sync_fork(repo, relation, ctx.form['default_branch_only'] == 'true') or {
		return ctx.transport_api_error(409, err.str())
	}
	return ctx.json(ApiForkSyncView{
		updated: result.updated
		skipped: result.skipped
	})
}

@['/api/v1/repos/:username/:repo_name/mirrors']
pub fn (mut app App) api_v1_repo_mirrors(mut ctx Context, username string, repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.transport_api_error(403, 'Maintainer access is required')
	}
	return ctx.json(app.list_repo_mirrors(repo.id).map(it.to_api()))
}

@['/api/v1/repos/:username/:repo_name/mirrors'; post]
pub fn (mut app App) api_v1_add_repo_mirror(mut ctx Context, username string, repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.transport_api_error(403, 'Maintainer access is required')
	}
	mirror_id := app.add_repo_mirror(repo.id, user.id, ctx.form['url'],
		ctx.form['mirror_username'], ctx.form['mirror_password'], ctx.form['ssh_private_key'],
		ctx.form['ssh_known_hosts'], ctx.form['direction'],
		ctx.form['overwrite_diverged'] == 'true', ctx.form['only_protected'] == 'true',
		ctx.form['interval_minutes'].int()) or { return ctx.transport_api_error(400, err.str()) }
	mirror := app.find_repo_mirror(mirror_id) or { return ctx.api_not_found() }
	return ctx.json(mirror.to_api())
}

@['/api/v1/repos/:username/:repo_name/mirrors/:id/sync'; post]
pub fn (mut app App) api_v1_sync_repo_mirror(mut ctx Context, username string, repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.transport_api_error(403, 'Maintainer access is required')
	}
	mirror := app.find_repo_mirror(id.int()) or { return ctx.api_not_found() }
	if mirror.repo_id != repo.id {
		return ctx.api_not_found()
	}
	app.sync_repo_mirror(mirror, false) or { return ctx.transport_api_error(409, err.str()) }
	updated := app.find_repo_mirror(mirror.id) or { return ctx.api_not_found() }
	return ctx.json(updated.to_api())
}

@['/api/v1/repos/:username/:repo_name/mirrors/:id/state'; post]
pub fn (mut app App) api_v1_set_repo_mirror_state(mut ctx Context, username string, repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.transport_api_error(403, 'Maintainer access is required')
	}
	mirror := app.find_repo_mirror(id.int()) or { return ctx.api_not_found() }
	if mirror.repo_id != repo.id {
		return ctx.api_not_found()
	}
	raw_enabled := ctx.form['enabled'].trim_space().to_lower()
	if raw_enabled !in ['true', 'false', '1', '0'] {
		return ctx.transport_api_error(400, 'enabled must be true or false')
	}
	enabled := raw_enabled in ['true', '1']
	app.set_repo_mirror_enabled(repo.id, mirror.id, enabled) or {
		return ctx.transport_api_error(409, err.str())
	}
	updated := app.find_repo_mirror(mirror.id) or { return ctx.api_not_found() }
	return ctx.json(updated.to_api())
}

@['/api/v1/repos/:username/:repo_name/mirrors/:id'; 'delete']
pub fn (mut app App) api_v1_delete_repo_mirror(mut ctx Context, username string, repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.transport_api_error(403, 'Maintainer access is required')
	}
	mirror := app.find_repo_mirror(id.int()) or { return ctx.api_not_found() }
	if mirror.repo_id != repo.id {
		return ctx.api_not_found()
	}
	app.delete_repo_mirror(repo.id, mirror.id) or {
		return ctx.transport_api_error(500, 'Could not delete mirror')
	}
	return ctx.api_success_response()
}
