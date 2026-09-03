// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import time
import veb

struct ScimUserView {
	id        int
	username  string
	full_name string
	active    bool
}

struct ScimTokenCreatedResponse {
	id    int
	token string
}

struct DirectoryProviderView {
	id            int
	kind          string
	name          string
	base_url      string
	issuer        string
	client_id     string
	configuration string
	enabled       bool
	created_by    int
	created_at    int
}

struct ScimTokenView {
	id          int
	provider_id int
	created_by  int
	created_at  int
	expires_at  int
	revoked     bool
}

fn scim_token_view(token ScimToken) ScimTokenView {
	return ScimTokenView{
		id: token.id
		provider_id: token.provider_id
		created_by: token.created_by
		created_at: token.created_at
		expires_at: token.expires_at
		revoked: token.revoked
	}
}

fn directory_provider_view(provider DirectoryProvider) DirectoryProviderView {
	return DirectoryProviderView{
		id: provider.id
		kind: provider.kind
		name: provider.name
		base_url: provider.base_url
		issuer: provider.issuer
		client_id: provider.client_id
		configuration: provider.configuration
		enabled: provider.enabled
		created_by: provider.created_by
		created_at: provider.created_at
	}
}

fn (mut app App) render_platform_admin(mut ctx Context, created_secret string) veb.Result {
	if !ctx.is_admin() {
		return ctx.redirect_to_index()
	}
	quotas := sql app.db {
		select from NamespaceQuota order by namespace
	} or { []NamespaceQuota{} }
	jobs := sql app.db {
		select from PlatformJob order by id desc limit 100
	} or { []PlatformJob{} }
	instances := sql app.db {
		select from InstanceHeartbeat order by last_seen_at desc
	} or { []InstanceHeartbeat{} }
	backups := sql app.db {
		select from InstanceBackup order by id desc limit 100
	} or { []InstanceBackup{} }
	providers := app.list_directory_providers()
	frameworks := app.list_compliance_frameworks()
	return $veb.html('templates/admin/platform.html')
}

@['/admin/platform']
pub fn (mut app App) platform_admin(mut ctx Context) veb.Result {
	return app.render_platform_admin(mut ctx, '')
}

@['/admin/platform/quotas'; post]
pub fn (mut app App) handle_admin_namespace_quota(mut ctx Context) veb.Result {
	if !ctx.is_admin() {
		return ctx.redirect_to_index()
	}
	app.set_namespace_quota(ctx.form['namespace'], ctx.form['max_repositories'].int(), ctx.form['max_storage_bytes'].i64(), ctx.user.id) or { ctx.error(err.msg()) }
	return app.render_platform_admin(mut ctx, '')
}

@['/admin/platform/providers'; post]
pub fn (mut app App) handle_admin_directory_provider(mut ctx Context) veb.Result {
	if !ctx.is_admin() {
		return ctx.redirect_to_index()
	}
	app.create_directory_provider(ctx.form['kind'], ctx.form['name'], ctx.form['base_url'], ctx.form['issuer'], ctx.form['client_id'], ctx.form['secret'], ctx.form['configuration'], ctx.user.id) or { ctx.error(err.msg()) }
	return app.render_platform_admin(mut ctx, '')
}

@['/admin/platform/providers/:id/scim-token'; post]
pub fn (mut app App) handle_admin_scim_token(mut ctx Context, id string) veb.Result {
	if !ctx.is_admin() {
		return ctx.redirect_to_index()
	}
	_, secret := app.create_scim_token(id.int(), ctx.user.id, ctx.form['expires_at'].int()) or {
		ctx.error(err.msg())
		return app.render_platform_admin(mut ctx, '')
	}
	return app.render_platform_admin(mut ctx, secret)
}

@['/admin/platform/frameworks'; post]
pub fn (mut app App) handle_admin_compliance_framework(mut ctx Context) veb.Result {
	if !ctx.is_admin() {
		return ctx.redirect_to_index()
	}
	app.add_compliance_framework(ctx.form['name'], ctx.form['description'], ctx.form['requirements'], ctx.user.id) or { ctx.error(err.msg()) }
	return app.render_platform_admin(mut ctx, '')
}

@['/admin/platform/backups'; post]
pub fn (mut app App) handle_admin_backup(mut ctx Context) veb.Result {
	if !ctx.is_admin() {
		return ctx.redirect_to_index()
	}
	app.create_instance_backup(ctx.user.id) or { ctx.error(err.msg()) }
	return app.render_platform_admin(mut ctx, '')
}

@['/health/live']
pub fn (mut app App) health_live(mut ctx Context) veb.Result {
	return ctx.json({
		'status':  'ok'
		'version': app.version
	})
}

@['/health/ready']
pub fn (mut app App) health_ready(mut ctx Context) veb.Result {
	app.get_users_count() or {
		return ctx.api_error_response(503, 'Service Unavailable', 'database is unavailable')
	}
	return ctx.json({
		'status':   'ready'
		'database': db_backend_name()
		'instance': resolved_instance_id(app.config)
	})
}

@['/api/v1/admin/platform/jobs']
pub fn (mut app App) api_v1_admin_jobs(mut ctx Context) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	jobs := sql app.db {
		select from PlatformJob order by id desc limit 500
	} or { []PlatformJob{} }
	return ctx.json(jobs)
}

@['/api/v1/admin/platform/jobs'; post]
pub fn (mut app App) api_v1_admin_enqueue_job(mut ctx Context) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	id := app.enqueue_platform_job(ctx.form['queue'], ctx.form['kind'], ctx.form['payload'], ctx.form['priority'].int(), ctx.form['run_after'].int(), ctx.form['max_attempts'].int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_platform_job(id) or { return ctx.api_not_found() })
}

@['/api/v1/admin/platform/quotas'; post]
pub fn (mut app App) api_v1_admin_set_quota(mut ctx Context) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	app.set_namespace_quota(ctx.form['namespace'], ctx.form['max_repositories'].int(), ctx.form['max_storage_bytes'].i64(), user.id) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_namespace_quota(ctx.form['namespace']) or { return ctx.api_not_found() })
}

@['/api/v1/admin/platform/backups'; post]
pub fn (mut app App) api_v1_admin_create_backup(mut ctx Context) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	backup := app.create_instance_backup(user.id) or {
		return ctx.api_error_response(500, 'Internal Server Error', err.msg())
	}
	app.record_audit_event('instance', 0, user.id, 'backup.create', 'backup', backup.id.str(), backup.checksum, ctx.ip())
	return ctx.json(backup)
}

@['/api/v1/admin/platform/backups/:id/verify']
pub fn (mut app App) api_v1_admin_verify_backup(mut ctx Context, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	valid := app.verify_instance_backup(id.int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json({
		'valid': valid
	})
}

@['/api/v1/admin/directory-providers'; post]
pub fn (mut app App) api_v1_admin_create_directory_provider(mut ctx Context) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	id := app.create_directory_provider(ctx.form['kind'], ctx.form['name'], ctx.form['base_url'], ctx.form['issuer'], ctx.form['client_id'], ctx.form['secret'], ctx.form['configuration'], user.id) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	provider := app.find_directory_provider(id) or { return ctx.api_not_found() }
	return ctx.json(directory_provider_view(provider))
}

@['/api/v1/admin/directory-providers']
pub fn (mut app App) api_v1_admin_directory_providers(mut ctx Context) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	return ctx.json(app.list_directory_providers().map(directory_provider_view(it)))
}

@['/api/v1/admin/directory-providers/:id/state'; post]
pub fn (mut app App) api_v1_admin_set_directory_provider_state(mut ctx Context,
	id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	app.set_directory_provider_enabled(id.int(), ctx.form['enabled'] != 'false', user.id) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	provider := app.find_directory_provider(id.int()) or { return ctx.api_not_found() }
	return ctx.json(directory_provider_view(provider))
}

@['/api/v1/admin/directory-providers/:id/scim-tokens'; post]
pub fn (mut app App) api_v1_admin_create_scim_token(mut ctx Context, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	token_id, secret := app.create_scim_token(id.int(), user.id, ctx.form['expires_at'].int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(ScimTokenCreatedResponse{
		id: token_id
		token: secret
	})
}

@['/api/v1/admin/directory-providers/:id/scim-tokens']
pub fn (mut app App) api_v1_admin_scim_tokens(mut ctx Context, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	app.find_directory_provider(id.int()) or { return ctx.api_not_found() }
	return ctx.json(app.list_scim_tokens(id.int()).map(scim_token_view(it)))
}

@['/api/v1/admin/directory-providers/:provider_id/scim-tokens/:token_id/revoke'; post]
pub fn (mut app App) api_v1_admin_revoke_scim_token(mut ctx Context, provider_id string,
	token_id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	app.revoke_scim_token(provider_id.int(), token_id.int(), user.id) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/scim/v2/Users'; post]
pub fn (mut app App) api_scim_create_user(mut ctx Context) veb.Result {
	secret := ctx.api_bearer_token()
	token := app.authenticate_scim_token(secret) or { return ctx.api_unauthorized() }
	if !app.consume_abuse_limit('scim', token.id.str(), 300, 60) {
		return ctx.api_error_response(429, 'Too Many Requests', 'rate limit exceeded')
	}
	provider := app.find_directory_provider(token.provider_id) or { return ctx.api_not_found() }
	user := app.provision_external_user(provider, ctx.form['external_id'], ctx.form['username'], ctx.form['display_name'], ctx.form['email'], ctx.form['active'] != 'false') or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(ScimUserView{
		id: user.id
		username: user.username
		full_name: user.full_name
		active: !user.is_blocked
	})
}

@['/api/v1/repos/:username/:repo_name/exports'; post]
pub fn (mut app App) api_v1_create_project_export(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	export := app.create_project_export(repo, user.id) or {
		return ctx.api_error_response(500, 'Internal Server Error', err.msg())
	}
	return ctx.json(export)
}

@['/api/v1/repos/:username/:repo_name/exports/:id/download']
pub fn (mut app App) api_v1_download_project_export(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	export := app.find_project_export(id.int()) or { return ctx.api_not_found() }
	if export.repo_id != repo.id || export.expires_at <= int(time.now().unix()) {
		return ctx.api_not_found()
	}
	data := app.load_platform_blob(export.bundle_blob_id) or { return ctx.api_not_found() }
	ctx.set_content_type('application/octet-stream')
	ctx.set_header(.content_disposition, 'attachment; filename="${repo.name}.bundle"')
	return ctx.ok(data.bytestr())
}

@['/api/v1/repos/:username/:repo_name/imports/:export_id'; post]
pub fn (mut app App) api_v1_import_project_export(mut ctx Context, username string,
	repo_name string, export_id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	target := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	export := app.find_project_export(export_id.int()) or { return ctx.api_not_found() }
	if export.expires_at <= int(time.now().unix()) {
		return ctx.api_not_found()
	}
	app.import_project_export(export, target, user.id) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/groups/:id/exports'; post]
pub fn (mut app App) api_v1_create_group_export(mut ctx Context, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	org := app.get_org_by_id(id.int()) or { return ctx.api_not_found() }
	export := app.create_group_export(org, user.id) or {
		return ctx.api_error_response(403, 'Forbidden', err.msg())
	}
	return ctx.json(export)
}

@['/api/v1/groups/:id/imports/:export_id'; post]
pub fn (mut app App) api_v1_import_group_export(mut ctx Context, id string,
	export_id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	target := app.get_org_by_id(id.int()) or { return ctx.api_not_found() }
	export := app.find_group_export(export_id.int()) or { return ctx.api_not_found() }
	if export.expires_at <= int(time.now().unix()) {
		return ctx.api_not_found()
	}
	app.import_group_export(export, target, user.id) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/admin/audit-events']
pub fn (mut app App) api_v1_admin_audit_events(mut ctx Context) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	ctx.set_content_type('application/json')
	return ctx.ok(app.export_audit_events('instance', 0, (ctx.query['after_id'] or { '0' }).int()))
}
