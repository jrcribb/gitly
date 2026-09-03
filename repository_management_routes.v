// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import veb

struct ApiDeployTokenCreated {
	id         int
	name       string
	username   string
	token      string
	scopes     []string
	expires_at int
}

struct ApiDeployTokenView {
	id           int
	name         string
	username     string
	scopes       []string
	expires_at   int
	revoked      bool
	created_at   int
	last_used_at int
	last_used_ip string
}

struct ApiProtectedTagView {
	id            int
	pattern       string
	create_access int
}

struct ApiSnippetView {
	id          int
	title       string
	description string
	file_name   string
	content     string
	author_id   int
	is_public   bool
	created_at  int
	updated_at  int
}

fn requested_deploy_token_scopes(form map[string]string) []string {
	mut scopes := []string{}
	for scope in [deploy_token_scope_read_repository, deploy_token_scope_write_repository,
		deploy_token_scope_read_lfs, deploy_token_scope_write_lfs] {
		if scope in form {
			scopes << scope
		}
	}
	return scopes
}

fn snippet_to_api(snippet Snippet) ApiSnippetView {
	return ApiSnippetView{
		id: snippet.id
		title: snippet.title
		description: snippet.description
		file_name: snippet.file_name
		content: snippet.content
		author_id: snippet.author_id
		is_public: snippet.is_public
		created_at: snippet.created_at
		updated_at: snippet.updated_at
	}
}

fn deploy_token_to_api(token DeployToken) ApiDeployTokenView {
	return ApiDeployTokenView{
		id: token.id
		name: token.name
		username: token.username
		scopes: token.scopes.split(',').map(it.trim_space()).filter(it != '')
		expires_at: token.expires_at
		revoked: token.revoked
		created_at: token.created_at
		last_used_at: token.last_used_at
		last_used_ip: token.last_used_ip
	}
}

fn (mut app App) render_repository_management(mut ctx Context, username string, repo_name string,
	created_username string, created_secret string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	deploy_tokens := app.find_repo_deploy_tokens(repo.id)
	protected_tags := app.find_protected_tags(repo.id)
	housekeeping := app.repository_housekeeping(repo.id) or { RepoHousekeeping{} }
	return $veb.html('templates/repo/repository_management.html')
}

@['/:username/:repo_name/settings/repository-management']
pub fn (mut app App) repository_management_settings(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	return app.render_repository_management(mut ctx, username, repo_name, '', '')
}

@['/:username/:repo_name/settings/deploy-tokens'; post]
pub fn (mut app App) handle_add_deploy_token(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	expires_at := parse_yyyy_mm_dd(ctx.form['expires_at'])
	_, token_username, secret := app.add_deploy_token(repo.id, ctx.user.id, ctx.form['name'], requested_deploy_token_scopes(ctx.form), expires_at) or {
		ctx.error(err.msg())
		return app.render_repository_management(mut ctx, username, repo_name, '', '')
	}
	return app.render_repository_management(mut ctx, username, repo_name, token_username, secret)
}

@['/:username/:repo_name/settings/deploy-tokens/:id/revoke'; post]
pub fn (mut app App) handle_revoke_deploy_token(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	app.revoke_deploy_token(repo.id, id.int()) or { ctx.error(err.msg()) }
	return ctx.redirect('/${username}/${repo_name}/settings/repository-management')
}

@['/:username/:repo_name/settings/protected-tags'; post]
pub fn (mut app App) handle_protect_tag(mut ctx Context, username string, repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	app.protect_tag(repo.id, ctx.form['pattern'], ctx.form['create_access'].int()) or {
		ctx.error(err.msg())
		return app.render_repository_management(mut ctx, username, repo_name, '', '')
	}
	return ctx.redirect('/${username}/${repo_name}/settings/repository-management')
}

@['/:username/:repo_name/settings/protected-tags/:id/delete'; post]
pub fn (mut app App) handle_unprotect_tag(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	app.unprotect_tag(repo.id, id.int()) or { ctx.error(err.msg()) }
	return ctx.redirect('/${username}/${repo_name}/settings/repository-management')
}

@['/:username/:repo_name/settings/signed-commits'; post]
pub fn (mut app App) handle_signed_commit_policy(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	app.set_signed_commit_policy(repo.id, 'required' in ctx.form) or { ctx.error(err.msg()) }
	app.ensure_protected_branch_hook(repo) or { ctx.error(err.msg()) }
	return ctx.redirect('/${username}/${repo_name}/settings/repository-management')
}

@['/:username/:repo_name/settings/housekeeping'; post]
pub fn (mut app App) handle_repository_housekeeping(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	app.run_repository_housekeeping(repo) or { ctx.error(err.msg()) }
	return app.render_repository_management(mut ctx, username, repo_name, '', '')
}

@['/:username/:repo_name/snippets']
pub fn (mut app App) repo_snippets(mut ctx Context, username string, repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_read_repo(ctx, repo) {
		return ctx.not_found()
	}
	viewer_id := if ctx.logged_in { ctx.user.id } else { 0 }
	snippets := app.find_repo_snippets(repo.id).filter(app.user_can_read_snippet(viewer_id, repo, it))
	can_create := ctx.logged_in && app.repo_access_level(ctx.user.id, repo) >= project_access_developer
	return $veb.html('templates/snippets.html')
}

@['/:username/:repo_name/snippets'; post]
pub fn (mut app App) handle_add_snippet(mut ctx Context, username string, repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_developer {
		return ctx.not_found()
	}
	id := app.add_snippet(repo.id, ctx.user.id, ctx.form['title'], ctx.form['description'], ctx.form['file_name'], ctx.form['content'], ctx.form['visibility'] == 'public') or {
		ctx.error(err.msg())
		return app.repo_snippets(mut ctx, username, repo_name)
	}
	return ctx.redirect('/${username}/${repo_name}/snippets/${id}')
}

@['/:username/:repo_name/snippets/:id']
pub fn (mut app App) repo_snippet(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_read_repo(ctx, repo) {
		return ctx.not_found()
	}
	snippet := app.find_snippet(repo.id, id.int()) or { return ctx.not_found() }
	viewer_id := if ctx.logged_in { ctx.user.id } else { 0 }
	if !app.user_can_read_snippet(viewer_id, repo, snippet) {
		return ctx.not_found()
	}
	can_edit := ctx.logged_in && (snippet.author_id == ctx.user.id
		|| app.repo_access_level(ctx.user.id, repo) >= project_access_maintainer)
	return $veb.html('templates/snippet.html')
}

@['/:username/:repo_name/snippets/:id'; post]
pub fn (mut app App) handle_update_snippet(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	snippet := app.find_snippet(repo.id, id.int()) or { return ctx.not_found() }
	if !ctx.logged_in || (snippet.author_id != ctx.user.id
		&& app.repo_access_level(ctx.user.id, repo) < project_access_maintainer) {
		return ctx.not_found()
	}
	app.update_snippet(repo.id, snippet.id, ctx.form['title'], ctx.form['description'], ctx.form['file_name'], ctx.form['content'], ctx.form['visibility'] == 'public') or {
		ctx.error(err.msg())
		return app.repo_snippet(mut ctx, username, repo_name, id)
	}
	return ctx.redirect('/${username}/${repo_name}/snippets/${id}')
}

@['/:username/:repo_name/snippets/:id/delete'; post]
pub fn (mut app App) handle_delete_snippet(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	snippet := app.find_snippet(repo.id, id.int()) or { return ctx.not_found() }
	if !ctx.logged_in || (snippet.author_id != ctx.user.id
		&& app.repo_access_level(ctx.user.id, repo) < project_access_maintainer) {
		return ctx.not_found()
	}
	app.delete_snippet(repo.id, snippet.id) or { return ctx.server_error(err.msg()) }
	return ctx.redirect('/${username}/${repo_name}/snippets')
}

@['/api/v1/repos/:username/:repo_name/deploy-tokens'; post]
pub fn (mut app App) api_v1_add_deploy_token(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	expires_at := parse_yyyy_mm_dd(ctx.form['expires_at'])
	scopes := requested_deploy_token_scopes(ctx.form)
	id, token_username, secret := app.add_deploy_token(repo.id, user.id, ctx.form['name'], scopes, expires_at) or { return ctx.api_error_response(400, 'Bad Request', err.msg()) }
	return ctx.json(ApiDeployTokenCreated{
		id: id
		name: ctx.form['name'].trim_space()
		username: token_username
		token: secret
		scopes: scopes
		expires_at: expires_at
	})
}

@['/api/v1/repos/:username/:repo_name/deploy-tokens']
pub fn (mut app App) api_v1_deploy_tokens(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	return ctx.json(app.find_repo_deploy_tokens(repo.id).map(deploy_token_to_api(it)))
}

@['/api/v1/repos/:username/:repo_name/deploy-tokens/:id/revoke'; post]
pub fn (mut app App) api_v1_revoke_deploy_token(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	app.revoke_deploy_token(repo.id, id.int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/protected-tags']
pub fn (mut app App) api_v1_protected_tags(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if !app.user_has_repo_read_access(user.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.find_protected_tags(repo.id).map(ApiProtectedTagView{
		id: it.id
		pattern: it.pattern
		create_access: it.create_access
	}))
}

@['/api/v1/repos/:username/:repo_name/protected-tags'; post]
pub fn (mut app App) api_v1_protect_tag(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	pattern := ctx.form['pattern'].trim_space()
	access := ctx.form['create_access'].int()
	id := app.protect_tag(repo.id, pattern, access) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(ApiProtectedTagView{
		id: id
		pattern: pattern
		create_access: access
	})
}

@['/api/v1/repos/:username/:repo_name/protected-tags/:id/delete'; post]
pub fn (mut app App) api_v1_unprotect_tag(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	app.find_protected_tag_by_id(repo.id, id.int()) or { return ctx.api_not_found() }
	app.unprotect_tag(repo.id, id.int()) or {
		return ctx.api_error_response(500, 'Internal Server Error', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/snippets']
pub fn (mut app App) api_v1_snippets(mut ctx Context, username string, repo_name string) veb.Result {
	caller := app.api_user_from_ctx(ctx) or { User{} }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	visible := app.find_repo_snippets(repo.id).filter(app.user_can_read_snippet(caller.id, repo, it))
	return ctx.json(visible.map(snippet_to_api(it)))
}

@['/api/v1/repos/:username/:repo_name/snippets'; post]
pub fn (mut app App) api_v1_add_snippet(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_developer {
		return ctx.api_error_response(403, 'Forbidden', 'Developer access is required')
	}
	id := app.add_snippet(repo.id, user.id, ctx.form['title'], ctx.form['description'], ctx.form['file_name'], ctx.form['content'], ctx.form['visibility'] == 'public') or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(snippet_to_api(app.find_snippet(repo.id, id) or { return ctx.api_not_found() }))
}

@['/api/v1/repos/:username/:repo_name/snippets/:id'; post]
pub fn (mut app App) api_v1_update_snippet(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	snippet := app.find_snippet(repo.id, id.int()) or { return ctx.api_not_found() }
	if snippet.author_id != user.id && app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'snippet author or Maintainer access is required')
	}
	app.update_snippet(repo.id, snippet.id, ctx.form['title'], ctx.form['description'], ctx.form['file_name'], ctx.form['content'], ctx.form['visibility'] == 'public') or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(snippet_to_api(app.find_snippet(repo.id, snippet.id) or {
		return ctx.api_not_found()
	}))
}

@['/api/v1/repos/:username/:repo_name/snippets/:id/delete'; post]
pub fn (mut app App) api_v1_delete_snippet(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	snippet := app.find_snippet(repo.id, id.int()) or { return ctx.api_not_found() }
	if snippet.author_id != user.id && app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'snippet author or Maintainer access is required')
	}
	app.delete_snippet(repo.id, snippet.id) or {
		return ctx.api_error_response(500, 'Internal Server Error', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/housekeeping'; post]
pub fn (mut app App) api_v1_repository_housekeeping(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	result := app.run_repository_housekeeping(repo) or {
		return ctx.api_error_response(500, 'Internal Server Error', err.msg())
	}
	return ctx.json(result)
}

@['/api/v1/repos/:username/:repo_name/commits/:hash/signature']
pub fn (mut app App) api_v1_commit_signature(mut ctx Context, username string, repo_name string,
	hash string) veb.Result {
	caller := app.api_user_from_ctx(ctx) or { User{} }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.verify_commit_ssh_signature(repo, hash))
}

@['/api/v1/repos/:username/:repo_name/releases'; post]
pub fn (mut app App) api_v1_publish_release(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	release := app.publish_release(repo, ctx.form['tag_name'].trim_space(), ctx.form['notes'], user.id) or { return ctx.api_error_response(400, 'Bad Request', err.msg()) }
	return ctx.json(release)
}

@['/api/v1/repos/:username/:repo_name/releases/:id/delete'; post]
pub fn (mut app App) api_v1_delete_release(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	app.remove_published_release(repo, id.int(), user.id) or {
		return ctx.api_error_response(403, 'Forbidden', err.msg())
	}
	return ctx.api_success_response()
}
