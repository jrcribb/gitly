// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import veb

struct ApiLabelView {
	id    int
	name  string
	color string
}

fn (label Label) to_api() ApiLabelView {
	return ApiLabelView{
		id: label.id
		name: label.name
		color: '#${label.color}'
	}
}

fn (app &App) user_can_manage_labels(user_id int, repo Repo) bool {
	return app.repo_access_level(user_id, repo) >= project_access_reporter
}

@['/:username/:repo_name/labels']
pub fn (mut app App) repo_labels(mut ctx Context, username string, repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_read_repo(ctx, repo) {
		return ctx.not_found()
	}
	labels := app.list_repo_labels(repo.id)
	can_manage := ctx.logged_in && app.user_can_manage_labels(ctx.user.id, repo)
	ctx.set_page_title(['Labels', '${repo.user_name}/${repo.name}'])
	return $veb.html('templates/labels.html')
}

@['/:username/:repo_name/labels'; post]
pub fn (mut app App) handle_add_repo_label(mut ctx Context, username string, repo_name string) veb.Result {
	if !ctx.logged_in {
		return ctx.redirect_to_login()
	}
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_read_repo(ctx, repo) || !app.user_can_manage_labels(ctx.user.id, repo) {
		return ctx.not_found()
	}
	app.add_repo_label(repo.id, ctx.form['name'], ctx.form['color']) or {
		ctx.error(err.msg())
		return app.repo_labels(mut ctx, username, repo_name)
	}
	return ctx.redirect('/${username}/${repo_name}/labels')
}

@['/:username/:repo_name/labels/:id'; post]
pub fn (mut app App) handle_update_repo_label(mut ctx Context, username string, repo_name string, id string) veb.Result {
	if !ctx.logged_in {
		return ctx.redirect_to_login()
	}
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_read_repo(ctx, repo) || !app.user_can_manage_labels(ctx.user.id, repo) {
		return ctx.not_found()
	}
	app.update_repo_label(repo.id, id.int(), ctx.form['name'], ctx.form['color']) or {
		ctx.error(err.msg())
		return app.repo_labels(mut ctx, username, repo_name)
	}
	return ctx.redirect('/${username}/${repo_name}/labels')
}

@['/:username/:repo_name/labels/:id/delete'; post]
pub fn (mut app App) handle_delete_repo_label(mut ctx Context, username string, repo_name string, id string) veb.Result {
	if !ctx.logged_in {
		return ctx.redirect_to_login()
	}
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_read_repo(ctx, repo) || !app.user_can_manage_labels(ctx.user.id, repo) {
		return ctx.not_found()
	}
	app.delete_repo_label(repo.id, id.int()) or {
		ctx.error('Could not delete that label')
		return app.repo_labels(mut ctx, username, repo_name)
	}
	return ctx.redirect('/${username}/${repo_name}/labels')
}

@['/api/v1/repos/:username/:repo_name/labels']
pub fn (mut app App) api_v1_repo_labels(mut ctx Context, username string, repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.list_repo_labels(repo.id).map(it.to_api()))
}

@['/api/v1/repos/:username/:repo_name/labels'; post]
pub fn (mut app App) api_v1_add_repo_label(mut ctx Context, username string, repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if !app.user_has_repo_read_access(user.id, repo) {
		return ctx.api_not_found()
	}
	if !app.user_can_manage_labels(user.id, repo) {
		return ctx.api_error_response(403, 'Forbidden', 'Reporter access is required')
	}
	id := app.add_repo_label(repo.id, ctx.form['name'], ctx.form['color']) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	label := app.find_repo_label_by_id(repo.id, id) or { return ctx.api_not_found() }
	return ctx.json(label.to_api())
}

@['/api/v1/repos/:username/:repo_name/labels/:id'; post]
pub fn (mut app App) api_v1_update_repo_label(mut ctx Context, username string, repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if !app.user_has_repo_read_access(user.id, repo) {
		return ctx.api_not_found()
	}
	if !app.user_can_manage_labels(user.id, repo) {
		return ctx.api_error_response(403, 'Forbidden', 'Reporter access is required')
	}
	label := app.find_repo_label_by_id(repo.id, id.int()) or { return ctx.api_not_found() }
	app.update_repo_label(repo.id, label.id, ctx.form['name'], ctx.form['color']) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	updated := app.find_repo_label_by_id(repo.id, label.id) or { return ctx.api_not_found() }
	return ctx.json(updated.to_api())
}

@['/api/v1/repos/:username/:repo_name/labels/:id/delete'; post]
pub fn (mut app App) api_v1_delete_repo_label(mut ctx Context, username string, repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	if !app.user_has_repo_read_access(user.id, repo) {
		return ctx.api_not_found()
	}
	if !app.user_can_manage_labels(user.id, repo) {
		return ctx.api_error_response(403, 'Forbidden', 'Reporter access is required')
	}
	label := app.find_repo_label_by_id(repo.id, id.int()) or { return ctx.api_not_found() }
	app.delete_repo_label(repo.id, label.id) or {
		return ctx.api_error_response(500, 'Internal Server Error', 'failed to delete label')
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/issues/:id/labels'; post]
pub fn (mut app App) api_v1_add_issue_label(mut ctx Context, username string, repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	issue := app.find_issue_by_id(id.int()) or { return ctx.api_not_found() }
	label := app.find_repo_label_by_id(repo.id, ctx.form['label_id'].int()) or {
		return ctx.api_not_found()
	}
	if issue.repo_id != repo.id || issue.is_pr || !app.user_has_repo_read_access(user.id, repo) {
		return ctx.api_not_found()
	}
	if !app.issue_user_can_manage(user.id, repo, issue) {
		return ctx.api_error_response(403, 'Forbidden', 'permission to manage the issue is required')
	}
	app.add_issue_label(issue.id, label.id) or {
		return ctx.api_error_response(500, 'Internal Server Error', 'failed to add issue label')
	}
	updated := app.find_issue_by_id(issue.id) or { return ctx.api_not_found() }
	return ctx.json(app.issue_to_api(updated))
}

@['/api/v1/repos/:username/:repo_name/issues/:id/labels/:label_id/delete'; post]
pub fn (mut app App) api_v1_remove_issue_label(mut ctx Context, username string, repo_name string, id string, label_id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or {
		return ctx.api_not_found()
	}
	issue := app.find_issue_by_id(id.int()) or { return ctx.api_not_found() }
	label := app.find_repo_label_by_id(repo.id, label_id.int()) or { return ctx.api_not_found() }
	if issue.repo_id != repo.id || issue.is_pr || !app.user_has_repo_read_access(user.id, repo) {
		return ctx.api_not_found()
	}
	if !app.issue_user_can_manage(user.id, repo, issue) {
		return ctx.api_error_response(403, 'Forbidden', 'permission to manage the issue is required')
	}
	app.remove_issue_label(issue.id, label.id) or {
		return ctx.api_error_response(500, 'Internal Server Error', 'failed to remove issue label')
	}
	updated := app.find_issue_by_id(issue.id) or { return ctx.api_not_found() }
	return ctx.json(app.issue_to_api(updated))
}
