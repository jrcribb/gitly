// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import veb

fn (mut app App) group_dashboard(mut ctx Context, org_id int) veb.Result {
	if !ctx.logged_in || !app.user_can_read_group(ctx.user.id, org_id) {
		return ctx.not_found()
	}
	group := app.get_org_by_id(org_id) or { return ctx.not_found() }
	subgroups := app.find_subgroups(group.id)
	epics := app.find_group_epics(group.id)
	iterations := app.find_group_iterations(group.id)
	can_admin := app.user_can_admin_group(ctx.user.id, group.id)
	return $veb.html('templates/group.html')
}

@['/groups/:id']
pub fn (mut app App) view_group(mut ctx Context, id string) veb.Result {
	return app.group_dashboard(mut ctx, id.int())
}

@['/groups/:id/subgroups'; post]
pub fn (mut app App) handle_add_subgroup(mut ctx Context, id string) veb.Result {
	if !ctx.logged_in || !app.user_can_admin_group(ctx.user.id, id.int()) {
		return ctx.not_found()
	}
	app.add_subgroup(id.int(), ctx.form['path'], ctx.form['display_name'], ctx.user.id) or {
		ctx.error(err.msg())
	}
	return app.group_dashboard(mut ctx, id.int())
}

@['/groups/:id/epics'; post]
pub fn (mut app App) handle_add_epic(mut ctx Context, id string) veb.Result {
	if !ctx.logged_in || !app.user_can_admin_group(ctx.user.id, id.int()) {
		return ctx.not_found()
	}
	app.add_epic(id.int(), ctx.form['parent_epic_id'].int(), ctx.user.id, ctx.form['title'], ctx.form['description'], parse_yyyy_mm_dd(ctx.form['starts_at']), parse_yyyy_mm_dd(ctx.form['due_at'])) or { ctx.error(err.msg()) }
	return app.group_dashboard(mut ctx, id.int())
}

@['/groups/:id/roadmap']
pub fn (mut app App) group_roadmap(mut ctx Context, id string) veb.Result {
	if !ctx.logged_in || !app.user_can_read_group(ctx.user.id, id.int()) {
		return ctx.not_found()
	}
	group := app.get_org_by_id(id.int()) or { return ctx.not_found() }
	epics := app.find_group_epics(group.id).filter(it.state == 'open')
	iterations := app.find_group_iterations(group.id)
	return $veb.html('templates/roadmap.html')
}

@['/groups/:id/epics/:epic_id/issues'; post]
pub fn (mut app App) handle_add_epic_issue(mut ctx Context, id string,
	epic_id string) veb.Result {
	if !ctx.logged_in || !app.user_can_admin_group(ctx.user.id, id.int()) {
		return ctx.not_found()
	}
	epic := app.find_epic(epic_id.int()) or { return ctx.not_found() }
	if epic.org_id != id.int() {
		return ctx.not_found()
	}
	app.add_issue_to_epic(epic.id, ctx.form['issue_id'].int()) or { ctx.error(err.msg()) }
	return app.group_dashboard(mut ctx, id.int())
}

@['/groups/:id/iterations'; post]
pub fn (mut app App) handle_add_iteration(mut ctx Context, id string) veb.Result {
	if !ctx.logged_in || !app.user_can_admin_group(ctx.user.id, id.int()) {
		return ctx.not_found()
	}
	app.add_iteration(id.int(), ctx.form['title'], ctx.form['description'], parse_yyyy_mm_dd(ctx.form['starts_at']), parse_yyyy_mm_dd(ctx.form['due_at'])) or {
		ctx.error(err.msg())
	}
	return app.group_dashboard(mut ctx, id.int())
}

fn (mut app App) issue_for_planning_action(ctx Context, username string, repo_name string,
	id int) ?(Repo, Issue) {
	if !ctx.logged_in {
		return none
	}
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return none }
	mut issue := app.find_issue_by_id(id) or { return none }
	if issue.repo_id != repo.id || issue.is_pr {
		return none
	}
	issue.assigned = app.find_issue_assignees(issue).map(it.id)
	if !app.issue_user_can_manage(ctx.user.id, repo, issue) {
		return none
	}
	return repo, issue
}

@['/:username/:repo_name/issue/:id/tasks'; post]
pub fn (mut app App) handle_add_issue_task(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	_, issue := app.issue_for_planning_action(ctx, username, repo_name, id.int()) or {
		return ctx.not_found()
	}
	app.add_issue_task(issue.id, ctx.user.id, ctx.form['title']) or { ctx.error(err.msg()) }
	return ctx.redirect('/${username}/${repo_name}/issue/${id}')
}

@['/:username/:repo_name/issue/:id/tasks/:task_id/toggle'; post]
pub fn (mut app App) handle_toggle_issue_task(mut ctx Context, username string, repo_name string,
	id string, task_id string) veb.Result {
	_, issue := app.issue_for_planning_action(ctx, username, repo_name, id.int()) or {
		return ctx.not_found()
	}
	task := app.find_issue_tasks(issue.id).filter(it.id == task_id.int())
	if task.len != 1 {
		return ctx.not_found()
	}
	app.set_issue_task_completed(issue.id, task.first().id, !task.first().completed) or {
		ctx.error(err.msg())
	}
	return ctx.redirect('/${username}/${repo_name}/issue/${id}')
}

@['/:username/:repo_name/issue/:id/tasks/:task_id/delete'; post]
pub fn (mut app App) handle_delete_issue_task(mut ctx Context, username string, repo_name string,
	id string, task_id string) veb.Result {
	_, issue := app.issue_for_planning_action(ctx, username, repo_name, id.int()) or {
		return ctx.not_found()
	}
	app.delete_issue_task(issue.id, task_id.int()) or { ctx.error(err.msg()) }
	return ctx.redirect('/${username}/${repo_name}/issue/${id}')
}

@['/:username/:repo_name/issue/:id/time'; post]
pub fn (mut app App) handle_add_issue_time(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	_, issue := app.issue_for_planning_action(ctx, username, repo_name, id.int()) or {
		return ctx.not_found()
	}
	if ctx.form['estimate_minutes'] != '' {
		app.set_issue_time_estimate(issue.id, ctx.form['estimate_minutes'].int()) or {
			ctx.error(err.msg())
		}
	}
	if ctx.form['minutes'].int() > 0 {
		app.add_issue_time(issue.id, ctx.user.id, ctx.form['minutes'].int(), ctx.form['note']) or {
			ctx.error(err.msg())
		}
	}
	return ctx.redirect('/${username}/${repo_name}/issue/${id}')
}

@['/:username/:repo_name/issue/:id/relationships'; post]
pub fn (mut app App) handle_add_issue_relationship(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	_, issue := app.issue_for_planning_action(ctx, username, repo_name, id.int()) or {
		return ctx.not_found()
	}
	app.relate_issues(issue.id, ctx.form['target_issue_id'].int(), ctx.form['relationship_type'], ctx.user.id) or { ctx.error(err.msg()) }
	return ctx.redirect('/${username}/${repo_name}/issue/${id}')
}

@['/:username/:repo_name/issue/:id/relationships/:relationship_id/delete'; post]
pub fn (mut app App) handle_delete_issue_relationship(mut ctx Context, username string,
	repo_name string, id string, relationship_id string) veb.Result {
	_, issue := app.issue_for_planning_action(ctx, username, repo_name, id.int()) or {
		return ctx.not_found()
	}
	app.remove_issue_relationship(issue.id, relationship_id.int()) or { ctx.error(err.msg()) }
	return ctx.redirect('/${username}/${repo_name}/issue/${id}')
}

@['/:username/:repo_name/issue/:id/iteration'; post]
pub fn (mut app App) handle_assign_issue_iteration(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	_, issue := app.issue_for_planning_action(ctx, username, repo_name, id.int()) or {
		return ctx.not_found()
	}
	app.assign_issue_iteration(issue.id, ctx.form['iteration_id'].int()) or { ctx.error(err.msg()) }
	return ctx.redirect('/${username}/${repo_name}/issue/${id}')
}

fn (mut app App) render_service_desk_settings(mut ctx Context, username string, repo_name string,
	created_secret string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	return $veb.html('templates/repo/service_desk.html')
}

@['/:username/:repo_name/settings/service-desk']
pub fn (mut app App) service_desk_settings(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	return app.render_service_desk_settings(mut ctx, username, repo_name, '')
}

@['/:username/:repo_name/settings/service-desk/enable'; post]
pub fn (mut app App) handle_enable_service_desk(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	secret := app.enable_service_desk(repo.id) or {
		ctx.error(err.msg())
		return app.render_service_desk_settings(mut ctx, username, repo_name, '')
	}
	return app.render_service_desk_settings(mut ctx, username, repo_name, secret)
}

@['/:username/:repo_name/settings/service-desk/disable'; post]
pub fn (mut app App) handle_disable_service_desk(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	app.disable_service_desk(repo.id) or { ctx.error(err.msg()) }
	return ctx.redirect('/${username}/${repo_name}/settings/service-desk')
}

@['/api/v1/service-desk/:token'; post]
pub fn (mut app App) api_v1_service_desk(mut ctx Context, token string) veb.Result {
	issue_id := app.create_service_desk_issue(token, ctx.form['requester_email'], ctx.form['subject'], ctx.form['body'], ctx.form['external_id']) or {
		return ctx.api_error_response(404, 'Not Found', 'service desk endpoint not found')
	}
	return ctx.json({
		'issue_id': issue_id
	})
}

@['/api/v1/repos/:username/:repo_name/service-desk/enable'; post]
pub fn (mut app App) api_v1_enable_service_desk(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	secret := app.enable_service_desk(repo.id) or {
		return ctx.api_error_response(500, 'Internal Server Error', err.msg())
	}
	return ctx.json({
		'token':    secret
		'endpoint': '/api/v1/service-desk/${secret}'
	})
}

@['/api/v1/repos/:username/:repo_name/service-desk/disable'; post]
pub fn (mut app App) api_v1_disable_service_desk(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	app.disable_service_desk(repo.id) or {
		return ctx.api_error_response(500, 'Internal Server Error', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/groups/:id/epics']
pub fn (mut app App) api_v1_group_epics(mut ctx Context, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !app.user_can_read_group(user.id, id.int()) {
		return ctx.api_not_found()
	}
	return ctx.json(app.find_group_epics(id.int()))
}

@['/api/v1/groups/:id/subgroups']
pub fn (mut app App) api_v1_group_subgroups(mut ctx Context, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !app.user_can_read_group(user.id, id.int()) {
		return ctx.api_not_found()
	}
	return ctx.json(app.find_subgroups(id.int()))
}

@['/api/v1/groups/:id/subgroups'; post]
pub fn (mut app App) api_v1_add_subgroup(mut ctx Context, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !app.user_can_admin_group(user.id, id.int()) {
		return ctx.api_error_response(403, 'Forbidden', 'Group administrator access is required')
	}
	group_id := app.add_subgroup(id.int(), ctx.form['path'], ctx.form['display_name'], user.id) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.get_org_by_id(group_id) or { return ctx.api_not_found() })
}

@['/api/v1/groups/:id/epics'; post]
pub fn (mut app App) api_v1_add_group_epic(mut ctx Context, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !app.user_can_admin_group(user.id, id.int()) {
		return ctx.api_error_response(403, 'Forbidden', 'Group administrator access is required')
	}
	epic_id := app.add_epic(id.int(), ctx.form['parent_epic_id'].int(), user.id, ctx.form['title'], ctx.form['description'], parse_yyyy_mm_dd(ctx.form['starts_at']), parse_yyyy_mm_dd(ctx.form['due_at'])) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_epic(epic_id) or { return ctx.api_not_found() })
}

@['/api/v1/groups/:id/iterations']
pub fn (mut app App) api_v1_group_iterations(mut ctx Context, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !app.user_can_read_group(user.id, id.int()) {
		return ctx.api_not_found()
	}
	return ctx.json(app.find_group_iterations(id.int()))
}

@['/api/v1/groups/:id/iterations'; post]
pub fn (mut app App) api_v1_add_group_iteration(mut ctx Context, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !app.user_can_admin_group(user.id, id.int()) {
		return ctx.api_error_response(403, 'Forbidden', 'Group administrator access is required')
	}
	iteration_id := app.add_iteration(id.int(), ctx.form['title'], ctx.form['description'], parse_yyyy_mm_dd(ctx.form['starts_at']), parse_yyyy_mm_dd(ctx.form['due_at'])) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_iteration(iteration_id) or { return ctx.api_not_found() })
}

@['/api/v1/groups/:id/iterations/:iteration_id'; post]
pub fn (mut app App) api_v1_update_group_iteration(mut ctx Context, id string,
	iteration_id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !app.user_can_admin_group(user.id, id.int()) {
		return ctx.api_error_response(403, 'Forbidden', 'Group administrator access is required')
	}
	iteration := app.find_iteration(iteration_id.int()) or { return ctx.api_not_found() }
	if iteration.org_id != id.int() {
		return ctx.api_not_found()
	}
	app.update_iteration(iteration.id, ctx.form['title'], ctx.form['description'], ctx.form['state'], parse_yyyy_mm_dd(ctx.form['starts_at']), parse_yyyy_mm_dd(ctx.form['due_at'])) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_iteration(iteration.id) or { return ctx.api_not_found() })
}

@['/api/v1/groups/:id/epics/:epic_id'; post]
pub fn (mut app App) api_v1_update_group_epic(mut ctx Context, id string,
	epic_id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !app.user_can_admin_group(user.id, id.int()) {
		return ctx.api_error_response(403, 'Forbidden', 'Group administrator access is required')
	}
	epic := app.find_epic(epic_id.int()) or { return ctx.api_not_found() }
	if epic.org_id != id.int() {
		return ctx.api_not_found()
	}
	app.update_epic(epic.id, ctx.form['title'], ctx.form['description'], ctx.form['state'], parse_yyyy_mm_dd(ctx.form['starts_at']), parse_yyyy_mm_dd(ctx.form['due_at'])) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_epic(epic.id) or { return ctx.api_not_found() })
}

@['/api/v1/groups/:id/epics/:epic_id/issues'; post]
pub fn (mut app App) api_v1_add_epic_issue(mut ctx Context, id string,
	epic_id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !app.user_can_admin_group(user.id, id.int()) {
		return ctx.api_error_response(403, 'Forbidden', 'Group administrator access is required')
	}
	epic := app.find_epic(epic_id.int()) or { return ctx.api_not_found() }
	if epic.org_id != id.int() {
		return ctx.api_not_found()
	}
	app.add_issue_to_epic(epic.id, ctx.form['issue_id'].int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_epic_issues(epic.id))
}

@['/api/v1/repos/:username/:repo_name/issues/:id/tasks'; post]
pub fn (mut app App) api_v1_add_issue_task(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	mut issue := app.find_issue_by_id(id.int()) or { return ctx.api_not_found() }
	issue.assigned = app.find_issue_assignees(issue).map(it.id)
	if issue.repo_id != repo.id || !app.issue_user_can_manage(user.id, repo, issue) {
		return ctx.api_error_response(403, 'Forbidden', 'issue management access is required')
	}
	task_id := app.add_issue_task(issue.id, user.id, ctx.form['title']) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_issue_tasks(issue.id).filter(it.id == task_id).first())
}

@['/api/v1/repos/:username/:repo_name/issues/:id/tasks']
pub fn (mut app App) api_v1_issue_tasks(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	caller := app.api_user_from_ctx(ctx) or { User{} }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	issue := app.find_issue_by_id(id.int()) or { return ctx.api_not_found() }
	if issue.repo_id != repo.id || !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.find_issue_tasks(issue.id))
}

@['/api/v1/repos/:username/:repo_name/issues/:id/tasks/:task_id/toggle'; post]
pub fn (mut app App) api_v1_toggle_issue_task(mut ctx Context, username string,
	repo_name string, id string, task_id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	mut issue := app.find_issue_by_id(id.int()) or { return ctx.api_not_found() }
	issue.assigned = app.find_issue_assignees(issue).map(it.id)
	if issue.repo_id != repo.id || !app.issue_user_can_manage(user.id, repo, issue) {
		return ctx.api_error_response(403, 'Forbidden', 'issue management access is required')
	}
	tasks := app.find_issue_tasks(issue.id).filter(it.id == task_id.int())
	if tasks.len != 1 {
		return ctx.api_not_found()
	}
	app.set_issue_task_completed(issue.id, tasks.first().id, !tasks.first().completed) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_issue_tasks(issue.id).filter(it.id == task_id.int()).first())
}

@['/api/v1/repos/:username/:repo_name/issues/:id/time'; post]
pub fn (mut app App) api_v1_add_issue_time(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	mut issue := app.find_issue_by_id(id.int()) or { return ctx.api_not_found() }
	issue.assigned = app.find_issue_assignees(issue).map(it.id)
	if issue.repo_id != repo.id || !app.issue_user_can_manage(user.id, repo, issue) {
		return ctx.api_error_response(403, 'Forbidden', 'issue management access is required')
	}
	entry_id := app.add_issue_time(issue.id, user.id, ctx.form['minutes'].int(), ctx.form['note']) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json({
		'id':            entry_id
		'total_minutes': app.issue_time_spent(issue.id)
	})
}

@['/api/v1/repos/:username/:repo_name/issues/:id/time']
pub fn (mut app App) api_v1_issue_time(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	caller := app.api_user_from_ctx(ctx) or { User{} }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	issue := app.find_issue_by_id(id.int()) or { return ctx.api_not_found() }
	if issue.repo_id != repo.id || !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json({
		'estimate_minutes': issue.time_estimate_minutes
		'spent_minutes':    app.issue_time_spent(issue.id)
	})
}

@['/api/v1/repos/:username/:repo_name/issues/:id/relationships'; post]
pub fn (mut app App) api_v1_relate_issues(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	mut issue := app.find_issue_by_id(id.int()) or { return ctx.api_not_found() }
	issue.assigned = app.find_issue_assignees(issue).map(it.id)
	if issue.repo_id != repo.id || !app.issue_user_can_manage(user.id, repo, issue) {
		return ctx.api_error_response(403, 'Forbidden', 'issue management access is required')
	}
	relation_id := app.relate_issues(issue.id, ctx.form['target_issue_id'].int(), ctx.form['relationship_type'], user.id) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_issue_relationships(issue.id).filter(it.id == relation_id).first())
}

@['/api/v1/repos/:username/:repo_name/issues/:id/relationships']
pub fn (mut app App) api_v1_issue_relationships(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	caller := app.api_user_from_ctx(ctx) or { User{} }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	issue := app.find_issue_by_id(id.int()) or { return ctx.api_not_found() }
	if issue.repo_id != repo.id || !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.find_issue_relationships(issue.id))
}

@['/api/v1/repos/:username/:repo_name/issues/:id/iteration'; post]
pub fn (mut app App) api_v1_assign_issue_iteration(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	mut issue := app.find_issue_by_id(id.int()) or { return ctx.api_not_found() }
	issue.assigned = app.find_issue_assignees(issue).map(it.id)
	if issue.repo_id != repo.id || !app.issue_user_can_manage(user.id, repo, issue) {
		return ctx.api_error_response(403, 'Forbidden', 'issue management access is required')
	}
	app.assign_issue_iteration(issue.id, ctx.form['iteration_id'].int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.issue_to_api(app.find_issue_by_id(issue.id) or { return ctx.api_not_found() }))
}
