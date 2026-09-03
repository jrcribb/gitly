// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import veb

@['/:username/:repo_name/platform/security-policies'; post]
pub fn (mut app App) handle_add_security_policy(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_maintainer {
		return ctx.not_found()
	}
	app.add_security_policy(repo, ctx.user.id, ctx.form['name'], ctx.form['branch_pattern'], ctx.form['required_scan_types'], ctx.form['blocked_severities'], ctx.form['max_scan_age_hours'].int(), ctx.form['allowed_licenses'], 'block_unresolved' in ctx.form) or { ctx.error(err.msg()) }
	return app.platform_dashboard(mut ctx, username, repo_name, '')
}

@['/:username/:repo_name/platform/approval-policies'; post]
pub fn (mut app App) handle_add_approval_policy(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_maintainer {
		return ctx.not_found()
	}
	app.add_merge_approval_policy(repo, ctx.user.id, ctx.form['name'], ctx.form['branch_pattern'], ctx.form['required_approvals'].int(), ctx.form['approver_role']) or { ctx.error(err.msg()) }
	return app.platform_dashboard(mut ctx, username, repo_name, '')
}

@['/api/v1/repos/:username/:repo_name/security/scans']
pub fn (mut app App) api_v1_security_scans(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.list_security_scans(repo.id))
}

@['/api/v1/repos/:username/:repo_name/security/scans'; post]
pub fn (mut app App) api_v1_start_security_scan(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	id := app.start_security_scan(repo, user.id, ctx.form['scan_type'], ctx.form['ref'], ctx.form['commit_sha'], ctx.form['scanner'], ctx.form['report_format']) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	app.record_audit_event('project', repo.id, user.id, 'security.scan.start', 'security_scan', id.str(), ctx.form['scan_type'], ctx.ip())
	return ctx.json(app.find_security_scan(repo.id, id) or { return ctx.api_not_found() })
}

@['/api/v1/repos/:username/:repo_name/security/scans/:id/findings'; post]
pub fn (mut app App) api_v1_add_security_finding(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_developer {
		return ctx.api_error_response(403, 'Forbidden', 'Developer access is required')
	}
	scan := app.find_security_scan(repo.id, id.int()) or { return ctx.api_not_found() }
	finding := app.record_security_finding(scan, ctx.form['title'], ctx.form['description'], ctx.form['severity'], ctx.form['location'], ctx.form['identifiers'], ctx.form['evidence'], ctx.form['fingerprint']) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(finding)
}

@['/api/v1/repos/:username/:repo_name/security/scans/:id/finish'; post]
pub fn (mut app App) api_v1_finish_security_scan(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_developer {
		return ctx.api_error_response(403, 'Forbidden', 'Developer access is required')
	}
	scan := app.find_security_scan(repo.id, id.int()) or { return ctx.api_not_found() }
	app.finish_security_scan(scan, ctx.form['status'] != 'failed', ctx.form['error']) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_security_scan(repo.id, scan.id) or { return ctx.api_not_found() })
}

@['/api/v1/repos/:username/:repo_name/security/findings']
pub fn (mut app App) api_v1_security_findings(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.list_security_findings(repo.id))
}

@['/api/v1/repos/:username/:repo_name/security/findings/:id/state'; post]
pub fn (mut app App) api_v1_set_security_finding_state(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_developer {
		return ctx.api_error_response(403, 'Forbidden', 'Developer access is required')
	}
	app.set_vulnerability_state(repo.id, id.int(), user.id, ctx.form['state'], ctx.form['reason']) or { return ctx.api_error_response(400, 'Bad Request', err.msg()) }
	app.record_audit_event('project', repo.id, user.id, 'vulnerability.state', 'finding', id, ctx.form['state'], ctx.ip())
	return ctx.json(app.find_security_finding(repo.id, id.int()) or { return ctx.api_not_found() })
}

@['/api/v1/repos/:username/:repo_name/security/policies']
pub fn (mut app App) api_v1_security_policies(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.list_security_policies(repo.id))
}

@['/api/v1/repos/:username/:repo_name/security/policies'; post]
pub fn (mut app App) api_v1_add_security_policy(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	id := app.add_security_policy(repo, user.id, ctx.form['name'], ctx.form['branch_pattern'], ctx.form['required_scan_types'], ctx.form['blocked_severities'], ctx.form['max_scan_age_hours'].int(), ctx.form['allowed_licenses'], ctx.form['block_unresolved'] != 'false') or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	app.record_audit_event('project', repo.id, user.id, 'security.policy.create', 'policy', id.str(), ctx.form['name'], ctx.ip())
	return ctx.json(app.list_security_policies(repo.id).filter(it.id == id).first())
}

@['/api/v1/repos/:username/:repo_name/security/policies/:id/delete'; post]
pub fn (mut app App) api_v1_delete_security_policy(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	app.delete_security_policy(repo.id, id.int()) or {
		return ctx.api_error_response(500, 'Internal Server Error', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/approval-policies']
pub fn (mut app App) api_v1_approval_policies(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.list_merge_approval_policies(repo.id))
}

@['/api/v1/repos/:username/:repo_name/approval-policies'; post]
pub fn (mut app App) api_v1_add_approval_policy(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	id := app.add_merge_approval_policy(repo, user.id, ctx.form['name'], ctx.form['branch_pattern'], ctx.form['required_approvals'].int(), ctx.form['approver_role']) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.list_merge_approval_policies(repo.id).filter(it.id == id).first())
}

@['/api/v1/repos/:username/:repo_name/approval-policies/:id/delete'; post]
pub fn (mut app App) api_v1_delete_approval_policy(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	app.delete_merge_approval_policy(repo, user.id, id.int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/compliance-framework'; post]
pub fn (mut app App) api_v1_assign_compliance_framework(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	app.assign_compliance_framework(repo.id, ctx.form['framework_id'].int(), user.id) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	app.record_audit_event('project', repo.id, user.id, 'compliance.assign', 'framework', ctx.form['framework_id'], '', ctx.ip())
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/audit-events']
pub fn (mut app App) api_v1_project_audit_events(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	after_id := (ctx.query['after_id'] or { '0' }).int()
	ctx.set_content_type('application/json')
	return ctx.ok(app.export_audit_events('project', repo.id, after_id))
}

@['/api/v1/admin/compliance-frameworks'; post]
pub fn (mut app App) api_v1_admin_add_compliance_framework(mut ctx Context) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if !user.is_admin {
		return ctx.api_error_response(403, 'Forbidden', 'administrator access is required')
	}
	id := app.add_compliance_framework(ctx.form['name'], ctx.form['description'], ctx.form['requirements'], user.id) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.list_compliance_frameworks().filter(it.id == id).first())
}
