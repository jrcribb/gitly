// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import veb
import time

struct ClusterAgentCreatedResponse {
	id    int
	name  string
	token string
}

struct ClusterAgentView {
	id              int
	repo_id         int
	name            string
	environment     string
	configuration   string
	created_at      int
	last_contact_at int
	last_contact_ip string
	cluster_version string
	inventory       string
	revoked         bool
}

fn cluster_agent_view(agent ClusterAgent) ClusterAgentView {
	return ClusterAgentView{
		id: agent.id
		repo_id: agent.repo_id
		name: agent.name
		environment: agent.environment
		configuration: agent.configuration
		created_at: agent.created_at
		last_contact_at: agent.last_contact_at
		last_contact_ip: agent.last_contact_ip
		cluster_version: agent.cluster_version
		inventory: agent.inventory
		revoked: agent.revoked
	}
}

struct ClusterAgentHeartbeatResponse {
	agent_id      int
	configuration string
}

struct FeatureFlagEvaluationResponse {
	name    string
	enabled bool
}

struct AlertIntegrationCreatedResponse {
	id       int
	token    string
	endpoint string
}

struct CurrentOnCallResponse {
	user_id  int
	username string
}

@['/:username/:repo_name/platform/feature-flags'; post]
pub fn (mut app App) handle_add_feature_flag(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_developer {
		return ctx.not_found()
	}
	app.add_feature_flag(repo, ctx.user.id, ctx.form['name'], ctx.form['description'], ctx.form['strategy'], ctx.form['rollout'].int(), ctx.form['environments'], ctx.form['targets']) or { ctx.error(err.msg()) }
	return app.platform_dashboard(mut ctx, username, repo_name, '')
}

@['/:username/:repo_name/platform/incidents'; post]
pub fn (mut app App) handle_create_incident(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_developer {
		return ctx.not_found()
	}
	app.create_incident(repo, ctx.user.id, ctx.form['title'], ctx.form['description'], ctx.form['severity'], '') or { ctx.error(err.msg()) }
	return app.platform_dashboard(mut ctx, username, repo_name, '')
}

@['/:username/:repo_name/platform/alert-integrations'; post]
pub fn (mut app App) handle_create_alert_integration(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_maintainer {
		return ctx.not_found()
	}
	_, secret := app.create_alert_integration(repo, ctx.user.id, ctx.form['name']) or {
		ctx.error(err.msg())
		return app.platform_dashboard(mut ctx, username, repo_name, '')
	}
	return app.platform_dashboard(mut ctx, username, repo_name, secret)
}

@['/:username/:repo_name/platform/agents'; post]
pub fn (mut app App) handle_create_cluster_agent(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_maintainer {
		return ctx.not_found()
	}
	_, secret := app.create_cluster_agent(repo, ctx.user.id, ctx.form['name'], ctx.form['environment'], ctx.form['configuration']) or {
		ctx.error(err.msg())
		return app.platform_dashboard(mut ctx, username, repo_name, '')
	}
	return app.platform_dashboard(mut ctx, username, repo_name, secret)
}

@['/:username/:repo_name/platform/on-call'; post]
pub fn (mut app App) handle_add_on_call_schedule(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_maintainer {
		return ctx.not_found()
	}
	app.add_on_call_schedule(repo, ctx.user.id, ctx.form['name'], ctx.form['timezone'], ctx.form['shift_seconds'].int()) or { ctx.error(err.msg()) }
	return app.platform_dashboard(mut ctx, username, repo_name, '')
}

@['/api/v1/repos/:username/:repo_name/cluster-agents']
pub fn (mut app App) api_v1_cluster_agents(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	return ctx.json(app.list_cluster_agents(repo.id).map(cluster_agent_view(it)))
}

@['/api/v1/repos/:username/:repo_name/cluster-agents/:id/revoke'; post]
pub fn (mut app App) api_v1_revoke_cluster_agent(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	app.find_cluster_agent(repo.id, id.int()) or { return ctx.api_not_found() }
	app.revoke_cluster_agent(repo.id, id.int()) or {
		return ctx.api_error_response(500, 'Internal Server Error', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/cluster-agents'; post]
pub fn (mut app App) api_v1_create_cluster_agent(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	agent, secret := app.create_cluster_agent(repo, user.id, ctx.form['name'], ctx.form['environment'], ctx.form['configuration']) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	app.record_audit_event('project', repo.id, user.id, 'cluster_agent.create', 'agent', agent.id.str(), agent.name, ctx.ip())
	return ctx.json(ClusterAgentCreatedResponse{
		id: agent.id
		name: agent.name
		token: secret
	})
}

@['/api/v1/cluster-agents/:token/heartbeat'; post]
pub fn (mut app App) api_v1_cluster_agent_heartbeat(mut ctx Context, token string) veb.Result {
	if !app.consume_abuse_limit('cluster_agent', ctx.ip(), 120, 60) {
		return ctx.api_error_response(429, 'Too Many Requests', 'rate limit exceeded')
	}
	agent := app.cluster_agent_heartbeat(token, ctx.ip(), ctx.form['cluster_version'], ctx.form['inventory']) or { return ctx.api_not_found() }
	return ctx.json(ClusterAgentHeartbeatResponse{
		agent_id: agent.id
		configuration: agent.configuration
	})
}

@['/api/v1/repos/:username/:repo_name/feature-flags']
pub fn (mut app App) api_v1_feature_flags(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if app.repo_access_level(caller.id, repo) < project_access_developer {
		return ctx.api_error_response(403, 'Forbidden', 'Developer access is required')
	}
	return ctx.json(app.list_feature_flags(repo.id))
}

@['/api/v1/repos/:username/:repo_name/feature-flags'; post]
pub fn (mut app App) api_v1_add_feature_flag(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	id := app.add_feature_flag(repo, user.id, ctx.form['name'], ctx.form['description'], ctx.form['strategy'], ctx.form['rollout'].int(), ctx.form['environments'], ctx.form['targets']) or { return ctx.api_error_response(400, 'Bad Request', err.msg()) }
	return ctx.json(app.list_feature_flags(repo.id).filter(it.id == id).first())
}

@['/api/v1/repos/:username/:repo_name/feature-flags/:name/evaluate']
pub fn (mut app App) api_v1_evaluate_feature_flag(mut ctx Context, username string,
	repo_name string, name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	flag := app.find_feature_flag(repo.id, name) or { return ctx.api_not_found() }
	return ctx.json(FeatureFlagEvaluationResponse{
		name: flag.name
		enabled: feature_flag_enabled(flag, ctx.query['environment'] or { '' }, ctx.query['subject'] or { '' })
	})
}

@['/api/v1/repos/:username/:repo_name/feature-flags/:id/state'; post]
pub fn (mut app App) api_v1_set_feature_flag_state(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_developer {
		return ctx.api_error_response(403, 'Forbidden', 'Developer access is required')
	}
	app.set_feature_flag_active(repo.id, id.int(), ctx.form['active'] != 'false') or {
		return ctx.api_error_response(500, 'Internal Server Error', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/incidents']
pub fn (mut app App) api_v1_incidents(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.list_incidents(repo.id))
}

@['/api/v1/repos/:username/:repo_name/incidents'; post]
pub fn (mut app App) api_v1_create_incident(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	id := app.create_incident(repo, user.id, ctx.form['title'], ctx.form['description'], ctx.form['severity'], '') or { return ctx.api_error_response(400, 'Bad Request', err.msg()) }
	return ctx.json(app.find_incident(repo.id, id) or { return ctx.api_not_found() })
}

@['/api/v1/repos/:username/:repo_name/incidents/:id'; post]
pub fn (mut app App) api_v1_update_incident(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_developer {
		return ctx.api_error_response(403, 'Forbidden', 'Developer access is required')
	}
	app.find_incident(repo.id, id.int()) or { return ctx.api_not_found() }
	app.update_incident(repo.id, id.int(), ctx.form['status'], ctx.form['severity'], ctx.form['assignee_id'].int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_incident(repo.id, id.int()) or { return ctx.api_not_found() })
}

@['/api/v1/repos/:username/:repo_name/incidents/:id/notes'; post]
pub fn (mut app App) api_v1_add_incident_note(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_developer {
		return ctx.api_error_response(403, 'Forbidden', 'Developer access is required')
	}
	incident := app.find_incident(repo.id, id.int()) or { return ctx.api_not_found() }
	note_id := app.add_incident_note(incident.id, user.id, ctx.form['body']) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.list_incident_notes(incident.id).filter(it.id == note_id).first())
}

@['/api/v1/repos/:username/:repo_name/alert-integrations'; post]
pub fn (mut app App) api_v1_create_alert_integration(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	integration, secret := app.create_alert_integration(repo, user.id, ctx.form['name']) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(AlertIntegrationCreatedResponse{
		id: integration.id
		token: secret
		endpoint: '/api/v1/alerts/${secret}'
	})
}

@['/api/v1/repos/:username/:repo_name/alert-integrations/:id/revoke'; post]
pub fn (mut app App) api_v1_revoke_alert_integration(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	app.revoke_alert_integration(repo, user.id, id.int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/alerts/:token'; post]
pub fn (mut app App) api_v1_ingest_alert(mut ctx Context, token string) veb.Result {
	if !app.consume_abuse_limit('alert', ctx.ip(), 120, 60) {
		return ctx.api_error_response(429, 'Too Many Requests', 'rate limit exceeded')
	}
	incident := app.ingest_alert(token, ctx.form['fingerprint'], ctx.form['title'], ctx.form['severity'], ctx.form['payload']) or { return ctx.api_not_found() }
	return ctx.json(incident)
}

@['/api/v1/repos/:username/:repo_name/telemetry'; post]
pub fn (mut app App) api_v1_record_telemetry(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_developer
		|| !app.consume_abuse_limit('telemetry', '${repo.id}/${user.id}', 600, 60) {
		return ctx.api_error_response(403, 'Forbidden', 'telemetry ingestion is not permitted')
	}
	id := app.record_telemetry(repo, ctx.form['kind'], ctx.form['service'], ctx.form['environment'], ctx.form['trace_id'], ctx.form['name'], ctx.form['value'], ctx.form['payload']) or { return ctx.api_error_response(400, 'Bad Request', err.msg()) }
	return ctx.json({
		'id': id
	})
}

@['/api/v1/repos/:username/:repo_name/telemetry/:kind']
pub fn (mut app App) api_v1_telemetry(mut ctx Context, username string, repo_name string,
	kind string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	if app.repo_access_level(caller.id, repo) < project_access_developer
		|| kind !in ['metric', 'trace', 'error'] {
		return ctx.api_not_found()
	}
	return ctx.json(app.list_telemetry(repo.id, kind))
}

@['/api/v1/repos/:username/:repo_name/on-call'; post]
pub fn (mut app App) api_v1_add_on_call_schedule(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	id := app.add_on_call_schedule(repo, user.id, ctx.form['name'], ctx.form['timezone'], ctx.form['shift_seconds'].int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(app.find_on_call_schedule(repo.id, id) or { return ctx.api_not_found() })
}

@['/api/v1/repos/:username/:repo_name/on-call/:id/rotations'; post]
pub fn (mut app App) api_v1_add_on_call_rotation(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	schedule := app.find_on_call_schedule(repo.id, id.int()) or { return ctx.api_not_found() }
	rotation_id := app.add_on_call_rotation(schedule, ctx.form['user_id'].int(), ctx.form['position'].int(), ctx.form['starts_at'].int(), ctx.form['ends_at'].int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json({
		'id': rotation_id
	})
}

@['/api/v1/repos/:username/:repo_name/on-call/:id/current']
pub fn (mut app App) api_v1_current_on_call(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	schedule := app.find_on_call_schedule(repo.id, id.int()) or { return ctx.api_not_found() }
	user := app.on_call_user(schedule, int(time.now().unix())) or { return ctx.api_not_found() }
	return ctx.json(CurrentOnCallResponse{
		user_id: user.id
		username: user.username
	})
}
