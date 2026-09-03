// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import crypto.rand
import crypto.sha256
import encoding.hex
import time

struct ClusterAgent {
	id int @[primary; sql: serial]
mut:
	repo_id         int
	created_by      int
	name            string
	token_hash      string @[unique]
	environment     string
	configuration   string
	created_at      int
	last_contact_at int
	last_contact_ip string
	cluster_version string
	inventory       string
	revoked         bool
}

struct FeatureFlag {
	id int @[primary; sql: serial]
mut:
	repo_id      int @[unique: 'feature_flag']
	name         string @[unique: 'feature_flag']
	description  string
	active       bool
	strategy     string
	rollout      int
	environments string
	targets      string
	created_by   int
	created_at   int
	updated_at   int
}

struct Incident {
	id int @[primary; sql: serial]
mut:
	repo_id     int
	created_by  int
	title       string
	description string
	severity    string
	status      string
	assignee_id int
	alert_key   string
	created_at  int
	updated_at  int
	resolved_at int
}

struct IncidentNote {
	id int @[primary; sql: serial]
mut:
	incident_id int
	author_id   int
	body        string
	created_at  int
}

struct AlertIntegration {
	id int @[primary; sql: serial]
mut:
	repo_id      int
	created_by   int
	name         string
	token_hash   string @[unique]
	created_at   int
	last_used_at int
	revoked      bool
}

fn (app &App) list_alert_integrations(repo_id int) []AlertIntegration {
	return sql app.db {
		select from AlertIntegration where repo_id == repo_id order by id
	} or { []AlertIntegration{} }
}

fn (mut app App) revoke_alert_integration(repo Repo, actor_id int, integration_id int) ! {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer {
		return error('Maintainer access is required')
	}
	revoked := true
	sql app.db {
		update AlertIntegration set revoked = revoked where repo_id == repo.id && id == integration_id
	}!
}

struct AlertEvent {
	id int @[primary; sql: serial]
mut:
	integration_id int @[unique: 'alert_event']
	fingerprint    string @[unique: 'alert_event']
	incident_id    int
	severity       string
	title          string
	payload        string
	created_at     int
}

struct TelemetryEvent {
	id int @[primary; sql: serial]
mut:
	repo_id     int
	kind        string
	service     string
	environment string
	trace_id    string
	name        string
	value       string
	payload     string
	created_at  int
}

struct OnCallSchedule {
	id int @[primary; sql: serial]
mut:
	repo_id       int
	name          string
	timezone      string
	shift_seconds int
	enabled       bool
	created_by    int
	created_at    int
}

struct OnCallRotation {
	id int @[primary; sql: serial]
mut:
	schedule_id int @[unique: 'on_call_rotation']
	user_id     int @[unique: 'on_call_rotation']
	position    int
	starts_at   int
	ends_at     int
}

fn new_integration_secret(prefix string) !string {
	return prefix + hex.encode(rand.bytes(24)!)
}

fn (mut app App) create_cluster_agent(repo Repo, actor_id int, name string, environment string,
	configuration string) !(ClusterAgent, string) {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer || !valid_short_name(name)
		|| !valid_short_name(environment) || !valid_body(configuration) {
		return error('invalid cluster agent or Maintainer access is required')
	}
	secret := new_integration_secret('glagent_')!
	id := db_insert_returning_id(mut app.db, 'ClusterAgent', ['repo_id', 'created_by', 'name',
		'token_hash', 'environment', 'configuration', 'created_at', 'last_contact_at',
		'last_contact_ip', 'cluster_version', 'inventory', 'revoked'], [repo.id.str(),
		actor_id.str(), name.trim_space(), hash_api_token(secret), environment.trim_space(),
		configuration, int(time.now().unix()).str(), '0', '', '', '', db_bool_value(false)])!
	return app.find_cluster_agent(repo.id, id) or { return error('agent was not saved') }, secret
}

fn (app &App) find_cluster_agent(repo_id int, id int) ?ClusterAgent {
	rows := sql app.db {
		select from ClusterAgent where repo_id == repo_id && id == id limit 1
	} or { []ClusterAgent{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) list_cluster_agents(repo_id int) []ClusterAgent {
	return sql app.db {
		select from ClusterAgent where repo_id == repo_id order by id
	} or { []ClusterAgent{} }
}

fn (mut app App) cluster_agent_heartbeat(secret string, ip string, cluster_version string,
	inventory string) !ClusterAgent {
	if !secret.starts_with('glagent_') || secret.len > 128 || cluster_version.len > 255
		|| inventory.len > max_body_len {
		return error('invalid cluster agent heartbeat')
	}
	hash := hash_api_token(secret)
	rows := sql app.db {
		select from ClusterAgent where token_hash == hash && revoked == false limit 1
	}!
	if rows.len != 1 {
		return error('cluster agent not found')
	}
	id := rows.first().id
	now := int(time.now().unix())
	safe_ip := ip[..if ip.len < 255 { ip.len } else { 255 }]
	sql app.db {
		update ClusterAgent set last_contact_at = now, last_contact_ip = safe_ip,
		cluster_version = cluster_version, inventory = inventory where id == id
	}!
	return app.find_cluster_agent(rows.first().repo_id, id) or { return error('agent disappeared') }
}

fn (mut app App) revoke_cluster_agent(repo_id int, id int) ! {
	revoked := true
	sql app.db {
		update ClusterAgent set revoked = revoked where repo_id == repo_id && id == id
	}!
}

fn (mut app App) add_feature_flag(repo Repo, actor_id int, name string, description string,
	strategy string, rollout int, environments string, targets string) !int {
	kind := strategy.trim_space().to_lower()
	if app.repo_access_level(actor_id, repo) < project_access_developer
		|| !valid_registry_name(name) || !valid_body(description)
		|| kind !in ['all', 'percentage', 'targets'] || rollout < 0 || rollout > 100
		|| environments.len > 4096 || targets.len > 10000 {
		return error('invalid feature flag or Developer access is required')
	}
	now := int(time.now().unix())
	return db_insert_returning_id(mut app.db, 'FeatureFlag', ['repo_id', 'name', 'description',
		'active', 'strategy', 'rollout', 'environments', 'targets', 'created_by', 'created_at',
		'updated_at'], [repo.id.str(), name.trim_space(), description, db_bool_value(true), kind,
		rollout.str(), normalize_csv_values(environments, [], true)!,
		normalize_csv_values(targets, [], true)!, actor_id.str(), now.str(), now.str()])
}

fn (app &App) find_feature_flag(repo_id int, name string) ?FeatureFlag {
	rows := sql app.db {
		select from FeatureFlag where repo_id == repo_id && name == name limit 1
	} or { []FeatureFlag{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) list_feature_flags(repo_id int) []FeatureFlag {
	return sql app.db {
		select from FeatureFlag where repo_id == repo_id order by name
	} or { []FeatureFlag{} }
}

fn (mut app App) set_feature_flag_active(repo_id int, id int, active bool) ! {
	now := int(time.now().unix())
	sql app.db {
		update FeatureFlag set active = active, updated_at = now where repo_id == repo_id && id == id
	}!
}

fn feature_flag_enabled(flag FeatureFlag, environment string, subject string) bool {
	if !flag.active {
		return false
	}
	environments := flag.environments.split(',').filter(it != '')
	if environments.len > 0 && environment.trim_space().to_lower() !in environments {
		return false
	}
	match flag.strategy {
		'all' {
			return true
		}
		'targets' {
			return subject.trim_space().to_lower() in flag.targets.split(',')
		}
		'percentage' {
			digest := sha256.sum('${flag.repo_id}/${flag.name}/${subject}'.bytes())
			bucket := (int(digest[0]) * 256 + int(digest[1])) % 100
			return bucket < flag.rollout
		}
		else {
			return false
		}
	}
}

fn (mut app App) create_incident(repo Repo, actor_id int, title string, description string,
	severity string, alert_key string) !int {
	level := severity.trim_space().to_lower()
	if actor_id > 0 && app.repo_access_level(actor_id, repo) < project_access_developer {
		return error('Developer access is required')
	}
	if !valid_title(title) || !valid_body(description) || level !in ['low', 'medium', 'high',
		'critical'] || alert_key.len > 255 {
		return error('invalid incident')
	}
	now := int(time.now().unix())
	return db_insert_returning_id(mut app.db, 'Incident', ['repo_id', 'created_by', 'title',
		'description', 'severity', 'status', 'assignee_id', 'alert_key', 'created_at', 'updated_at',
		'resolved_at'], [repo.id.str(), actor_id.str(), title.trim_space(), description, level,
		'open', '0', alert_key, now.str(), now.str(), '0'])
}

fn (app &App) find_incident(repo_id int, id int) ?Incident {
	rows := sql app.db {
		select from Incident where repo_id == repo_id && id == id limit 1
	} or { []Incident{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) list_incidents(repo_id int) []Incident {
	return sql app.db {
		select from Incident where repo_id == repo_id order by id desc
	} or { []Incident{} }
}

fn (mut app App) update_incident(repo_id int, id int, status string, severity string,
	assignee_id int) ! {
	if status !in ['open', 'investigating', 'mitigated', 'resolved'] || severity !in [
		'low',
		'medium',
		'high',
		'critical',
	] {
		return error('invalid incident state')
	}
	now := int(time.now().unix())
	resolved := if status == 'resolved' { now } else { 0 }
	sql app.db {
		update Incident set status = status, severity = severity, assignee_id = assignee_id,
		updated_at = now, resolved_at = resolved where repo_id == repo_id && id == id
	}!
}

fn (mut app App) add_incident_note(incident_id int, author_id int, body string) !int {
	if incident_id <= 0 || author_id <= 0 || !valid_comment(body) {
		return error('invalid incident note')
	}
	return db_insert_returning_id(mut app.db, 'IncidentNote', ['incident_id', 'author_id', 'body',
		'created_at'], [incident_id.str(), author_id.str(), body, int(time.now().unix()).str()])
}

fn (app &App) list_incident_notes(incident_id int) []IncidentNote {
	return sql app.db {
		select from IncidentNote where incident_id == incident_id order by id
	} or { []IncidentNote{} }
}

fn (mut app App) create_alert_integration(repo Repo, actor_id int, name string) !(AlertIntegration, string) {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer || !valid_short_name(name) {
		return error('invalid alert integration or Maintainer access is required')
	}
	secret := new_integration_secret('glalert_')!
	id := db_insert_returning_id(mut app.db, 'AlertIntegration', ['repo_id', 'created_by', 'name',
		'token_hash', 'created_at', 'last_used_at', 'revoked'], [repo.id.str(), actor_id.str(),
		name.trim_space(), hash_api_token(secret), int(time.now().unix()).str(), '0',
		db_bool_value(false)])!
	rows := sql app.db {
		select from AlertIntegration where id == id limit 1
	}!
	return rows.first(), secret
}

fn (mut app App) ingest_alert(secret string, fingerprint string, title string, severity string,
	payload string) !Incident {
	if !secret.starts_with('glalert_') || secret.len > 128 || !valid_title(title)
		|| severity !in ['low', 'medium', 'high', 'critical'] || payload.len > max_body_len
		|| fingerprint.trim_space() == '' || fingerprint.len > 255 {
		return error('invalid alert')
	}
	hash := hash_api_token(secret)
	integrations := sql app.db {
		select from AlertIntegration where token_hash == hash && revoked == false limit 1
	}!
	if integrations.len != 1 {
		return error('alert integration not found')
	}
	integration := integrations.first()
	existing := sql app.db {
		select from AlertEvent where integration_id == integration.id
		&& fingerprint == fingerprint limit 1
	}!
	if existing.len > 0 {
		return app.find_incident(integration.repo_id, existing.first().incident_id) or {
			return error('incident not found')
		}
	}
	repo := app.find_repo_by_id(integration.repo_id) or { return error('project not found') }
	incident_id := app.create_incident(repo, 0, title, payload, severity, fingerprint)!
	event := AlertEvent{
		integration_id: integration.id
		fingerprint: fingerprint
		incident_id: incident_id
		severity: severity
		title: title
		payload: payload
		created_at: int(time.now().unix())
	}
	sql app.db {
		insert event into AlertEvent
	}!
	now := int(time.now().unix())
	id := integration.id
	sql app.db {
		update AlertIntegration set last_used_at = now where id == id
	}!
	return app.find_incident(repo.id, incident_id) or { return error('incident was not saved') }
}

fn (mut app App) record_telemetry(repo Repo, kind string, service string, environment string,
	trace_id string, name string, value string, payload string) !int {
	if kind !in ['metric', 'trace', 'error'] || !valid_short_name(service)
		|| !valid_short_name(environment) || !valid_short_name(name) || trace_id.len > 255
		|| value.len > 255 || payload.len > max_body_len {
		return error('invalid telemetry event')
	}
	return db_insert_returning_id(mut app.db, 'TelemetryEvent', ['repo_id', 'kind', 'service',
		'environment', 'trace_id', 'name', 'value', 'payload', 'created_at'], [
		repo.id.str(),
		kind,
		service.trim_space(),
		environment.trim_space(),
		trace_id,
		name.trim_space(),
		value,
		payload,
		int(time.now().unix()).str(),
	])
}

fn (app &App) list_telemetry(repo_id int, kind string) []TelemetryEvent {
	return sql app.db {
		select from TelemetryEvent where repo_id == repo_id && kind == kind order by id desc limit 500
	} or { []TelemetryEvent{} }
}

fn (mut app App) prune_telemetry(retention_days int) !int {
	if retention_days < 1 || retention_days > 3650 {
		return error('invalid telemetry retention')
	}
	cutoff := int(time.now().unix()) - retention_days * 86400
	count := sql app.db {
		select count from TelemetryEvent where created_at < cutoff
	}!
	sql app.db {
		delete from TelemetryEvent where created_at < cutoff
	}!
	return count
}

fn (mut app App) add_on_call_schedule(repo Repo, actor_id int, name string, timezone string,
	shift_seconds int) !int {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer || !valid_short_name(name)
		|| !valid_short_name(timezone) || shift_seconds < 300 || shift_seconds > 31 * 86400 {
		return error('invalid on-call schedule or Maintainer access is required')
	}
	return db_insert_returning_id(mut app.db, 'OnCallSchedule', ['repo_id', 'name', 'timezone',
		'shift_seconds', 'enabled', 'created_by', 'created_at'], [repo.id.str(), name.trim_space(),
		timezone.trim_space(), shift_seconds.str(), db_bool_value(true), actor_id.str(),
		int(time.now().unix()).str()])
}

fn (app &App) find_on_call_schedule(repo_id int, id int) ?OnCallSchedule {
	rows := sql app.db {
		select from OnCallSchedule where repo_id == repo_id && id == id limit 1
	} or { []OnCallSchedule{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) list_on_call_schedules(repo_id int) []OnCallSchedule {
	return sql app.db {
		select from OnCallSchedule where repo_id == repo_id order by id
	} or { []OnCallSchedule{} }
}

fn (mut app App) add_on_call_rotation(schedule OnCallSchedule, user_id int, position int,
	starts_at int, ends_at int) !int {
	if user_id <= 0 || position < 0 || starts_at < 0 || ends_at < 0
		|| (ends_at > 0 && ends_at <= starts_at) {
		return error('invalid on-call rotation')
	}
	repo := app.find_repo_by_id(schedule.repo_id) or { return error('project not found') }
	if app.repo_access_level(user_id, repo) < project_access_reporter {
		return error('on-call user must be a project member')
	}
	return db_insert_returning_id(mut app.db, 'OnCallRotation', ['schedule_id', 'user_id', 'position',
		'starts_at', 'ends_at'], [schedule.id.str(), user_id.str(), position.str(), starts_at.str(),
		ends_at.str()])
}

fn (app &App) on_call_user(schedule OnCallSchedule, at int) ?User {
	if !schedule.enabled {
		return none
	}
	rotations := sql app.db {
		select from OnCallRotation where schedule_id == schedule.id order by position
	} or { []OnCallRotation{} }
	active := rotations.filter(it.starts_at <= at && (it.ends_at == 0 || it.ends_at > at))
	if active.len == 0 {
		return none
	}
	base := active.map(it.starts_at).filter(it > 0)
	anchor := if base.len > 0 { base[0] } else { 0 }
	index := ((at - anchor) / schedule.shift_seconds) % active.len
	return app.get_user_by_id(active[index].user_id)
}
