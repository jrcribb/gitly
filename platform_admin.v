// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import crypto.sha256
import encoding.hex
import config
import git
import os
import rand
import time
import x.json2 as json

struct NamespaceQuota {
	id int @[primary; sql: serial]
mut:
	namespace         string @[unique]
	max_repositories  int
	max_storage_bytes i64
	updated_by        int
	updated_at        int
}

struct AbuseLimitBucket {
	id int @[primary; sql: serial]
mut:
	action         string @[unique: 'abuse_limit_bucket']
	key_hash       string @[unique: 'abuse_limit_bucket']
	window_started int
	request_count  int
	blocked_until  int
	updated_at     int
}

struct PlatformJob {
	id int @[primary; sql: serial]
mut:
	queue        string
	kind         string
	payload      string
	status       string
	priority     int
	attempts     int
	max_attempts int
	run_after    int
	locked_by    string
	locked_at    int
	last_error   string
	created_at   int
	finished_at  int
}

struct InstanceHeartbeat {
	id int @[primary; sql: serial]
mut:
	instance_id  string @[unique]
	version      string
	started_at   int
	last_seen_at int
	jobs_running int
}

struct InstanceBackup {
	id int @[primary; sql: serial]
mut:
	created_by   int
	status       string
	storage_key  string
	checksum     string
	size         i64
	started_at   int
	completed_at int
	last_error   string
}

struct DirectoryProvider {
	id int @[primary; sql: serial]
mut:
	kind             string
	name             string @[unique]
	base_url         string
	issuer           string
	client_id        string
	encrypted_secret string
	configuration    string
	enabled          bool
	created_by       int
	created_at       int
}

struct ExternalIdentity {
	id int @[primary; sql: serial]
mut:
	provider_id  int @[unique: 'external_identity']
	external_uid string @[unique: 'external_identity']
	user_id      int
	created_at   int
	last_seen_at int
	active       bool
}

struct ScimToken {
	id int @[primary; sql: serial]
mut:
	provider_id int
	created_by  int
	token_hash  string @[unique]
	created_at  int
	expires_at  int
	revoked     bool
}

struct ProjectExport {
	id int @[primary; sql: serial]
mut:
	repo_id          int
	created_by       int
	bundle_blob_id   int
	metadata_blob_id int
	checksum         string
	created_at       int
	expires_at       int
}

struct GroupExport {
	id int @[primary; sql: serial]
mut:
	org_id     int
	created_by int
	blob_id    int
	checksum   string
	created_at int
	expires_at int
}

struct ProjectExportMetadata {
	name           string
	namespace      string
	description    string
	default_branch string
	is_public      bool
	labels         []Label
	milestones     []Milestone
	issues         []ProjectExportIssue
}

struct ProjectExportIssue {
	source_id    int
	title        string
	text         string
	created_at   int
	status       int
	milestone_id int
	label_ids    []int
}

fn (app &App) project_export_issues(repo_id int) []ProjectExportIssue {
	issues := sql app.db {
		select from Issue where repo_id == repo_id && is_pr == false order by id
	} or { []Issue{} }
	mut exported := []ProjectExportIssue{cap: issues.len}
	for issue in issues {
		exported << ProjectExportIssue{
			source_id: issue.id
			title: issue.title
			text: issue.text
			created_at: issue.created_at
			status: int(issue.status)
			milestone_id: issue.milestone_id
			label_ids: app.get_issue_labels(issue.id).map(it.id)
		}
	}
	return exported
}

struct GroupExportPayload {
	group      Org
	subgroups  []Org
	epics      []Epic
	iterations []Iteration
}

fn (app &App) find_project_export(export_id int) ?ProjectExport {
	wanted_id := export_id
	rows := sql app.db {
		select from ProjectExport where id == wanted_id limit 1
	} or { []ProjectExport{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) find_group_export(export_id int) ?GroupExport {
	wanted_id := export_id
	rows := sql app.db {
		select from GroupExport where id == wanted_id limit 1
	} or { []GroupExport{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) find_namespace_quota(namespace string) ?NamespaceQuota {
	rows := sql app.db {
		select from NamespaceQuota where namespace == namespace limit 1
	} or { []NamespaceQuota{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (mut app App) set_namespace_quota(namespace string, max_repositories int,
	max_storage_bytes i64, actor_id int) ! {
	if namespace.trim_space() == '' || namespace.len > 255 || max_repositories < 0
		|| max_storage_bytes < 0 || actor_id <= 0 {
		return error('invalid namespace quota')
	}
	clean := namespace.trim_space().to_lower()
	existing := app.find_namespace_quota(clean) or { NamespaceQuota{} }
	now := int(time.now().unix())
	if existing.id == 0 {
		row := NamespaceQuota{
			namespace: clean
			max_repositories: max_repositories
			max_storage_bytes: max_storage_bytes
			updated_by: actor_id
			updated_at: now
		}
		sql app.db {
			insert row into NamespaceQuota
		}!
	} else {
		sql app.db {
			update NamespaceQuota set max_repositories = max_repositories,
			max_storage_bytes = max_storage_bytes, updated_by = actor_id, updated_at = now
			where namespace == clean
		}!
	}
}

fn platform_directory_size(path string) i64 {
	if !os.exists(path) {
		return 0
	}
	mut total := i64(0)
	for name in os.ls(path) or { return total } {
		entry := os.join_path(path, name)
		if os.is_dir(entry) {
			total += platform_directory_size(entry)
		} else if os.is_file(entry) {
			total += os.file_size(entry)
		}
	}
	return total
}

fn (app &App) namespace_storage_usage(namespace string) i64 {
	repos := sql app.db {
		select from Repo where user_name == namespace && is_deleted == false
	} or { []Repo{} }
	mut total := i64(0)
	mut blob_ids := map[int]bool{}
	for repo in repos {
		total += platform_directory_size(repo.git_dir)
		for artifact in app.list_repo_packages(repo.id) {
			blob_ids[artifact.blob_id] = true
		}
		for manifest in app.list_container_manifests(repo.id) {
			blob_ids[manifest.blob_id] = true
		}
		links := sql app.db {
			select from RepoLfsObject where repo_id == repo.id
		} or { []RepoLfsObject{} }
		for link in links {
			objects := sql app.db {
				select from LfsObject where id == link.lfs_object_id limit 1
			} or { []LfsObject{} }
			if objects.len == 1 {
				total += objects.first().size
			}
		}
	}
	for blob_id, _ in blob_ids {
		rows := sql app.db {
			select from PlatformBlob where id == blob_id limit 1
		} or { []PlatformBlob{} }
		if rows.len == 1 {
			total += rows.first().size
		}
	}
	return total
}

fn (app &App) ensure_namespace_storage_quota(namespace string, additional_bytes i64) ! {
	quota := app.find_namespace_quota(namespace) or { return }
	if quota.max_storage_bytes > 0
		&& app.namespace_storage_usage(namespace) + additional_bytes > quota.max_storage_bytes {
		return error('namespace storage quota would be exceeded')
	}
}

fn (app &App) ensure_namespace_repository_quota(namespace string) ! {
	quota := app.find_namespace_quota(namespace) or { return }
	if quota.max_repositories <= 0 {
		return
	}
	count := sql app.db {
		select count from Repo where user_name == namespace && is_deleted == false
	} or { 0 }
	if count >= quota.max_repositories {
		return error('namespace repository quota has been reached')
	}
}

fn (mut app App) consume_abuse_limit(action string, key string, limit int,
	window_seconds int) bool {
	if action.trim_space() == '' || key.trim_space() == '' || limit <= 0 || window_seconds <= 0 {
		return false
	}
	now := int(time.now().unix())
	hash := sha256.sum(key.bytes()).hex()
	rows := sql app.db {
		select from AbuseLimitBucket where action == action && key_hash == hash limit 1
	} or { []AbuseLimitBucket{} }
	if rows.len == 0 {
		row := AbuseLimitBucket{
			action: action
			key_hash: hash
			window_started: now
			request_count: 1
			updated_at: now
		}
		sql app.db {
			insert row into AbuseLimitBucket
		} or { return false }
		return true
	}
	row := rows.first()
	if row.blocked_until > now {
		return false
	}
	if row.window_started <= now - window_seconds {
		one := 1
		zero := 0
		sql app.db {
			update AbuseLimitBucket set window_started = now, request_count = one,
			blocked_until = zero, updated_at = now where id == row.id
		} or { return false }
		return true
	}
	next := row.request_count + 1
	blocked_until := if next > limit { row.window_started + window_seconds } else { 0 }
	sql app.db {
		update AbuseLimitBucket set request_count = next, blocked_until = blocked_until,
		updated_at = now where id == row.id
	} or { return false }
	return next <= limit
}

fn (mut app App) enqueue_platform_job(queue string, kind string, payload string, priority int,
	run_after int, max_attempts int) !int {
	if !valid_short_name(queue) || !valid_short_name(kind) || payload.len > max_body_len
		|| priority < -100 || priority > 100 || max_attempts < 1 || max_attempts > 100 {
		return error('invalid background job')
	}
	return db_insert_returning_id(mut app.db, 'PlatformJob', ['queue', 'kind', 'payload', 'status',
		'priority', 'attempts', 'max_attempts', 'run_after', 'locked_by', 'locked_at', 'last_error',
		'created_at', 'finished_at'], [queue.trim_space(), kind.trim_space(), payload, 'queued',
		priority.str(), '0', max_attempts.str(), run_after.str(), '', '0', '',
		int(time.now().unix()).str(), '0'])
}

fn (app &App) find_platform_job(id int) ?PlatformJob {
	rows := sql app.db {
		select from PlatformJob where id == id limit 1
	} or { []PlatformJob{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (mut app App) claim_platform_job(worker string, queue string) ?PlatformJob {
	now := int(time.now().unix())
	stale := now - 900
	candidates := if queue == '' {
		sql app.db {
			select from PlatformJob where run_after <= now
			&& (status == 'queued' || (status == 'running' && locked_at < stale))
			order by priority desc limit 10
		} or { []PlatformJob{} }
	} else {
		sql app.db {
			select from PlatformJob where queue == queue && run_after <= now
			&& (status == 'queued' || (status == 'running' && locked_at < stale))
			order by priority desc limit 10
		} or { []PlatformJob{} }
	}
	for candidate in candidates {
		rows := db_exec_values(mut app.db, 'update ${sql_table('PlatformJob')}
			set ${sql_table('status')} = \'running\', ${sql_table('locked_by')} = ${sql_literal(worker)},
			${sql_table('locked_at')} = ${now}, ${sql_table('attempts')} = ${candidate.attempts + 1}
			where ${sql_table('id')} = ${candidate.id}
			and (${sql_table('status')} = \'queued\' or ${sql_table('locked_at')} < ${stale})
			returning ${sql_table('id')}') or { continue }
		if rows.len == 1 {
			return app.find_platform_job(candidate.id)
		}
	}
	return none
}

fn (mut app App) complete_platform_job(id int) ! {
	now := int(time.now().unix())
	empty := ''
	sql app.db {
		update PlatformJob set status = 'complete', finished_at = now, locked_by = empty,
		locked_at = 0 where id == id && status == 'running'
	}!
}

fn (mut app App) fail_platform_job(job PlatformJob, message string) ! {
	now := int(time.now().unix())
	status := if job.attempts >= job.max_attempts { 'failed' } else { 'queued' }
	run_after := if status == 'queued' { now + job.attempts * 60 } else { job.run_after }
	finished := if status == 'failed' { now } else { 0 }
	empty := ''
	clean := message[..if message.len < 4096 { message.len } else { 4096 }]
	sql app.db {
		update PlatformJob set status = status, run_after = run_after, finished_at = finished,
		locked_by = empty, locked_at = 0, last_error = clean where id == job.id
	}!
}

fn (mut app App) execute_platform_job(job PlatformJob) ! {
	match job.kind {
		'package_retention' { app.apply_package_retention(job.payload.int())! }
		'container_retention' { app.apply_container_retention(job.payload.int())! }
		'telemetry_retention' { app.prune_telemetry(job.payload.int())! }
		else {
			return error('unknown background job kind `${job.kind}`')
		}
	}
}

fn resolved_instance_id(conf config.Config) string {
	if conf.instance_id.trim_space() != '' {
		return conf.instance_id.trim_space()
	}
	hostname := os.hostname() or { 'gitly' }
	return '${hostname}-${os.getpid()}'
}

fn (mut app App) heartbeat_instance(instance_id string) {
	now := int(time.now().unix())
	running := sql app.db {
		select count from PlatformJob where status == 'running' && locked_by == instance_id
	} or { 0 }
	rows := sql app.db {
		select from InstanceHeartbeat where instance_id == instance_id limit 1
	} or { []InstanceHeartbeat{} }
	if rows.len == 0 {
		row := InstanceHeartbeat{
			instance_id: instance_id
			version: app.version
			started_at: int(app.started_at)
			last_seen_at: now
			jobs_running: running
		}
		sql app.db {
			insert row into InstanceHeartbeat
		} or { return }
	} else {
		sql app.db {
			update InstanceHeartbeat set version = app.version, last_seen_at = now,
			jobs_running = running where instance_id == instance_id
		} or { return }
	}
}

fn run_platform_worker(conf config.Config) {
	instance_id := resolved_instance_id(conf)
	for {
		mut app := App{
			db: connect_db(conf) or {
				time.sleep(10 * time.second)
				continue
			}
			config: conf
			started_at: time.now().unix()
		}
		app.heartbeat_instance(instance_id)
		if job := app.claim_platform_job(instance_id, '') {
			app.execute_platform_job(job) or {
				app.fail_platform_job(job, err.msg()) or {}
				app.db.close() or {}
				time.sleep(time.second)
				continue
			}
			app.complete_platform_job(job.id) or {}
		}
		app.db.close() or {}
		time.sleep(5 * time.second)
	}
}

fn (mut app App) create_directory_provider(kind string, name string, base_url string,
	issuer string, client_id string, secret string, configuration string, actor_id int) !int {
	type_name := kind.trim_space().to_lower()
	if type_name !in ['ldap', 'saml', 'scim'] || !valid_short_name(name) || base_url.len > 2048
		|| issuer.len > 2048 || client_id.len > 1024 || configuration.len > max_body_len
		|| actor_id <= 0 {
		return error('invalid directory provider')
	}
	encrypted := if secret != '' {
		encrypt_mirror_secret(app.config.storage_secret, secret)!
	} else {
		''
	}
	return db_insert_returning_id(mut app.db, 'DirectoryProvider', ['kind', 'name', 'base_url',
		'issuer', 'client_id', 'encrypted_secret', 'configuration', 'enabled', 'created_by',
		'created_at'], [type_name, name.trim_space(), base_url.trim_space(), issuer.trim_space(),
		client_id.trim_space(), encrypted, configuration, db_bool_value(true), actor_id.str(),
		int(time.now().unix()).str()])
}

fn (app &App) find_directory_provider(id int) ?DirectoryProvider {
	rows := sql app.db {
		select from DirectoryProvider where id == id limit 1
	} or { []DirectoryProvider{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) list_directory_providers() []DirectoryProvider {
	return sql app.db {
		select from DirectoryProvider order by name
	} or { []DirectoryProvider{} }
}

fn (mut app App) set_directory_provider_enabled(id int, enabled bool, actor_id int) ! {
	if id <= 0 || actor_id <= 0 || app.find_directory_provider(id) == none {
		return error('directory provider not found')
	}
	sql app.db {
		update DirectoryProvider set enabled = enabled where id == id
	}!
}

fn (mut app App) create_scim_token(provider_id int, actor_id int, expires_at int) !(int, string) {
	provider := app.find_directory_provider(provider_id) or { return error('provider not found') }
	if !provider.enabled || actor_id <= 0 || (expires_at > 0 && expires_at <= int(time.now().unix())) {
		return error('invalid SCIM token')
	}
	secret := 'glscim_' + hex.encode(rand.bytes(24)!)
	id := db_insert_returning_id(mut app.db, 'ScimToken', ['provider_id', 'created_by', 'token_hash',
		'created_at', 'expires_at', 'revoked'], [provider_id.str(), actor_id.str(),
		hash_api_token(secret), int(time.now().unix()).str(), expires_at.str(), db_bool_value(false)])!
	return id, secret
}

fn (app &App) authenticate_scim_token(secret string) ?ScimToken {
	if !secret.starts_with('glscim_') || secret.len > 128 {
		return none
	}
	hash := hash_api_token(secret)
	now := int(time.now().unix())
	rows := sql app.db {
		select from ScimToken where token_hash == hash && revoked == false
		&& (expires_at == 0 || expires_at > now) limit 1
	} or { []ScimToken{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) list_scim_tokens(provider_id int) []ScimToken {
	return sql app.db {
		select from ScimToken where provider_id == provider_id order by id desc
	} or { []ScimToken{} }
}

fn (mut app App) revoke_scim_token(provider_id int, token_id int, actor_id int) ! {
	if provider_id <= 0 || token_id <= 0 || actor_id <= 0 {
		return error('invalid SCIM token')
	}
	revoked := true
	sql app.db {
		update ScimToken set revoked = revoked where provider_id == provider_id && id == token_id
	}!
}

fn (mut app App) provision_external_user(provider DirectoryProvider, external_uid string,
	username string, full_name string, email string, active bool) !User {
	if !provider.enabled || external_uid.trim_space() == '' || external_uid.len > 255
		|| !valid_service_desk_email(email) {
		return error('invalid external user')
	}
	existing := sql app.db {
		select from ExternalIdentity where provider_id == provider.id
		&& external_uid == external_uid limit 1
	}!
	if existing.len == 1 {
		identity := existing.first()
		user := app.get_user_by_id(identity.user_id) or { return error('provisioned user missing') }
		blocked := !active
		now := int(time.now().unix())
		mut tx := db_begin_transaction(mut app.db)!
		mut committed := false
		defer {
			if !committed {
				tx.rollback() or {}
			}
		}
		conflicting_emails := sql tx {
			select from Email where email == email && user_id != user.id limit 1
		}!
		if conflicting_emails.len > 0 {
			return error('email is already linked to another user')
		}
		emails := sql tx {
			select from Email where user_id == user.id order by id limit 1
		}!
		clean_email := email.trim_space().to_lower()
		if emails.len == 0 {
			row := Email{
				user_id: user.id
				email: clean_email
			}
			sql tx {
				insert row into Email
			}!
		} else {
			email_id := emails.first().id
			sql tx {
				update Email set email = clean_email where id == email_id
			}!
		}
		sql tx {
			update User set full_name = full_name, is_blocked = blocked where id == user.id
		}!
		sql tx {
			update ExternalIdentity set active = active, last_seen_at = now where id == identity.id
		}!
		tx.commit()!
		committed = true
		return app.get_user_by_id(user.id) or { return error('provisioned user missing') }
	}
	if app.get_user_by_username(username) != none {
		return error('username is already linked to another identity')
	}
	password := hash_password_with_salt('scim-' + rand.ulid(), '')
	app.register_user(username, password, '', [email], false, false)!
	user := app.get_user_by_username(username) or { return error('provisioned user missing') }
	blocked := !active
	now := int(time.now().unix())
	sql app.db {
		update User set full_name = full_name, is_blocked = blocked where id == user.id
	}!
	identity := ExternalIdentity{
		provider_id: provider.id
		external_uid: external_uid
		user_id: user.id
		created_at: now
		last_seen_at: now
		active: active
	}
	sql app.db {
		insert identity into ExternalIdentity
	}!
	return app.get_user_by_id(user.id) or { return error('provisioned user missing') }
}

fn (mut app App) create_project_export(repo Repo, actor_id int) !ProjectExport {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer {
		return error('Maintainer access is required')
	}
	temporary := os.join_path(os.temp_dir(), 'gitly-export-${repo.id}-${rand.ulid()}.bundle')
	defer {
		os.rm(temporary) or {}
	}
	result := git.Git.exec_in_dir(repo.git_dir, ['bundle', 'create', temporary, '--all'])
	if result.exit_code != 0 {
		return error('could not create Git bundle: ${result.output}')
	}
	bundle := os.read_bytes(temporary)!
	metadata := json.encode(ProjectExportMetadata{
		name: repo.name
		namespace: repo.user_name
		description: repo.description
		default_branch: repo.primary_branch
		is_public: repo.is_public
		labels: app.list_repo_labels(repo.id)
		milestones: app.list_repo_milestones(repo.id)
		issues: app.project_export_issues(repo.id)
	})
	bundle_blob := app.store_platform_blob('exports', bundle)!
	metadata_blob := app.store_platform_blob('exports', metadata.bytes())!
	now := int(time.now().unix())
	id := db_insert_returning_id(mut app.db, 'ProjectExport', ['repo_id', 'created_by',
		'bundle_blob_id', 'metadata_blob_id', 'checksum', 'created_at', 'expires_at'], [
		repo.id.str(),
		actor_id.str(),
		bundle_blob.id.str(),
		metadata_blob.id.str(),
		bundle_blob.oid,
		now.str(),
		(now + 7 * 86400).str(),
	])!
	rows := sql app.db {
		select from ProjectExport where id == id limit 1
	}!
	return rows.first()
}

fn (mut app App) import_project_export(export ProjectExport, target Repo, actor_id int) ! {
	if app.repo_access_level(actor_id, target) < project_access_maintainer {
		return error('Maintainer access is required')
	}
	source := app.find_repo_by_id(export.repo_id) or { return error('export source project not found') }
	if !app.user_has_repo_read_access(actor_id, source) {
		return error('source project read access is required')
	}
	refs := git.Git.exec_in_dir(target.git_dir, ['for-each-ref', '--format=%(refname)'])
	if refs.exit_code != 0 || refs.output.trim_space() != '' {
		return error('project import target must be empty')
	}
	data := app.load_platform_blob(export.bundle_blob_id)!
	if sha256.sum(data).hex() != export.checksum {
		return error('project export checksum mismatch')
	}
	temporary := os.join_path(os.temp_dir(), 'gitly-import-${target.id}-${rand.ulid()}.bundle')
	defer {
		os.rm(temporary) or {}
	}
	os.write_file_array(temporary, data)!
	result := git.Git.exec_in_dir(target.git_dir, ['fetch', temporary, 'refs/heads/*:refs/heads/*',
		'refs/tags/*:refs/tags/*'])
	if result.exit_code != 0 {
		return error('could not import Git bundle: ${result.output}')
	}
	metadata_data := app.load_platform_blob(export.metadata_blob_id)!
	metadata := json.decode[ProjectExportMetadata](metadata_data.bytestr())!
	default_branch := metadata.default_branch
	mut branch := target.primary_branch
	if is_safe_ref(default_branch) {
		branch_ref := 'refs/heads/${default_branch}'
		if git.Git.exec_in_dir(target.git_dir, ['rev-parse', '--verify', branch_ref]).exit_code == 0 {
			branch = default_branch
		}
	}
	// Importing must never make a private target public as a side effect.
	app.update_repo_general_settings(target.id, metadata.description, target.is_public, branch)!
	mut label_ids := map[int]int{}
	for label in metadata.labels {
		new_id := app.find_or_create_label(target.id, label.name, label.color) or { continue }
		label_ids[label.id] = new_id
	}
	mut milestone_ids := map[int]int{}
	for milestone in metadata.milestones {
		new_id := app.add_milestone(target.id, milestone.title, milestone.description, milestone.due_date) or { continue }
		if milestone.is_closed {
			app.set_milestone_closed(new_id, true) or {}
		}
		milestone_ids[milestone.id] = new_id
	}
	for issue in metadata.issues {
		new_id := app.add_imported_issue_returning_id(target.id, actor_id, issue.title, issue.text, issue.created_at) or { continue }
		if issue.status == int(IssueStatus.closed) {
			app.set_issue_status(new_id, .closed) or {}
		}
		if issue.milestone_id in milestone_ids {
			mapped_milestone := milestone_ids[issue.milestone_id]
			sql app.db {
				update Issue set milestone_id = mapped_milestone where id == new_id
			} or {}
		}
		for label_id in issue.label_ids {
			if label_id in label_ids {
				app.add_issue_label(new_id, label_ids[label_id]) or {}
			}
		}
	}
	app.sync_repo_open_issue_count(target.id)!
	mut updated_target := target
	app.update_repo_from_fs(mut updated_target, true)!
}

fn (mut app App) create_group_export(org Org, actor_id int) !GroupExport {
	if !app.user_can_admin_group(actor_id, org.id) {
		return error('group administrator access is required')
	}
	payload := json.encode(GroupExportPayload{
		group: org
		subgroups: app.find_subgroups(org.id)
		epics: app.find_group_epics(org.id)
		iterations: app.find_group_iterations(org.id)
	})
	blob := app.store_platform_blob('exports', payload.bytes())!
	now := int(time.now().unix())
	id := db_insert_returning_id(mut app.db, 'GroupExport', ['org_id', 'created_by', 'blob_id',
		'checksum', 'created_at', 'expires_at'], [org.id.str(), actor_id.str(), blob.id.str(),
		blob.oid, now.str(), (now + 7 * 86400).str()])!
	rows := sql app.db {
		select from GroupExport where id == id limit 1
	}!
	return rows.first()
}

fn (mut app App) import_group_export(export GroupExport, target Org, actor_id int) ! {
	if !app.user_can_admin_group(actor_id, target.id) {
		return error('group administrator access is required')
	}
	source := app.get_org_by_id(export.org_id) or { return error('export source group not found') }
	if !app.user_can_admin_group(actor_id, source.id) {
		return error('source group administrator access is required')
	}
	data := app.load_platform_blob(export.blob_id)!
	if sha256.sum(data).hex() != export.checksum {
		return error('group export checksum mismatch')
	}
	payload := json.decode[GroupExportPayload](data.bytestr())!
	for subgroup in payload.subgroups {
		path := subgroup.name.all_after_last('/')
		if app.get_org_by_name('${target.name}/${path}') == none {
			app.add_subgroup(target.id, path, subgroup.display_name, actor_id)!
		}
	}
	for epic in payload.epics {
		app.add_epic(target.id, 0, actor_id, epic.title, epic.description, epic.starts_at, epic.due_at)!
	}
	for iteration in payload.iterations {
		app.add_iteration(target.id, iteration.title, iteration.description, iteration.starts_at, iteration.due_at)!
	}
}

fn run_process(executable string, args []string, environment map[string]string) ! {
	path := os.find_abs_path_of_executable(executable) or {
		return error('${executable} is not installed')
	}
	mut process := os.new_process(path)
	process.set_args(args)
	if environment.len > 0 {
		process.set_environment(environment)
	}
	process.set_redirect_stdio()
	process.run()
	process.wait()
	stderr := process.stderr_slurp()
	code := process.code
	process.close()
	if code != 0 {
		return error('${executable} failed: ${stderr}')
	}
}

fn (mut app App) create_instance_backup(actor_id int) !InstanceBackup {
	if actor_id <= 0 {
		return error('administrator identity is required')
	}
	now := int(time.now().unix())
	id := db_insert_returning_id(mut app.db, 'InstanceBackup', ['created_by', 'status', 'storage_key',
		'checksum', 'size', 'started_at', 'completed_at', 'last_error'], [
		actor_id.str(),
		'running',
		'',
		'',
		'0',
		now.str(),
		'0',
		'',
	])!
	return app.complete_instance_backup(id, now) or {
		message := err.msg()[..if err.msg().len < 4096 { err.msg().len } else { 4096 }]
		failed := 'failed'
		completed := int(time.now().unix())
		sql app.db {
			update InstanceBackup set status = failed, completed_at = completed,
			last_error = message where id == id
		} or {}
		return error(message)
	}
}

fn (mut app App) complete_instance_backup(id int, now int) !InstanceBackup {
	temporary_dir := os.join_path(os.temp_dir(), 'gitly-backup-${id}-${rand.ulid()}')
	os.mkdir_all(temporary_dir)!
	defer {
		os.rmdir_all(temporary_dir) or {}
	}
	database_path := os.join_path(temporary_dir, 'database.dump')
	$if sqlite ? {
		app.db.exec('vacuum into ${sql_literal(database_path)}')!
	} $else {
		mut environment := os.environ()
		environment['PGPASSWORD'] = app.config.pg.password
		mut args := ['--format=custom', '--file=${database_path}', '--host=${app.config.pg.host}',
			'--port=${app.config.pg.port}', '--username=${app.config.pg.user}', app.config.pg.dbname]
		if app.config.pg.conninfo != '' {
			args = ['--format=custom', '--file=${database_path}',
				'--dbname=${app.config.pg.conninfo}']
		}
		run_process('pg_dump', args, environment)!
	}
	manifest := json.encode({
		'created_at':       now.str()
		'version':          app.version
		'database_backend': db_backend_name()
		'repository_root':  app.config.repo_storage_path
	})
	os.write_file(os.join_path(temporary_dir, 'manifest.json'), manifest)!
	archive := os.join_path(os.temp_dir(), 'gitly-backup-${id}-${rand.ulid()}.tar.gz')
	defer {
		os.rm(archive) or {}
	}
	repository_root_name := os.base(app.config.repo_storage_path)
	mut args := ['-czf', archive, '--exclude=${repository_root_name}/.gitly-objects/backups']
	object_root := app.object_store_local_root()
	repository_prefix := app.config.repo_storage_path.trim_string_right('/') + '/'
	include_separate_object_root := app.config.object_storage_url == ''
		&& object_root != app.config.repo_storage_path && !object_root.starts_with(repository_prefix)
	if include_separate_object_root {
		object_root_name := os.base(object_root)
		args << '--exclude=${object_root_name}/backups'
	}
	args << '-C'
	args << temporary_dir
	args << '.'
	args << '-C'
	args << os.dir(app.config.repo_storage_path)
	args << repository_root_name
	if include_separate_object_root {
		args << '-C'
		args << os.dir(object_root)
		args << os.base(object_root)
	}
	run_process('tar', args, {})!
	data := os.read_bytes(archive)!
	checksum := sha256.sum(data).hex()
	key := 'backups/${now}-${id}-${checksum[..12]}.tar.gz'
	app.object_store_put(key, data)!
	completed := int(time.now().unix())
	sql app.db {
		update InstanceBackup set status = 'complete', storage_key = key, checksum = checksum,
		size = data.len, completed_at = completed where id == id
	}!
	rows := sql app.db {
		select from InstanceBackup where id == id limit 1
	}!
	return rows.first()
}

fn (app &App) verify_instance_backup(id int) !bool {
	rows := sql app.db {
		select from InstanceBackup where id == id && status == 'complete' limit 1
	}!
	if rows.len != 1 {
		return error('backup not found')
	}
	data := app.object_store_get(rows.first().storage_key)!
	return i64(data.len) == rows.first().size && sha256.sum(data).hex() == rows.first().checksum
}
