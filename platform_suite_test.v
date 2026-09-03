module main

import config
import crypto.sha256
import git
import os
import time

fn platform_test_app(root string) !&App {
	repositories := os.join_path(root, 'repos')
	objects := os.join_path(root, 'objects')
	os.mkdir_all(repositories)!
	os.mkdir_all(objects)!
	conf := config.Config{
		repo_storage_path: repositories
		archive_path: os.join_path(root, 'archives')
		avatars_path: os.join_path(root, 'avatars')
		object_storage_path: objects
		storage_secret: 'platform-test-secret-that-is-long-enough'
		max_package_size_bytes: 16 * 1024 * 1024
		sqlite: config.SqliteConfig{
			path: os.join_path(root, 'test.sqlite')
		}
	}
	mut app := &App{
		db: connect_db(conf)!
		config: conf
		started_at: time.now().unix()
	}
	app.create_tables()!
	app.migrate_tables()!
	return app
}

fn insert_platform_user(mut app App, id int, username string, is_admin bool) ! {
	user := User{
		id: id
		username: username
		is_registered: true
		is_admin: is_admin
	}
	sql app.db {
		insert user into User
	}!
}

fn insert_platform_repo(mut app App, id int, owner_id int, owner string, name string,
	git_dir string, is_public bool) !Repo {
	app.add_repo(Repo{
		id: id
		git_dir: git_dir
		name: name
		user_id: owner_id
		user_name: owner
		is_public: is_public
		primary_branch: 'main'
		status: .done
	})!
	return app.find_repo_by_id(id) or { return error('project was not saved') }
}

fn test_platform_delivery_security_operations_and_administration() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_platform_suite_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		defer {
			os.rmdir_all(root) or {}
		}
		mut app := platform_test_app(root)!
		defer {
			app.db.close() or {}
		}
		insert_platform_user(mut app, 1, 'owner', true)!
		insert_platform_user(mut app, 2, 'member', false)!
		bare := os.join_path(root, 'repos', 'owner', 'project.git')
		os.mkdir_all(os.dir(bare))!
		assert git.Git.exec(['init', '--bare', bare]).exit_code == 0
		repo := insert_platform_repo(mut app, 1, 1, 'owner', 'project', bare, true)!
		app.add_project_member(repo.id, 2, 'developer')!

		artifact1 := app.publish_package(repo, 2, 'npm', '@scope/pkg', '1.0.0', 'pkg.tgz', 'package-one'.bytes(), '{"builder":"test"}', 'signature', 'test-key')!
		assert artifact1.provenance_signature == 'signature'
		_, downloaded := app.download_package(repo.id, artifact1.id)!
		assert downloaded.bytestr() == 'package-one'
		mut duplicate_rejected := false
		app.publish_package(repo, 2, 'npm', '@scope/pkg', '1.0.0', 'pkg.tgz', 'different'.bytes(), '', '', '') or { duplicate_rejected = true }
		assert duplicate_rejected
		artifact2 := app.publish_package(repo, 2, 'npm', '@scope/pkg', '2.0.0', 'pkg.tgz', 'package-two'.bytes(), '', '', '')!
		app.set_package_retention(repo.id, true, 1, 0, true)!
		assert app.apply_package_retention(repo.id)! == 1
		assert app.find_package(repo.id, artifact1.id) == none
		assert app.find_package(repo.id, artifact2.id) != none

		manifest1 := app.publish_container_manifest(repo, 2, 'project/app', 'v1', 'application/vnd.oci.image.manifest.v1+json', '{"schemaVersion":2,"v":1}'.bytes())!
		app.set_container_manifest_protected(repo, 1, manifest1.id, true)!
		mut protected_replace_rejected := false
		app.publish_container_manifest(repo, 2, 'project/app', 'v1', 'application/vnd.oci.image.manifest.v1+json', '{"schemaVersion":2,"v":2}'.bytes()) or {
			protected_replace_rejected = true
		}
		assert protected_replace_rejected
		mut protected_delete_rejected := false
		app.delete_container_manifest(repo, 1, manifest1.id) or { protected_delete_rejected = true }
		assert protected_delete_rejected
		manifest2 := app.publish_container_manifest(repo, 2, 'project/app', 'v2', 'application/vnd.oci.image.manifest.v1+json', '{"schemaVersion":2,"v":2}'.bytes())!
		app.publish_container_manifest(repo, 2, 'project/app', 'v3', 'application/vnd.oci.image.manifest.v1+json', '{"schemaVersion":2,"v":3}'.bytes())!
		app.set_container_retention(repo, 1, true, 1, 0, true)!
		assert app.apply_container_retention(repo.id)! == 1
		assert app.find_container_manifest(repo.id, 'project/app', 'v1') != none
		assert app.find_container_manifest(repo.id, 'project/app', 'v2') == none
		app.set_container_manifest_protected(repo, 1, manifest1.id, false)!
		app.delete_container_manifest(repo, 1, manifest1.id)!
		assert app.find_container_manifest(repo.id, 'project/app', 'v1') == none
		assert manifest2.id > 0
		upload := app.start_container_upload(repo, 2, project_access_developer)!
		app.append_container_upload(repo, upload.uuid, project_access_developer, 'chunk-one'.bytes())!
		mut bad_upload_digest_rejected := false
		app.finish_container_upload(repo, upload.uuid, 2, project_access_developer, 'sha256:${'0'.repeat(64)}', []) or { bad_upload_digest_rejected = true }
		assert bad_upload_digest_rejected
		assert app.find_container_upload(repo.id, upload.uuid) != none
		upload_data := 'chunk-one-final'.bytes()
		upload_digest := sha256.sum(upload_data).hex()
		uploaded := app.finish_container_upload(repo, upload.uuid, 2, project_access_developer, 'sha256:${upload_digest}', '-final'.bytes())!
		assert uploaded.oid == upload_digest
		assert app.repo_has_container_blob(repo.id, upload_digest)
		assert app.find_container_upload(repo.id, upload.uuid) == none
		assert !dependency_proxy_url_allowed('http://127.0.0.1/package', ['127.0.0.1'])
		assert !dependency_proxy_url_allowed('https://example.com/package', [])

		commit_sha := 'a'.repeat(40)
		app.add_security_policy(repo, 1, 'main-policy', 'main', 'sast', 'critical', 24, '', true)!
		assert !app.security_gate(repo, 'main', commit_sha).allowed
		scan_id := app.start_security_scan(repo, 2, 'sast', 'main', commit_sha, 'semgrep', 'json')!
		scan := app.find_security_scan(repo.id, scan_id) or { panic('scan missing') }
		finding := app.record_security_finding(scan, 'Unsafe execution', 'Untrusted input reaches a shell', 'critical', 'src/main.v:10', 'CWE-78', '{}', '')!
		app.finish_security_scan(scan, true, '')!
		blocked := app.security_gate(repo, 'main', commit_sha)
		assert !blocked.allowed
		assert blocked.reasons.any(it.contains('Unsafe execution'))
		app.set_vulnerability_state(repo.id, finding.id, 1, 'dismissed', 'false positive')!
		assert app.security_gate(repo, 'main', commit_sha).allowed
		assert !app.security_gate(repo, 'main', 'b'.repeat(40)).allowed
		app.add_merge_approval_policy(repo, 1, 'maintainers', 'main', 2, 'maintainer')!
		assert app.required_approvals_for_branch(repo, 'main') == 2
		framework_id := app.add_compliance_framework('SOC 2', 'Controls', 'CC6.1', 1)!
		app.assign_compliance_framework(repo.id, framework_id, 1)!
		app.record_audit_event('project', repo.id, 1, 'policy.test', 'project', repo.id.str(), 'validated', '192.0.2.1')
		assert app.list_audit_events('project', repo.id, 0).len == 1
		assert app.export_audit_events('project', repo.id, 0).contains('policy.test')

		agent, agent_secret := app.create_cluster_agent(repo, 1, 'production-agent', 'production', '{"namespace":"default"}')!
		assert agent.token_hash != agent_secret
		contact := app.cluster_agent_heartbeat(agent_secret, '192.0.2.2', '1.31', '{}')!
		assert contact.last_contact_at > 0
		app.revoke_cluster_agent(repo.id, agent.id)!
		assert app.cluster_agent_heartbeat(agent_secret, '', '', '{}') or { ClusterAgent{} }.id == 0
		flag_id := app.add_feature_flag(repo, 2, 'new-ui', '', 'targets', 0, 'production', 'Member,other')!
		flag := app.find_feature_flag(repo.id, 'new-ui') or { panic('feature flag missing') }
		assert feature_flag_enabled(flag, 'production', 'member')
		assert !feature_flag_enabled(flag, 'staging', 'member')
		app.set_feature_flag_active(repo.id, flag_id, false)!
		assert !feature_flag_enabled(app.find_feature_flag(repo.id, 'new-ui') or { FeatureFlag{} }, 'production', 'member')
		incident_id := app.create_incident(repo, 2, 'Database latency', 'Elevated latency', 'high', '')!
		app.add_incident_note(incident_id, 2, 'Investigating')!
		app.update_incident(repo.id, incident_id, 'resolved', 'high', 2)!
		assert (app.find_incident(repo.id, incident_id) or { Incident{} }).resolved_at > 0
		integration, alert_secret := app.create_alert_integration(repo, 1, 'monitoring')!
		assert integration.token_hash != alert_secret
		alert1 := app.ingest_alert(alert_secret, 'database-latency', 'Database latency', 'high', '{"value":900}')!
		alert2 := app.ingest_alert(alert_secret, 'database-latency', 'Database latency', 'high', '{"value":901}')!
		assert alert1.id == alert2.id
		telemetry_id := app.record_telemetry(repo, 'metric', 'api', 'production', '', 'latency', '900', '{}')!
		assert telemetry_id > 0
		assert app.list_telemetry(repo.id, 'metric').len == 1
		schedule_id := app.add_on_call_schedule(repo, 1, 'primary', 'UTC', 3600)!
		schedule := app.find_on_call_schedule(repo.id, schedule_id) or { panic('schedule missing') }
		app.add_on_call_rotation(schedule, 2, 0, 0, 0)!
		assert (app.on_call_user(schedule, int(time.now().unix())) or { User{} }).id == 2

		assert app.consume_abuse_limit('test', 'client', 2, 60)
		assert app.consume_abuse_limit('test', 'client', 2, 60)
		assert !app.consume_abuse_limit('test', 'client', 2, 60)
		job_id := app.enqueue_platform_job('default', 'telemetry_retention', '30', 10, int(time.now().unix()), 2)!
		job := app.claim_platform_job('worker-1', 'default') or { panic('job was not claimed') }
		assert job.id == job_id
		assert job.attempts == 1
		app.execute_platform_job(job)!
		app.complete_platform_job(job.id)!
		assert (app.find_platform_job(job.id) or { PlatformJob{} }).status == 'complete'
		app.heartbeat_instance('instance-a')
		assert sql app.db {
			select count from InstanceHeartbeat where instance_id == 'instance-a'
		}! == 1

		provider_id := app.create_directory_provider('scim', 'workforce', 'https://id.example.test', 'https://id.example.test', 'gitly', 'provider-secret', '{}', 1)!
		provider := app.find_directory_provider(provider_id) or { panic('provider missing') }
		assert provider.encrypted_secret != 'provider-secret'
		assert decrypt_mirror_secret(app.config.storage_secret, provider.encrypted_secret)! == 'provider-secret'
		_, scim_secret := app.create_scim_token(provider.id, 1, int(time.now().unix()) + 3600)!
		assert (app.authenticate_scim_token(scim_secret) or { ScimToken{} }).provider_id == provider.id
		external := app.provision_external_user(provider, 'directory-1', 'external-user', 'External User', 'external@example.test', true)!
		updated := app.provision_external_user(provider, 'directory-1', 'ignored-new-name', 'Updated User', 'new-external@example.test', false)!
		assert external.id == updated.id
		assert updated.username == 'external-user'
		assert updated.is_blocked
		updated_user_id := updated.id
		assert sql app.db {
			select count from Email where user_id == updated_user_id
			&& email == 'new-external@example.test'
		}! == 1

		app.set_namespace_quota('owner', 1, 1, 1)!
		mut repo_quota_rejected := false
		app.ensure_namespace_repository_quota('owner') or { repo_quota_rejected = true }
		assert repo_quota_rejected
		mut storage_quota_rejected := false
		app.publish_package(repo, 2, 'generic', 'blocked', '1', 'blocked.bin', 'data'.bytes(), '', '', '') or {
			storage_quota_rejected = true
		}
		assert storage_quota_rejected

		corrupt := app.store_platform_blob('test', 'integrity-check'.bytes())!
		os.write_file(os.join_path(app.config.object_storage_path, corrupt.storage_key), 'corrupt')!
		mut corruption_detected := false
		app.load_platform_blob(corrupt.id) or { corruption_detected = true }
		assert corruption_detected
	} $else {
		assert true
	}
}

fn test_project_export_import_and_verified_backup() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_platform_export_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		defer {
			os.rmdir_all(root) or {}
		}
		work := os.join_path(root, 'work')
		source_bare := os.join_path(root, 'repos', 'owner', 'source.git')
		target_bare := os.join_path(root, 'repos', 'owner', 'target.git')
		assert git.Git.exec(['init', '-b', 'main', work]).exit_code == 0
		assert git.Git.exec_in_dir(work, ['config', 'user.name', 'Owner']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['config', 'user.email', 'owner@example.test']).exit_code == 0
		os.write_file(os.join_path(work, 'README.md'), 'exported\n')!
		assert git.Git.exec_in_dir(work, ['add', 'README.md']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['commit', '-m', 'initial']).exit_code == 0
		os.mkdir_all(os.dir(source_bare))!
		assert git.Git.exec(['clone', '--bare', work, source_bare]).exit_code == 0
		assert git.Git.exec(['init', '--bare', target_bare]).exit_code == 0

		mut app := platform_test_app(root)!
		defer {
			app.db.close() or {}
		}
		insert_platform_user(mut app, 1, 'owner', true)!
		source := insert_platform_repo(mut app, 1, 1, 'owner', 'source', source_bare, true)!
		target := insert_platform_repo(mut app, 2, 1, 'owner', 'target', target_bare, false)!
		label_id := app.add_repo_label(source.id, 'priority::high', '#ff0000')!
		milestone_id := app.add_milestone(source.id, 'Version 1', 'First release', 0)!
		issue_id := app.add_issue_returning_id(source.id, 1, 'Exported issue', 'Issue body')!
		app.add_issue_label(issue_id, label_id)!
		sql app.db {
			update Issue set milestone_id = milestone_id where id == issue_id
		}!
		app.set_issue_status(issue_id, .closed)!

		export := app.create_project_export(source, 1)!
		assert export.checksum.len == 64
		app.import_project_export(export, target, 1)!
		assert git.Git.exec_in_dir(target_bare, ['rev-parse', '--verify', 'refs/heads/main']).exit_code == 0
		imported_target := app.find_repo_by_id(target.id) or { panic('target missing') }
		assert !imported_target.is_public
		assert app.list_repo_labels(target.id).any(it.name == 'priority::high')
		assert app.list_repo_milestones(target.id).any(it.title == 'Version 1')
		imported_issues := app.find_repo_issues_as_page_by_state(target.id, 0, 'all')
		assert imported_issues.len == 1
		assert imported_issues.first().title == 'Exported issue'
		assert imported_issues.first().status == .closed
		assert app.get_issue_labels(imported_issues.first().id).any(it.name == 'priority::high')

		backup := app.create_instance_backup(1)!
		assert backup.status == 'complete'
		assert backup.size > 0
		assert app.verify_instance_backup(backup.id)!
	} $else {
		assert true
	}
}
