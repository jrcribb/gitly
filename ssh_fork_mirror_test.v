module main

import os
import config
import git
import time

fn transport_test_app(root string) !(&App, string) {
	db_path := os.join_path(root, 'transport.sqlite')
	conf := config.Config{
		repo_storage_path:        os.join_path(root, 'repos')
		archive_path:             root
		avatars_path:             root
		storage_secret:           'transport-test-secret-that-is-long-enough'
		ssh_enabled:              true
		ssh_hostname:             'git.example.test'
		ssh_port:                 2222
		ssh_user:                 'git'
		ssh_authorized_keys_path: os.join_path(root, 'authorized_keys')
		sqlite:                   config.SqliteConfig{
			path: db_path
		}
	}
	os.mkdir_all(conf.repo_storage_path)!
	mut app := &App{
		db:     connect_db(conf)!
		config: conf
	}
	app.create_tables()!
	return app, db_path
}

fn transport_git(args []string) string {
	result := git.Git.exec(args)
	if result.exit_code != 0 {
		panic('git ${args} failed: ${result.output}')
	}
	return result.output.trim_space()
}

fn transport_commit(work string, content string, message string) string {
	os.write_file(os.join_path(work, 'README.md'), content) or { panic(err) }
	transport_git(['-C', work, 'add', 'README.md'])
	transport_git(['-C', work, 'commit', '-m', message])
	return transport_git(['-C', work, 'rev-parse', 'HEAD'])
}

fn initialize_transport_origin(root string) !(string, string) {
	bare := os.join_path(root, 'source.git')
	work := os.join_path(root, 'source-work')
	transport_git(['init', '--bare', bare])
	transport_git(['init', '-b', 'main', work])
	transport_git(['-C', work, 'config', 'user.name', 'Transport Test'])
	transport_git(['-C', work, 'config', 'user.email', 'transport@example.test'])
	transport_git(['-C', work, 'remote', 'add', 'origin', bare])
	transport_commit(work, 'initial\n', 'initial')
	transport_git(['-C', work, 'push', '-u', 'origin', 'main'])
	transport_git(['-C', bare, 'symbolic-ref', 'HEAD', 'refs/heads/main'])
	return bare, work
}

fn insert_transport_user(mut app App, id int, username string) ! {
	row := User{
		id:            id
		username:      username
		is_registered: true
	}
	sql app.db {
		insert row into User
	}!
}

fn test_forks_track_lineage_and_only_fast_forward_from_upstream() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_fork_transport_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		mut app, db_path := transport_test_app(root)!
		defer {
			app.db.close() or {}
			os.rmdir_all(root) or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		bare, work := initialize_transport_origin(root)!
		insert_transport_user(mut app, 1, 'alice')!
		insert_transport_user(mut app, 2, 'bob')!
		insert_transport_user(mut app, 3, 'charlie')!
		app.add_repo(Repo{
			id:             1
			git_dir:        bare
			name:           'project'
			user_id:        1
			user_name:      'alice'
			is_public:      true
			primary_branch: 'main'
			status:         .done
		})!
		source := app.find_repo_by_id(1) or { panic('source missing') }
		created := app.create_fork(source, 'bob', 2, 'project', 'fork', true, false, 2)!
		relation := app.find_fork_by_repo(created.id) or { panic('fork relationship missing') }
		assert relation.source_repo_id == source.id
		assert relation.root_repo_id == source.id
		assert app.count_repo_forks(source.id) == 1
		assert transport_git(['-C', created.git_dir, 'remote', 'get-url', 'upstream']) == bare
		descendant := app.create_fork(created, 'charlie', 3, 'project', 'nested fork', true, false, 3)!
		descendant_relation := app.find_fork_by_repo(descendant.id) or {
			panic('descendant fork relationship missing')
		}
		assert descendant_relation.source_repo_id == created.id
		assert descendant_relation.root_repo_id == source.id
		assert app.count_repo_forks(source.id) == 2
		assert app.count_repo_forks(created.id) == 2
		assert app.find_repo_forks(source.id).map(it.id).contains(descendant.id)
		assert app.find_repo_forks(created.id).map(it.id).contains(source.id)
		mut duplicate_namespace_rejected := false
		app.create_fork(source, 'bob', 2, 'another-project', '', true, false, 2) or {
			duplicate_namespace_rejected = true
		}
		assert duplicate_namespace_rejected
		transport_git(['-C', work, 'checkout', '-b', 'next-default'])
		next_default_sha := transport_commit(work, 'next default\n', 'next default')
		transport_git(['-C', work, 'push', 'origin', 'next-default'])
		transport_git(['-C', work, 'checkout', 'main'])
		app.update_repo_primary_branch(source.id, 'next-default')!
		default_only_sync := app.sync_fork(created, relation, true)!
		assert default_only_sync.updated == ['next-default']
		assert transport_git(['-C', created.git_dir, 'rev-parse', 'next-default']) == next_default_sha

		second := transport_commit(work, 'second\n', 'second')
		transport_git(['-C', work, 'push', 'origin', 'main'])
		first_sync := app.sync_fork(created, relation, false)!
		assert first_sync.updated.contains('main')
		assert transport_git(['-C', created.git_dir, 'rev-parse', 'main']) == second

		fork_work := os.join_path(root, 'fork-work')
		transport_git(['clone', created.git_dir, fork_work])
		transport_git(['-C', fork_work, 'config', 'user.name', 'Fork User'])
		transport_git(['-C', fork_work, 'config', 'user.email', 'fork@example.test'])
		transport_commit(fork_work, 'fork change\n', 'fork change')
		transport_git(['-C', fork_work, 'push', 'origin', 'main'])
		transport_commit(work, 'upstream change\n', 'upstream change')
		transport_git(['-C', work, 'push', 'origin', 'main'])
		diverged := app.sync_fork(created, relation, false)!
		assert diverged.skipped.contains('main')
		assert transport_git(['-C', created.git_dir, 'rev-parse', 'main']) != transport_git([
			'-C',
			bare,
			'rev-parse',
			'main',
		])

		missing_source := RepoFork{
			...relation
			source_repo_id: 999_999
		}
		mut missing_source_rejected := false
		app.sync_fork(created, missing_source, false) or { missing_source_rejected = true }
		assert missing_source_rejected
		stored_relation := app.find_fork_by_repo(created.id) or {
			panic('fork relationship missing')
		}
		assert stored_relation.last_sync_error == 'The upstream repository no longer exists'
		app.delete_repository(created.id, created.git_dir, created.name)!
		reparented := app.find_fork_by_repo(descendant.id) or {
			panic('descendant relationship missing after upstream deletion')
		}
		assert reparented.source_repo_id == source.id
		assert reparented.root_repo_id == source.id
		assert app.repos_share_fork_network(source.id, descendant.id)
	} $else {
		assert true
	}
}

fn test_ssh_keys_generate_managed_authorized_keys_and_clone_url() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_ssh_transport_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		mut app, db_path := transport_test_app(root)!
		defer {
			app.db.close() or {}
			os.rmdir_all(root) or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		insert_transport_user(mut app, 1, 'alice')!
		key := 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTp8P3nHx3Eu0PUM1Op46RGvl/9Ln+w8pqoW5b+RF9y test@example'
		app.add_ssh_key(1, 'Laptop', key, 'auth', 0)!
		managed := os.read_file(app.config.ssh_authorized_keys_path)!
		assert managed.contains(ssh_authorized_keys_begin)
		assert managed.contains('restrict,no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding')
		assert managed.contains('command=')
		assert managed.contains('ssh-shell')
		assert managed.contains('user')
		assert managed.contains(normalized_ssh_public_key(key) or { '' })
		keys := app.find_ssh_keys(1)
		assert keys.len == 1
		assert keys[0].fingerprint.starts_with('SHA256:')
		app.mark_ssh_key_used('user', keys[0].id, '192.0.2.10')
		used_key := app.find_ssh_key_by_id(keys[0].id) or { panic('SSH key missing') }
		assert used_key.last_used_at > 0
		assert used_key.last_used_ip == '192.0.2.10'
		assert used_key.to_api().last_used_ip == '192.0.2.10'
		assert app.generate_ssh_clone_url(Repo{
			user_name: 'alice'
			name:      'project'
		}) == 'ssh://git@git.example.test:2222/alice/project.git'
	} $else {
		assert true
	}
}

fn test_ssh_key_usage_and_expiry_are_enforced() {
	now := 1_800_000_000
	assert SshKey{
		usage_type: 'auth'
	}.usable_for_auth(now)
	assert SshKey{
		usage_type: 'auth_and_signing'
		expires_at: now + 1
	}.usable_for_auth(now)
	assert normalized_ssh_usage_type('both') or { '' } == 'auth_and_signing'
	assert !SshKey{
		usage_type: 'signing'
	}.usable_for_auth(now)
	assert !SshKey{
		usage_type: 'auth'
		expires_at: now
	}.usable_for_auth(now)
	assert !DeployKey{
		enabled:    true
		expires_at: now - 1
	}.usable_for_auth(now)
}

fn test_deploy_key_write_access_does_not_bypass_protected_branches_by_default() {
	assert deploy_key_access_level(DeployKey{}) == project_access_reporter
	assert deploy_key_access_level(DeployKey{
		can_push: true
	}) == project_access_developer
	assert deploy_key_access_level(DeployKey{
		can_push:           true
		can_push_protected: true
	}) == project_access_developer
}

fn test_deploy_key_protected_branch_grants_are_explicit_and_repo_scoped() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_deploy_grants_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		mut app, db_path := transport_test_app(root)!
		defer {
			app.db.close() or {}
			os.rmdir_all(root) or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		insert_transport_user(mut app, 1, 'owner')!
		app.add_repo(Repo{
			id:             1
			name:           'project'
			user_id:        1
			user_name:      'owner'
			primary_branch: 'main'
		})!
		app.add_repo(Repo{
			id:             2
			name:           'other'
			user_id:        1
			user_name:      'owner'
			primary_branch: 'main'
		})!
		main_rule := app.protect_branch(1, 'main', project_access_maintainer,
			project_access_maintainer)!
		release_rule := app.protect_branch(1, 'release/*', project_access_maintainer,
			project_access_maintainer)!
		other_repo_rule := app.protect_branch(2, 'main', project_access_maintainer,
			project_access_maintainer)!
		key := 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTp8P3nHx3Eu0PUM1Op46RGvl/9Ln+w8pqoW5b+RF9z deploy@example'
		app.add_deploy_key(1, 1, 'Automation', key, true, 0)!
		deploy_key := app.find_repo_deploy_keys(1).first()
		assert app.deploy_key_protected_branch_grants_env(1, deploy_key.id) == ''

		app.grant_deploy_key_protected_branch(1, deploy_key.id, main_rule, 1)!
		assert app.deploy_key_has_protected_branch_grant(1, deploy_key.id, main_rule)
		assert !app.deploy_key_has_protected_branch_grant(1, deploy_key.id, release_rule)
		assert app.deploy_key_protected_branch_grants_env(1, deploy_key.id) == main_rule.str()
		assert app.deploy_key_to_api(deploy_key).protected_branch_ids == [main_rule]
		assert !app.deploy_key_to_api(deploy_key).can_push_protected
		mut cross_repo_rejected := false
		app.grant_deploy_key_protected_branch(1, deploy_key.id, other_repo_rule, 1) or {
			cross_repo_rejected = true
		}
		assert cross_repo_rejected
		read_only := DeployKey{
			id:         99
			repo_id:    1
			created_by: 1
			title:      'Read-only automation'
			enabled:    true
		}
		sql app.db {
			insert read_only into DeployKey
		}!
		mut read_only_rejected := false
		app.grant_deploy_key_protected_branch(1, read_only.id, main_rule, 1) or {
			read_only_rejected = true
		}
		assert read_only_rejected

		app.revoke_deploy_key_protected_branch(1, deploy_key.id, main_rule)!
		assert !app.deploy_key_has_protected_branch_grant(1, deploy_key.id, main_rule)
		app.grant_deploy_key_protected_branch(1, deploy_key.id, release_rule, 1)!
		app.unprotect_branch(1, release_rule)!
		assert app.find_repo_deploy_key_grants(1).len == 0
		app.grant_deploy_key_protected_branch(1, deploy_key.id, main_rule, 1)!
		app.remove_deploy_key(1, deploy_key.id)!
		assert app.find_repo_deploy_key_grants(1).len == 0
	} $else {
		assert true
	}
}

fn test_legacy_broad_deploy_key_access_is_migrated_once() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_deploy_grants_migration_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		mut app, db_path := transport_test_app(root)!
		defer {
			app.db.close() or {}
			os.rmdir_all(root) or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		app.add_repo(Repo{
			id:             1
			name:           'project'
			user_id:        1
			user_name:      'owner'
			primary_branch: 'main'
		})!
		first_rule := app.protect_branch(1, 'main', project_access_maintainer,
			project_access_maintainer)!
		legacy := DeployKey{
			id:                 10
			repo_id:            1
			created_by:         1
			title:              'Legacy automation'
			can_push:           true
			can_push_protected: true
			enabled:            true
		}
		sql app.db {
			insert legacy into DeployKey
		}!
		app.backfill_deploy_key_protected_branch_grants()!
		assert app.deploy_key_has_protected_branch_grant(1, legacy.id, first_rule)
		migrated := app.find_deploy_key_by_id(legacy.id) or { panic('legacy key missing') }
		assert migrated.protected_grants_migrated

		later_rule := app.protect_branch(1, 'release/*', project_access_maintainer,
			project_access_maintainer)!
		app.backfill_deploy_key_protected_branch_grants()!
		assert !app.deploy_key_has_protected_branch_grant(1, legacy.id, later_rule)
	} $else {
		assert true
	}
}

fn test_mirror_credentials_use_authenticated_encryption() {
	secret := 'a-long-storage-secret-for-tests'
	ciphertext := encrypt_mirror_secret(secret, 'sensitive-token')!
	assert ciphertext != 'sensitive-token'
	assert !ciphertext.contains('sensitive-token')
	assert decrypt_mirror_secret(secret, ciphertext)! == 'sensitive-token'
	mut tampered := ciphertext.bytes()
	tampered[tampered.len - 2] = if tampered[tampered.len - 2] == `A` { `B` } else { `A` }
	mut rejected := false
	decrypt_mirror_secret(secret, tampered.bytestr()) or { rejected = true }
	assert rejected
}

fn test_ssh_mirror_endpoint_requires_pinned_auth_material() {
	clean, username, password, scheme := normalize_mirror_endpoint('ssh://git@localhost/team/project.git', [
		'localhost',
	])!
	assert clean == 'ssh://git@localhost/team/project.git'
	assert username == 'git'
	assert password == ''
	assert scheme == 'ssh'
	assert is_safe_mirror_endpoint(clean, ['localhost'])
	assert !is_safe_mirror_endpoint(clean, [])
}

fn test_ssh_mirror_usernames_cannot_be_interpreted_as_ssh_options() {
	assert valid_ssh_mirror_username('git')
	assert valid_ssh_mirror_username('deploy-user')
	assert !valid_ssh_mirror_username('-oProxyCommand=evil')
	assert !valid_ssh_mirror_username('git user')
	assert !valid_ssh_mirror_username('git@example')
}

fn test_mirror_auth_files_are_private() {
	secret := 'mirror-auth-file-secret-that-is-long-enough'
	app := App{
		config: config.Config{
			storage_secret: secret
		}
	}
	mirror := RepoMirror{
		url:               'ssh://git@example.test/team/project.git'
		encrypted_ssh_key: encrypt_mirror_secret(secret, 'private-key-material')!
		ssh_known_hosts:   'example.test ssh-ed25519 AAAATEST'
		interval_minutes:  5
	}
	_, paths := prepare_mirror_auth(&app, mirror)!
	defer {
		for path in paths {
			os.rm(path) or {}
		}
	}
	assert paths.len == 3
	for path in paths {
		assert os.stat(path)!.mode & u32(0o077) == 0
	}
}

fn test_cross_fork_merge_request_refreshes_head_and_invalidates_approvals() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_cross_fork_pr_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		mut app, db_path := transport_test_app(root)!
		defer {
			app.db.close() or {}
			os.rmdir_all(root) or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		bare, _ := initialize_transport_origin(root)!
		insert_transport_user(mut app, 1, 'alice')!
		insert_transport_user(mut app, 2, 'bob')!
		insert_transport_user(mut app, 3, 'reviewer')!
		app.add_repo(Repo{
			id:             1
			git_dir:        bare
			name:           'project'
			user_id:        1
			user_name:      'alice'
			is_public:      true
			primary_branch: 'main'
			status:         .done
		})!
		source := app.find_repo_by_id(1) or { panic('source missing') }
		created := app.create_fork(source, 'bob', 2, 'project', 'fork', true, false, 2)!
		fork_work := os.join_path(root, 'feature-work')
		transport_git(['clone', created.git_dir, fork_work])
		transport_git(['-C', fork_work, 'config', 'user.name', 'Fork User'])
		transport_git(['-C', fork_work, 'config', 'user.email', 'fork@example.test'])
		transport_git(['-C', fork_work, 'checkout', '-b', 'feature'])
		feature_sha := transport_commit(fork_work, 'feature\n', 'feature')
		transport_git(['-C', fork_work, 'push', 'origin', 'feature'])
		mut refreshed_fork := created
		app.update_repo_from_fs(mut refreshed_fork, false)!

		pr_id := app.add_pull_request_from_repo(source.id, created.id, 2, 'Feature', '', 'feature',
			'main')!
		pr := app.find_pull_request_by_id(pr_id) or { panic('PR missing') }
		app.refresh_open_cross_fork_pr_heads(created.id, 'feature')
		assert transport_git(['-C', source.git_dir, 'rev-parse', pr.head_ref()]) == feature_sha
		assert source.list_commits_between('main', pr.head_ref()).len == 1

		app.add_project_member(source.id, 3, 'developer')!
		app.approve_pull_request(pr.id, 3)!
		assert app.pull_request_approval_count(pr.id) == 1
		updated_feature_sha := transport_commit(fork_work, 'updated feature\n', 'update feature')
		transport_git(['-C', fork_work, 'push', 'origin', 'feature'])
		app.refresh_cross_fork_pr_head(source, pr)!
		assert transport_git(['-C', source.git_dir, 'rev-parse', pr.head_ref()]) == updated_feature_sha
		assert app.pull_request_approval_count(pr.id) == 0
		merge_sha := merge_branches_in_bare_at_head(source, 'main', pr.head_ref(),
			updated_feature_sha, 'Reviewer', 'merge')!
		assert transport_git(['-C', source.git_dir, 'rev-parse', 'main']) == merge_sha
	} $else {
		assert true
	}
}

fn test_local_push_and_pull_mirror_ref_updates() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_mirror_transport_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		mut app, db_path := transport_test_app(root)!
		defer {
			app.db.close() or {}
			os.rmdir_all(root) or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		source_bare, source_work := initialize_transport_origin(root)!
		insert_transport_user(mut app, 1, 'alice')!
		app.add_repo(Repo{
			id:             1
			git_dir:        source_bare
			name:           'source'
			user_id:        1
			user_name:      'alice'
			is_public:      true
			primary_branch: 'main'
			status:         .done
		})!
		push_target := os.join_path(root, 'push-target.git')
		transport_git(['init', '--bare', push_target])
		push_mirror := RepoMirror{
			id:                 1
			repo_id:            1
			created_by:         1
			direction:          'push'
			url:                push_target
			enabled:            true
			overwrite_diverged: true
			interval_minutes:   5
		}
		sql app.db {
			insert push_mirror into RepoMirror
		}!
		app.sync_repo_mirror(push_mirror, true)!
		assert transport_git(['-C', push_target, 'rev-parse', 'refs/heads/main']) == transport_git([
			'-C',
			source_bare,
			'rev-parse',
			'refs/heads/main',
		])

		pull_target := os.join_path(root, 'pull-target.git')
		transport_git(['init', '--bare', pull_target])
		app.add_repo(Repo{
			id:             2
			git_dir:        pull_target
			name:           'pull-target'
			user_id:        1
			user_name:      'alice'
			is_public:      true
			primary_branch: 'main'
			status:         .done
		})!
		new_head := transport_commit(source_work, 'mirror update\n', 'mirror update')
		transport_git(['-C', source_work, 'push', 'origin', 'main'])
		pull_mirror := RepoMirror{
			id:               2
			repo_id:          2
			created_by:       1
			direction:        'pull'
			url:              source_bare
			enabled:          true
			interval_minutes: 5
		}
		sql app.db {
			insert pull_mirror into RepoMirror
		}!
		app.sync_repo_mirror(pull_mirror, true)!
		assert transport_git(['-C', pull_target, 'rev-parse', 'refs/heads/main']) == new_head
	} $else {
		assert true
	}
}

fn test_mirror_sync_claim_prevents_overlap_and_recovers_stale_leases() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_mirror_claim_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		mut app, db_path := transport_test_app(root)!
		defer {
			app.db.close() or {}
			os.rmdir_all(root) or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		mirror := RepoMirror{
			id: 1
			repo_id: 1
			created_by: 1
			direction: 'pull'
			url: 'https://example.test/project.git'
			enabled: true
			interval_minutes: 5
		}
		sql app.db {
			insert mirror into RepoMirror
		}!
		claimed := app.claim_repo_mirror(mirror.id)!
		assert claimed.is_syncing
		assert claimed.sync_started_at > 0
		mut overlap_rejected := false
		app.claim_repo_mirror(mirror.id) or { overlap_rejected = true }
		assert overlap_rejected

		stale_started_at := int(time.now().unix()) - mirror_sync_lease_seconds - 1
		mirror_id := mirror.id
		sql app.db {
			update RepoMirror set sync_started_at = stale_started_at where id == mirror_id
		}!
		reclaimed := app.claim_repo_mirror(mirror.id)!
		assert reclaimed.is_syncing
		assert reclaimed.sync_started_at > stale_started_at
		app.record_mirror_result(RepoMirror{
			...claimed
			sync_started_at: stale_started_at
		}, 'stale worker result')
		still_claimed := app.find_repo_mirror(mirror.id) or { panic('mirror missing') }
		assert still_claimed.is_syncing
		app.record_mirror_result(reclaimed, '')
		finished := app.find_repo_mirror(mirror.id) or { panic('mirror missing') }
		assert !finished.is_syncing
		assert finished.sync_started_at == 0
		app.set_repo_mirror_enabled(mirror.repo_id, mirror.id, false)!
		mut paused_rejected := false
		app.claim_repo_mirror(mirror.id) or { paused_rejected = true }
		assert paused_rejected
		app.set_repo_mirror_enabled(mirror.repo_id, mirror.id, true)!
		resumed := app.claim_repo_mirror(mirror.id)!
		assert resumed.enabled
	} $else {
		assert true
	}
}

fn test_mirror_sync_lease_column_is_migrated() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_mirror_lease_migration_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		mut app, db_path := transport_test_app(root)!
		defer {
			app.db.close() or {}
			os.rmdir_all(root) or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		app.db.exec('alter table ${sql_table('RepoMirror')} drop column ${sql_table('sync_started_at')}')!
		assert !db_column_exists(mut app.db, 'RepoMirror', 'sync_started_at')!
		app.migrate_tables()!
		assert db_column_exists(mut app.db, 'RepoMirror', 'sync_started_at')!
	} $else {
		assert true
	}
}

fn test_mirror_ref_publication_is_atomic() {
	root := os.join_path(os.temp_dir(), 'gitly_mirror_atomic_refs_${os.getpid()}')
	os.rmdir_all(root) or {}
	os.mkdir_all(root)!
	defer {
		os.rmdir_all(root) or {}
	}
	bare, work := initialize_transport_origin(root)!
	old_oid := transport_git(['-C', bare, 'rev-parse', 'main'])
	new_oid := transport_commit(work, 'new snapshot\n', 'new snapshot')
	transport_git(['-C', work, 'push', 'origin', 'main'])
	transport_git(['-C', bare, 'update-ref', 'refs/heads/first', old_oid])
	transport_git(['-C', bare, 'update-ref', 'refs/heads/second', old_oid])
	mut rejected := false
	update_mirror_refs(bare, [
		MirrorRefUpdate{
			ref_name: 'refs/heads/first'
			new_oid:  new_oid
			old_oid:  old_oid
		},
		MirrorRefUpdate{
			ref_name: 'refs/heads/second'
			new_oid:  new_oid
			old_oid:  zero_oid_like(old_oid)!
		},
	]) or { rejected = true }
	assert rejected
	assert transport_git(['-C', bare, 'rev-parse', 'first']) == old_oid
	assert transport_git(['-C', bare, 'rev-parse', 'second']) == old_oid
}
