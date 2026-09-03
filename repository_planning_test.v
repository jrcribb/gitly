module main

import config
import crypto.sha256
import git
import os
import time

fn repository_planning_test_app(root string) !&App {
	conf := config.Config{
		repo_storage_path: root
		archive_path: root
		avatars_path: root
		sqlite: config.SqliteConfig{
			path: os.join_path(root, 'test.sqlite')
		}
	}
	mut app := &App{
		db: connect_db(conf)!
		config: conf
	}
	app.create_tables()!
	return app
}

fn insert_repository_planning_user(mut app App, id int, username string) ! {
	user := User{
		id: id
		username: username
		is_registered: true
	}
	sql app.db {
		insert user into User
	}!
}

fn test_deploy_tokens_protected_tags_lfs_and_housekeeping() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_repository_management_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		defer {
			os.rmdir_all(root) or {}
		}
		work := os.join_path(root, 'work')
		bare := os.join_path(root, 'project.git')
		assert git.Git.exec(['init', '-b', 'main', work]).exit_code == 0
		assert git.Git.exec_in_dir(work, ['config', 'user.name', 'Owner']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['config', 'user.email', 'owner@example.test']).exit_code == 0
		os.write_file(os.join_path(work, 'README.md'), 'hello\n')!
		assert git.Git.exec_in_dir(work, ['add', 'README.md']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['commit', '-m', 'initial']).exit_code == 0
		assert git.Git.exec(['clone', '--bare', work, bare]).exit_code == 0

		mut app := repository_planning_test_app(root)!
		defer {
			app.db.close() or {}
		}
		insert_repository_planning_user(mut app, 1, 'owner')!
		insert_repository_planning_user(mut app, 2, 'outsider')!
		app.add_repo(Repo{
			id: 1
			git_dir: bare
			name: 'project'
			user_id: 1
			user_name: 'owner'
			is_public: true
			primary_branch: 'main'
			status: .done
		})!
		repo := app.find_repo_by_id(1) or { panic('repository missing') }
		private_snippet_id := app.add_snippet(1, 1, 'Internal notes', '', 'internal.txt', 'secret', false)!
		public_snippet_id := app.add_snippet(1, 1, 'Public notes', '', 'public.txt', 'hello', true)!
		private_snippet := app.find_snippet(1, private_snippet_id) or {
			panic('private snippet missing')
		}
		public_snippet := app.find_snippet(1, public_snippet_id) or {
			panic('public snippet missing')
		}
		assert !app.user_can_read_snippet(0, repo, private_snippet)
		assert !app.user_can_read_snippet(2, repo, private_snippet)
		assert app.user_can_read_snippet(1, repo, private_snippet)
		assert app.user_can_read_snippet(0, repo, public_snippet)

		now := int(time.now().unix())
		token_id, username, secret := app.add_deploy_token(1, 1, 'automation', [
			deploy_token_scope_read_repository,
			deploy_token_scope_write_lfs,
		], now + 3600)!
		assert token_id > 0
		assert username.starts_with('deploy-')
		assert secret.starts_with('gldt_')
		assert (app.authenticate_deploy_token(1, username, secret, deploy_token_scope_read_repository, '192.0.2.1') or { DeployToken{} }).id == token_id
		assert (app.authenticate_deploy_token(1, username, secret, deploy_token_scope_write_repository, '') or { DeployToken{} }).id == 0
		app.revoke_deploy_token(1, token_id)!
		assert (app.authenticate_deploy_token(1, username, secret, deploy_token_scope_read_repository, '') or { DeployToken{} }).id == 0

		app.protect_tag(1, 'v*', project_access_maintainer)!
		assert app.tag_is_protected(1, 'v1.0.0')
		assert !app.access_level_can_create_tag(project_access_developer, 1, 'v1.0.0')
		assert app.access_level_can_create_tag(project_access_maintainer, 1, 'v1.0.0')
		assert app.access_level_can_create_tag(project_access_developer, 1, 'nightly')
		app.ensure_protected_branch_hook(repo)!
		assert git.Git.exec_in_dir(work, ['tag', 'v1.0.0']).exit_code == 0
		developer_env := {
			'GITLY_USER_ACCESS_LEVEL':   project_access_developer.str()
			'GITLY_PROTECTED_TAG_RULES': app.protected_tag_rules_env(repo.id)
		}
		assert git.Git.exec_in_dir_with_env(work, ['push', bare, 'v1.0.0'], developer_env).exit_code != 0
		maintainer_env := {
			'GITLY_USER_ACCESS_LEVEL':   project_access_maintainer.str()
			'GITLY_PROTECTED_TAG_RULES': app.protected_tag_rules_env(repo.id)
		}
		assert git.Git.exec_in_dir_with_env(work, ['push', bare, 'v1.0.0'], maintainer_env).exit_code == 0
		os.write_file(os.join_path(work, 'next.txt'), 'next\n')!
		assert git.Git.exec_in_dir(work, ['add', 'next.txt']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['commit', '-m', 'next']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['tag', '-f', 'v1.0.0', 'HEAD']).exit_code == 0
		assert git.Git.exec_in_dir_with_env(work, ['push', '--force', bare, 'v1.0.0'], maintainer_env).exit_code != 0
		app.fetch_tags(repo)!
		release := app.publish_release(repo, 'v1.0.0', 'Release notes', 1)!
		assert release.is_manual
		app.remove_published_release(repo, release.id, 1)!
		assert app.get_repo_release_count(repo.id) == 0
		tag := app.get_all_repo_tags(repo.id).filter(it.name == 'v1.0.0').first()
		app.add_release(tag.id, repo.id, time.now(), tag.message)!
		assert app.get_repo_release_count(repo.id) == 0
		app.publish_release(repo, 'v1.0.0', 'Republished', 1)!
		assert app.get_repo_release_count(repo.id) == 1

		data := 'large file payload'.bytes()
		oid := sha256.sum(data).hex()
		app.store_lfs_object(repo.id, oid, data.len, data)!
		assert app.repo_has_lfs_object(repo.id, oid)
		assert os.read_bytes(app.lfs_object_path(oid))! == data

		state := app.run_repository_housekeeping(repo)!
		assert !state.is_running
		assert state.last_completed_at > 0
		assert state.last_error == ''
		assert git.Git.exec_in_dir(bare, ['config', '--bool', 'uploadpack.allowFilter']).output.trim_space() == 'true'
	} $else {
		assert true
	}
}

fn test_ssh_commit_signature_verification_uses_active_signing_keys() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_signature_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		defer {
			os.rmdir_all(root) or {}
		}
		key_path := os.join_path(root, 'signing_key')
		keygen := os.exec(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key_path])
		if keygen.exit_code != 0 {
			eprintln('ssh-keygen unavailable; skipping SSH signature integration assertion')
			return
		}
		work := os.join_path(root, 'work')
		bare := os.join_path(root, 'signed.git')
		assert git.Git.exec(['init', '-b', 'main', work]).exit_code == 0
		assert git.Git.exec_in_dir(work, ['config', 'user.name', 'Signer']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['config', 'user.email', 'signer@example.test']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['config', 'gpg.format', 'ssh']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['config', 'user.signingkey', key_path]).exit_code == 0
		assert git.Git.exec_in_dir(work, ['config', 'commit.gpgsign', 'true']).exit_code == 0
		os.write_file(os.join_path(work, 'signed.txt'), 'signed\n')!
		assert git.Git.exec_in_dir(work, ['add', 'signed.txt']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['commit', '-m', 'signed']).exit_code == 0
		signed_oid := git.Git.exec_in_dir(work, ['rev-parse', 'HEAD']).output.trim_space()
		assert git.Git.exec(['clone', '--bare', work, bare]).exit_code == 0

		mut app := repository_planning_test_app(root)!
		defer {
			app.db.close() or {}
		}
		insert_repository_planning_user(mut app, 1, 'signer')!
		app.add_ssh_key(1, 'Signing key', os.read_file(key_path + '.pub')!, 'signing', 0)!
		app.add_repo(Repo{
			id: 1
			git_dir: bare
			name: 'signed'
			user_id: 1
			user_name: 'signer'
			primary_branch: 'main'
			status: .done
		})!
		repo := app.find_repo_by_id(1) or { panic('repository missing') }
		verified := app.verify_commit_ssh_signature(repo, signed_oid)
		assert verified.verified
		assert verified.signer_id == 1
		app.ensure_protected_branch_hook(repo)!

		assert git.Git.exec_in_dir(work, ['config', 'commit.gpgsign', 'false']).exit_code == 0
		os.write_file(os.join_path(work, 'unsigned.txt'), 'unsigned\n')!
		assert git.Git.exec_in_dir(work, ['add', 'unsigned.txt']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['commit', '-m', 'unsigned']).exit_code == 0
		unsigned_oid := git.Git.exec_in_dir(work, ['rev-parse', 'HEAD']).output.trim_space()
		assert !app.verify_commit_ssh_signature(repo, unsigned_oid).verified
		hook_env := {
			'GITLY_USER_ACCESS_LEVEL':      project_access_owner.str()
			'GITLY_REQUIRE_SIGNED_COMMITS': '1'
			'GITLY_SSH_ALLOWED_SIGNERS':    os.join_path(bare, '.gitly-hooks', 'allowed_signers')
		}
		assert git.Git.exec_in_dir(work, ['tag', 'unsigned-tag']).exit_code == 0
		assert git.Git.exec_in_dir_with_env(work, ['push', bare, 'unsigned-tag'], hook_env).exit_code != 0
		unsigned_push := git.Git.exec_in_dir_with_env(work, ['push', bare, 'main'], hook_env)
		assert unsigned_push.exit_code != 0
		assert unsigned_push.output.contains('does not have a trusted signature')
		assert git.Git.exec_in_dir(work, ['config', 'commit.gpgsign', 'true']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['commit', '--amend', '--no-edit']).exit_code == 0
		assert git.Git.exec_in_dir_with_env(work, ['push', bare, 'main'], hook_env).exit_code == 0
	} $else {
		assert true
	}
}

fn test_nested_group_planning_scoped_labels_and_advanced_boards() {
	$if sqlite ? {
		root := os.join_path(os.temp_dir(), 'gitly_planning_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		defer {
			os.rmdir_all(root) or {}
		}
		mut app := repository_planning_test_app(root)!
		defer {
			app.db.close() or {}
		}
		insert_repository_planning_user(mut app, 1, 'owner')!
		org_id := app.add_org('team', 'team@example.test', 'business', 1)!
		app.add_org_member(org_id, 1, 'admin')!
		subgroup_id := app.add_subgroup(org_id, 'platform', 'Platform', 1)!
		assert (app.get_org_by_id(subgroup_id) or { Org{} }).name == 'team/platform'
		assert app.user_can_admin_group(1, subgroup_id)

		app.add_repo(Repo{
			id: 1
			name: 'planner'
			user_id: 1
			user_name: 'team'
			primary_branch: 'main'
			status: .done
		})!
		first_issue := app.add_issue_returning_id(1, 1, 'First', 'body')!
		second_issue := app.add_issue_returning_id(1, 1, 'Second', 'body')!
		epic_id := app.add_epic(org_id, 0, 1, 'Ship platform', 'Roadmap item', 0, 0)!
		app.add_issue_to_epic(epic_id, first_issue)!
		assert app.find_epic_issues(epic_id).map(it.id) == [first_issue]
		iteration_id := app.add_iteration(org_id, 'Iteration 1', '', int(time.now().unix()), int(time.now().unix()) + 604800)!
		app.assign_issue_iteration(first_issue, iteration_id)!

		priority_high := app.add_repo_label(1, 'priority::high', 'ff0000')!
		priority_low := app.add_repo_label(1, 'priority::low', '00ff00')!
		app.add_issue_label(first_issue, priority_high)!
		app.add_issue_label(first_issue, priority_low)!
		labels := app.get_issue_labels(first_issue)
		assert labels.len == 1
		assert labels.first().name == 'priority::low'

		task_id := app.add_issue_task(first_issue, 1, 'Implement')!
		app.set_issue_task_completed(first_issue, task_id, true)!
		assert app.find_issue_tasks(first_issue).first().completed
		app.set_issue_time_estimate(first_issue, 480)!
		app.add_issue_time(first_issue, 1, 90, 'Design')!
		assert app.issue_time_spent(first_issue) == 90
		app.relate_issues(first_issue, second_issue, 'blocks', 1)!
		assert app.find_issue_relationships(first_issue).len == 1

		board_id := app.add_advanced_project(1, 'Delivery', '', priority_low, 0, iteration_id, 0)!
		limited_column := app.add_project_column_with_limit(board_id, 'Review', 3, 1)!
		app.add_project_card_for_issue(limited_column, 'First', '', first_issue)!
		mut wip_rejected := false
		app.add_project_card_for_issue(limited_column, 'Second', '', second_issue) or {
			wip_rejected = true
		}
		assert wip_rejected
		assert app.board_candidate_issues(app.find_project(board_id) or { Project{} }).map(it.id) == [
			first_issue,
		]

		service_secret := app.enable_service_desk(1)!
		service_issue := app.create_service_desk_issue(service_secret, 'customer@example.test', 'Need help', 'Support request', 'message-1')!
		assert service_issue > second_issue
		assert app.create_service_desk_issue(service_secret, 'customer@example.test', 'Duplicate', 'Same message', 'message-1')! == service_issue
	} $else {
		assert true
	}
}
