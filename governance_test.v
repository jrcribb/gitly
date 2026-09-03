module main

import config
import os
import git

fn governance_test_app() !(&App, string) {
	db_path := os.join_path(os.temp_dir(), 'gitly_governance_${os.getpid()}.sqlite')
	os.rm(db_path) or {}
	conf := config.Config{
		repo_storage_path: os.temp_dir()
		archive_path:      os.temp_dir()
		avatars_path:      os.temp_dir()
		sqlite:            config.SqliteConfig{
			path: db_path
		}
	}
	mut app := &App{
		db:     connect_db(conf)!
		config: conf
	}
	app.create_tables()!
	return app, db_path
}

fn insert_governance_test_user(mut app App, id int, username string) ! {
	user := User{
		id:            id
		username:      username
		is_registered: true
	}
	sql app.db {
		insert user into User
	}!
}

fn test_project_roles_separate_read_write_and_admin_access() {
	$if sqlite ? {
		mut app, db_path := governance_test_app()!
		defer {
			app.db.close() or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		for id, name in ['owner', 'reporter', 'developer', 'maintainer'] {
			insert_governance_test_user(mut app, id + 1, name)!
		}
		app.add_repo(Repo{
			id:             1
			name:           'private-project'
			user_id:        1
			user_name:      'owner'
			primary_branch: 'main'
		})!
		app.add_project_member(1, 2, 'reporter')!
		app.add_project_member(1, 3, 'developer')!
		app.add_project_member(1, 4, 'maintainer')!
		mut duplicate_rejected := false
		app.add_project_member(1, 2, 'developer') or { duplicate_rejected = true }
		assert duplicate_rejected
		mut missing_update_rejected := false
		app.update_project_member_role(1, 999_999, 'reporter') or {
			missing_update_rejected = true
		}
		assert missing_update_rejected
		mut missing_delete_rejected := false
		app.remove_project_member(1, 999_999) or { missing_delete_rejected = true }
		assert missing_delete_rejected
		repo := app.find_repo_by_id(1) or { panic('repo missing') }

		assert app.repo_access_level(1, repo) == project_access_owner
		assert app.user_has_repo_read_access(2, repo)
		assert !app.user_can_write_repo(2, repo)
		assert app.user_can_write_repo(3, repo)
		assert app.repo_access_level(3, repo) < project_access_maintainer
		assert app.repo_access_level(4, repo) == project_access_maintainer
		assert !app.user_has_repo_read_access(99, repo)

		owner_ctx := Context{
			logged_in: true
			user:      User{
				id: 1
			}
		}
		maintainer_ctx := Context{
			logged_in: true
			user:      User{
				id: 4
			}
		}
		assert app.can_admin_repo(owner_ctx, repo)
		assert app.can_own_repo(owner_ctx, repo)
		assert app.can_admin_repo(maintainer_ctx, repo)
		assert !app.can_own_repo(maintainer_ctx, repo)
	} $else {
		assert true
	}
}

fn test_protected_branch_wildcards_and_access_rules() {
	$if sqlite ? {
		mut app, db_path := governance_test_app()!
		defer {
			app.db.close() or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		for id, name in ['owner', 'developer', 'maintainer'] {
			insert_governance_test_user(mut app, id + 1, name)!
		}
		app.add_repo(Repo{
			id:             1
			name:           'project'
			user_id:        1
			user_name:      'owner'
			primary_branch: 'main'
		})!
		app.add_project_member(1, 2, 'developer')!
		app.add_project_member(1, 3, 'maintainer')!
		app.protect_branch(1, 'release/*', project_access_maintainer, project_access_developer)!
		repo := app.find_repo_by_id(1) or { panic('repo missing') }

		assert branch_pattern_matches('release/*', 'release/2026.08')
		assert !branch_pattern_matches('release/*', 'feature/release')
		assert app.user_can_push_branch(2, repo, 'feature/demo')
		assert !app.user_can_push_branch(2, repo, 'release/2026.08')
		assert app.user_can_push_branch(3, repo, 'release/2026.08')
		assert app.user_can_merge_branch(2, repo, 'release/2026.08')
		assert app.branch_is_protected(1, 'release/2026.08')
	} $else {
		assert true
	}
}

fn test_protected_branch_patterns_reject_invalid_git_ref_characters() {
	assert valid_protected_branch_pattern('release/*')
	assert valid_protected_branch_pattern('feature/team-*')
	for invalid in ['@', 'release/.hidden', 'release/foo~1', 'release/foo^1', 'release/foo:bar',
		'release/foo.lock', 'release/foo.', 'release//next', 'release/@{next}'] {
		assert !valid_protected_branch_pattern(invalid)
	}
	mut control_bytes := 'release/x'.bytes()
	control_bytes << u8(1)
	control_character := control_bytes.bytestr()
	assert !valid_protected_branch_pattern(control_character)
}

fn test_merge_approvals_are_unique_and_can_be_invalidated() {
	$if sqlite ? {
		mut app, db_path := governance_test_app()!
		repo_root := os.join_path(os.temp_dir(), 'gitly_governance_approval_${os.getpid()}')
		work_dir := os.join_path(repo_root, 'work')
		bare_dir := os.join_path(repo_root, 'project.git')
		os.rmdir_all(repo_root) or {}
		os.mkdir_all(repo_root)!
		defer {
			app.db.close() or {}
			os.rmdir_all(repo_root) or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		assert git.Git.exec(['init', '-b', 'main', work_dir]).exit_code == 0
		assert git.Git.exec_in_dir(work_dir, ['config', 'user.name', 'Tester']).exit_code == 0
		assert git.Git.exec_in_dir(work_dir, ['config', 'user.email', 'tester@example.com']).exit_code == 0
		os.write_file(os.join_path(work_dir, 'README.md'), 'base\n')!
		assert git.Git.exec_in_dir(work_dir, ['add', 'README.md']).exit_code == 0
		assert git.Git.exec_in_dir(work_dir, ['commit', '-m', 'base']).exit_code == 0
		assert git.Git.exec_in_dir(work_dir, ['checkout', '-b', 'feature']).exit_code == 0
		os.write_file(os.join_path(work_dir, 'feature.txt'), 'feature\n')!
		assert git.Git.exec_in_dir(work_dir, ['add', 'feature.txt']).exit_code == 0
		assert git.Git.exec_in_dir(work_dir, ['commit', '-m', 'feature']).exit_code == 0
		assert git.Git.exec(['init', '--bare', bare_dir]).exit_code == 0
		assert git.Git.exec_in_dir(work_dir, ['remote', 'add', 'origin', bare_dir]).exit_code == 0
		assert git.Git.exec_in_dir(work_dir, ['push', 'origin', 'main', 'feature']).exit_code == 0
		insert_governance_test_user(mut app, 1, 'owner')!
		insert_governance_test_user(mut app, 2, 'reviewer')!
		app.add_repo(Repo{
			id:                 1
			git_dir:            bare_dir
			name:               'project'
			user_id:            1
			user_name:          'owner'
			primary_branch:     'main'
			required_approvals: 1
		})!
		app.add_project_member(1, 2, 'developer')!
		pr_id := app.add_pull_request(1, 1, 'Feature', '', 'feature', 'main')!
		app.approve_pull_request(pr_id, 2)!
		app.approve_pull_request(pr_id, 2)!
		assert app.pull_request_approval_count(pr_id) == 1
		repo := app.find_repo_by_id(1) or { panic('repo missing') }
		pr := app.find_pull_request_by_id(pr_id) or { panic('PR missing') }
		assert app.pull_request_approvals_satisfied(pr, repo)

		app.clear_open_pr_approvals_for_head(1, 'feature')!
		assert app.pull_request_approval_count(pr_id) == 0
		assert !app.pull_request_approvals_satisfied(pr, repo)
	} $else {
		assert true
	}
}

fn test_protected_branch_hook_rejects_force_pushes() {
	$if sqlite ? {
		mut app, db_path := governance_test_app()!
		test_root := os.join_path(os.temp_dir(), 'gitly_hook_${os.getpid()}')
		os.rmdir_all(test_root) or {}
		os.mkdir_all(test_root)!
		defer {
			app.db.close() or {}
			os.rmdir_all(test_root) or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		bare := os.join_path(test_root, 'project.git')
		work := os.join_path(test_root, 'work')
		assert git.Git.exec(['init', '--bare', bare]).exit_code == 0
		assert git.Git.exec(['init', '-b', 'main', work]).exit_code == 0
		assert git.Git.exec_in_dir(work, ['config', 'user.name', 'Tester']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['config', 'user.email', 'tester@example.com']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['remote', 'add', 'origin', bare]).exit_code == 0

		app.add_repo(Repo{
			id:             1
			name:           'project'
			user_id:        1
			user_name:      'owner'
			git_dir:        bare
			primary_branch: 'main'
		})!
		rule_id := app.protect_branch(1, 'main', project_access_maintainer,
			project_access_maintainer)!
		repo := app.find_repo_by_id(1) or { panic('repo missing') }
		app.ensure_protected_branch_hook(repo)!
		assert git.Git.exec_in_dir(bare, ['config', '--get', 'core.hooksPath']).output.trim_space() == '.gitly-hooks'
		owner_environment := {
			'GITLY_PROTECTED_BRANCH_RULES': app.protected_branch_rules_env(1)
			'GITLY_USER_ACCESS_LEVEL':      project_access_owner.str()
		}

		os.write_file(os.join_path(work, 'README.md'), 'one\n')!
		assert git.Git.exec_in_dir(work, ['add', 'README.md']).exit_code == 0
		assert git.Git.exec_in_dir(work, ['commit', '-m', 'first']).exit_code == 0
		assert git.Git.exec_in_dir_with_env(work, ['push', 'origin', 'main'], owner_environment).exit_code == 0
		wildcard_rule_id := app.protect_branch(1, '*', project_access_no_one,
			project_access_no_one)!

		os.write_file(os.join_path(work, 'README.md'), 'two\n')!
		assert git.Git.exec_in_dir(work, ['commit', '-am', 'second']).exit_code == 0
		developer_environment := {
			'GITLY_PROTECTED_BRANCH_RULES':  app.protected_branch_rules_env(1)
			'GITLY_PROTECTED_BRANCH_GRANTS': ''
			'GITLY_USER_ACCESS_LEVEL':       project_access_developer.str()
		}
		denied := git.Git.exec_in_dir_with_env(work, ['push', 'origin', 'main'],
			developer_environment)
		assert denied.exit_code != 0
		assert denied.output.contains('not allowed to push to protected branch')
		main_only_environment := {
			'GITLY_PROTECTED_BRANCH_RULES':  app.protected_branch_rules_env(1)
			'GITLY_PROTECTED_BRANCH_GRANTS': rule_id.str()
			'GITLY_USER_ACCESS_LEVEL':       project_access_developer.str()
		}
		overlap_denied := git.Git.exec_in_dir_with_env(work, ['push', 'origin', 'main'],
			main_only_environment)
		assert overlap_denied.exit_code != 0
		granted_environment := {
			'GITLY_PROTECTED_BRANCH_RULES':  app.protected_branch_rules_env(1)
			'GITLY_PROTECTED_BRANCH_GRANTS': '${rule_id},${wildcard_rule_id}'
			'GITLY_USER_ACCESS_LEVEL':       project_access_developer.str()
		}
		assert git.Git.exec_in_dir_with_env(work, ['push', 'origin', 'main'],
			granted_environment).exit_code == 0

		assert git.Git.exec_in_dir(work, ['reset', '--hard', 'HEAD~1']).exit_code == 0
		os.write_file(os.join_path(work, 'README.md'), 'divergent\n')!
		assert git.Git.exec_in_dir(work, ['commit', '-am', 'divergent']).exit_code == 0
		forced := git.Git.exec_in_dir_with_env(work, ['push', '--force', 'origin', 'main'],
			granted_environment)
		assert forced.exit_code != 0
		assert forced.output.contains('force-pushing to protected branch')
	} $else {
		assert true
	}
}
