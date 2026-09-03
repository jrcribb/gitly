module main

import config
import git
import os

fn repo_core_test_app(suffix string) !(&App, string) {
	db_path := os.join_path(os.temp_dir(), 'gitly_repo_core_${os.getpid()}_${suffix}.sqlite')
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

fn cleanup_repo_core_test(mut app App, db_path string, repo_dir string) {
	app.db.close() or {}
	if repo_dir != '' {
		os.rmdir_all(repo_dir) or {}
	}
	for suffix in ['', '-shm', '-wal'] {
		os.rm(db_path + suffix) or {}
	}
}

fn must_repo_core_git(repo_dir string, args []string) string {
	result := git.Git.exec_in_dir(repo_dir, args)
	if result.exit_code != 0 {
		panic('git ${args} failed: ${result.output}')
	}
	return result.output.trim_space()
}

fn repo_core_commit(repo_dir string, file_name string, content string, message string, date string) ! {
	file_path := os.join_path(repo_dir, file_name)
	os.mkdir_all(os.dir(file_path))!
	os.write_file(file_path, content)!
	must_repo_core_git(repo_dir, ['add', file_name])
	result := git.Git.exec_in_dir_with_env(repo_dir, ['commit', '-m', message], {
		'GIT_AUTHOR_DATE':    date
		'GIT_COMMITTER_DATE': date
	})
	if result.exit_code != 0 {
		return error('git commit failed: ${result.output}')
	}
}

fn init_repo_core_git_repo(path string) {
	os.rmdir_all(path) or {}
	os.mkdir_all(path) or { panic(err) }
	must_repo_core_git(path, ['init', '-b', 'main'])
	must_repo_core_git(path, ['config', 'user.name', 'Repo Test'])
	must_repo_core_git(path, ['config', 'user.email', 'repo-test@example.com'])
}

fn test_repo_indexing_discovers_merged_commits_after_known_first_parent() {
	$if sqlite ? {
		mut app, db_path := repo_core_test_app('merge')!
		repo_dir := os.join_path(os.temp_dir(), 'gitly_repo_core_merge_${os.getpid()}')
		init_repo_core_git_repo(repo_dir)
		defer {
			cleanup_repo_core_test(mut app, db_path, repo_dir)
		}

		repo_core_commit(repo_dir, 'base.txt', 'base\n', 'base', '2026-01-01T00:00:00Z')!
		must_repo_core_git(repo_dir, ['checkout', '-b', 'side'])
		repo_core_commit(repo_dir, 'side.txt', 'side\n', 'side', '2026-01-01T00:01:00Z')!
		must_repo_core_git(repo_dir, ['checkout', 'main'])
		repo_core_commit(repo_dir, 'main.txt', 'main\n', 'main', '2026-01-01T00:02:00Z')!

		mut repo := Repo{
			id:             1
			name:           'merge-history'
			user_id:        1
			user_name:      'owner'
			git_dir:        repo_dir
			primary_branch: 'main'
		}
		app.add_repo(repo)!
		app.update_repo_from_fs(mut repo, false)!
		main_branch := app.find_repo_branch_by_name(repo.id, 'main')
		assert app.get_repo_commit_count(repo.id, main_branch.id) == 2

		merge_result := git.Git.exec_in_dir_with_env(repo_dir, ['merge', '--no-ff', 'side', '-m',
			'merge side'], {
			'GIT_AUTHOR_DATE':    '2026-01-01T00:03:00Z'
			'GIT_COMMITTER_DATE': '2026-01-01T00:03:00Z'
		})
		assert merge_result.exit_code == 0

		app.update_repo_branch_from_fs(mut repo, 'main')!
		assert app.get_repo_commit_count(repo.id, main_branch.id) == 4
	} $else {
		assert true
	}
}

fn test_repo_indexing_prunes_commits_made_unreachable_by_rewrite() {
	$if sqlite ? {
		mut app, db_path := repo_core_test_app('rewrite')!
		repo_dir := os.join_path(os.temp_dir(), 'gitly_repo_core_rewrite_${os.getpid()}')
		init_repo_core_git_repo(repo_dir)
		defer {
			cleanup_repo_core_test(mut app, db_path, repo_dir)
		}

		repo_core_commit(repo_dir, 'file.txt', 'base\n', 'base', '2026-01-01T00:00:00Z')!
		repo_core_commit(repo_dir, 'file.txt', 'old tip\n', 'old tip', '2026-01-01T00:01:00Z')!
		old_tip := must_repo_core_git(repo_dir, ['rev-parse', 'HEAD'])
		mut repo := Repo{
			id:             1
			name:           'rewritten-history'
			user_id:        1
			user_name:      'owner'
			git_dir:        repo_dir
			primary_branch: 'main'
		}
		app.add_repo(repo)!
		app.update_repo_from_fs(mut repo, false)!
		branch := app.find_repo_branch_by_name(repo.id, 'main')
		assert app.get_repo_commit_count(repo.id, branch.id) == 2
		assert app.commit_exists(repo.id, branch.id, old_tip)

		must_repo_core_git(repo_dir, ['reset', '--hard', 'HEAD~1'])
		repo_core_commit(repo_dir, 'file.txt', 'replacement\n', 'replacement',
			'2026-01-01T00:02:00Z')!
		app.update_repo_branch_from_fs(mut repo, 'main')!

		assert app.get_repo_commit_count(repo.id, branch.id) == 2
		assert !app.commit_exists(repo.id, branch.id, old_tip)
	} $else {
		assert true
	}
}

fn test_repo_tree_cache_preserves_deep_paths_and_spaces() {
	$if sqlite ? {
		mut app, db_path := repo_core_test_app('tree')!
		repo_dir := os.join_path(os.temp_dir(), 'gitly_repo_core_tree_${os.getpid()}')
		init_repo_core_git_repo(repo_dir)
		defer {
			cleanup_repo_core_test(mut app, db_path, repo_dir)
		}

		repo_core_commit(repo_dir, 'README.md', 'root\n', 'add files', '2026-01-02T00:00:00Z')!
		repo_core_commit(repo_dir, 'deep/nested/file with spaces.txt', 'content\n', 'nested file',
			'2026-01-02T00:01:00Z')!
		mut repo := Repo{
			id:             1
			name:           'tree-paths'
			user_id:        1
			user_name:      'owner'
			git_dir:        repo_dir
			primary_branch: 'main'
		}
		app.add_repo(repo)!

		items := app.cache_repository_items(mut repo, 'main', 'deep/nested')!
		assert items.len == 1
		assert items[0].name == 'file with spaces.txt'
		assert items[0].parent_path == 'deep/nested'
		assert items[0].full_path() == 'deep/nested/file with spaces.txt'

		mut file := app.find_repo_file_by_path(repo.id, 'main', 'deep/nested/file with spaces.txt') or {
			panic('cached nested file missing')
		}
		app.fetch_file_info(repo, file)!
		file = app.find_repo_file_by_path(repo.id, 'main', 'deep/nested/file with spaces.txt') or {
			panic('updated nested file missing')
		}
		assert file.last_msg == 'nested file'

		root_items := app.cache_repository_items(mut repo, 'main', '.')!
		assert root_items.any(it.name == 'README.md')
		assert root_items.any(it.name == 'deep' && it.is_dir)

		top_file :=
			repo.top_files('main', 10).filter(it.full_path() == 'deep/nested/file with spaces.txt')
		assert top_file.len == 1
		assert top_file[0].name == 'file with spaces.txt'
	} $else {
		assert true
	}
}

fn test_repo_tag_sync_is_idempotent_and_removes_deleted_tags() {
	$if sqlite ? {
		mut app, db_path := repo_core_test_app('tags')!
		repo_dir := os.join_path(os.temp_dir(), 'gitly_repo_core_tags_${os.getpid()}')
		init_repo_core_git_repo(repo_dir)
		defer {
			cleanup_repo_core_test(mut app, db_path, repo_dir)
		}

		repo_core_commit(repo_dir, 'file.txt', 'tagged\n', 'tagged commit', '2026-01-03T00:00:00Z')!
		must_repo_core_git(repo_dir, ['tag', 'v1'])
		must_repo_core_git(repo_dir, ['tag', '-a', 'release/v2', '-m', 'annotated release'])
		mut repo := Repo{
			id:             1
			name:           'tag-sync'
			user_id:        1
			user_name:      'owner'
			git_dir:        repo_dir
			primary_branch: 'main'
		}
		app.add_repo(repo)!

		app.update_repo_from_fs(mut repo, false)!
		assert app.get_all_repo_tags(repo.id).len == 2
		assert app.get_repo_release_count(repo.id) == 2
		persisted := app.find_repo_by_id(repo.id) or { panic('repo missing') }
		assert persisted.nr_tags == 2
		assert persisted.nr_releases == 2

		app.update_repo_from_fs(mut repo, false)!
		assert app.get_repo_release_count(repo.id) == 2

		must_repo_core_git(repo_dir, ['tag', '-d', 'v1'])
		app.update_repo_from_fs(mut repo, false)!
		assert app.get_all_repo_tags(repo.id).len == 1
		assert app.get_repo_release_count(repo.id) == 1
		persisted_after_delete := app.find_repo_by_id(repo.id) or { panic('repo missing') }
		assert persisted_after_delete.nr_tags == 1
		assert persisted_after_delete.nr_releases == 1

		archive_path := os.join_path(repo_dir, 'v2.tar.gz')
		repo.archive_tag('release/v2', archive_path, .tar_gz)!
		archive := os.read_bytes(archive_path)!
		assert archive.len > 2
		assert archive[0] == 0x1f && archive[1] == 0x8b
	} $else {
		assert true
	}
}

fn test_failed_repo_update_does_not_leave_transaction_open() {
	$if sqlite ? {
		mut app, db_path := repo_core_test_app('rollback')!
		defer {
			cleanup_repo_core_test(mut app, db_path, '')
		}
		mut repo := Repo{
			id:             1
			name:           'missing'
			user_id:        1
			user_name:      'owner'
			git_dir:        os.join_path(os.temp_dir(), 'gitly_missing_repo_${os.getpid()}')
			primary_branch: 'main'
		}
		app.add_repo(repo)!
		mut failed := false
		app.update_repo_from_fs(mut repo, false) or { failed = true }
		assert failed

		// A leaked transaction makes this fail with "cannot start a transaction
		// within a transaction" on SQLite.
		app.db.exec('BEGIN TRANSACTION')!
		app.db.exec('ROLLBACK')!
	} $else {
		assert true
	}
}

fn test_delete_repository_tombstones_before_returning() {
	$if sqlite ? {
		mut app, db_path := repo_core_test_app('delete')!
		defer {
			cleanup_repo_core_test(mut app, db_path, '')
		}
		repo := Repo{
			id:             1
			name:           'delete-me'
			user_id:        1
			user_name:      'owner'
			primary_branch: 'main'
		}
		app.add_repo(repo)!
		app.add_project_member(repo.id, 2, 'maintainer')!
		app.add_repo(Repo{
			id:             2
			name:           'surviving-fork'
			user_id:        2
			user_name:      'member'
			primary_branch: 'main'
		})!
		fork_relation := RepoFork{
			repo_id:        2
			source_repo_id: repo.id
			root_repo_id:   repo.id
			created_by:     2
			created_at:     1
		}
		sql app.db {
			insert fork_relation into RepoFork
		}!

		app.delete_repository(repo.id, '', repo.name)!

		mut visible := false
		if _ := app.find_repo_by_id(repo.id) {
			visible = true
		}
		assert !visible
		repo_id := repo.id
		member_count := sql app.db {
			select count from ProjectMember where repo_id == repo_id
		}!
		assert member_count == 0
		child_repo_id := 2
		fork_rows := sql app.db {
			select from RepoFork where repo_id == child_repo_id limit 1
		}!
		assert fork_rows.len == 1
		assert fork_rows[0].source_repo_id == repo.id
		assert fork_rows[0].root_repo_id == repo.id
		rows := sql app.db {
			select from Repo where id == repo_id limit 1
		}!
		assert rows.len == 1
		assert rows[0].is_deleted
	} $else {
		assert true
	}
}

fn test_delete_repository_rolls_back_all_database_cleanup_on_tombstone_failure() {
	$if sqlite ? {
		mut app, db_path := repo_core_test_app('delete_rollback')!
		repo_root := os.join_path(os.temp_dir(), 'gitly_delete_rollback_${os.getpid()}')
		repo_dir := os.join_path(repo_root, 'owner', 'repo')
		os.rmdir_all(repo_root) or {}
		os.mkdir_all(repo_dir)!
		defer {
			cleanup_repo_core_test(mut app, db_path, repo_root)
		}
		repo := Repo{
			git_dir:        repo_dir
			name:           'rollback-delete'
			user_id:        1
			user_name:      'owner'
			primary_branch: 'main'
		}
		app.add_repo(repo)!
		created := app.find_repo_by_name_and_username(repo.name, repo.user_name) or {
			panic('repo missing')
		}
		app.add_project_member(created.id, 2, 'maintainer')!
		app.request_repo_transfer(created.id, 1, 3)!
		app.db.exec('create trigger fail_repo_tombstone before update of is_deleted on ${sql_table('Repo')}
			when new.is_deleted is true begin select raise(abort, \'forced tombstone failure\'); end')!

		mut failed := false
		app.delete_repository(created.id, repo_dir, created.name) or { failed = true }
		assert failed
		assert os.exists(repo_dir)
		still_visible := app.find_repo_by_id(created.id) or { panic('repository was tombstoned') }
		assert !still_visible.is_deleted
		repo_id := created.id
		member_count := sql app.db {
			select count from ProjectMember where repo_id == repo_id
		}!
		transfer_count := sql app.db {
			select count from RepoTransfer where repo_id == repo_id
		}!
		assert member_count == 1
		assert transfer_count == 1
	} $else {
		assert true
	}
}

fn test_update_repo_general_settings_persists_all_fields_and_protects_default_branch() {
	$if sqlite ? {
		mut app, db_path := repo_core_test_app('settings')!
		defer {
			cleanup_repo_core_test(mut app, db_path, '')
		}
		repo := Repo{
			id:             1
			name:           'settings'
			user_id:        1
			user_name:      'owner'
			is_public:      true
			primary_branch: 'main'
		}
		app.add_repo(repo)!

		app.update_repo_general_settings(repo.id, 'Updated description', false, 'develop')!

		updated := app.find_repo_by_id(repo.id) or { panic('repo missing') }
		assert updated.description == 'Updated description'
		assert !updated.is_public
		assert updated.primary_branch == 'develop'
		assert app.branch_is_protected(repo.id, 'develop')
	} $else {
		assert true
	}
}

fn test_process_output_drain_cannot_deadlock_on_full_stderr_pipe() {
	$if !windows {
		mut process := os.new_process('/bin/sh')
		process.set_args(['-c', 'head -c 262144 /dev/zero >&2; printf ok'])
		process.set_redirect_stdio()
		process.run()
		output, errors := drain_process_output(mut process)
		process.wait()
		assert process.code == 0
		process.close()
		assert output == 'ok'
		assert errors.len == 262144
	} $else {
		assert true
	}
}
