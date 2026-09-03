module main

import config
import git
import os

fn branch_management_git(args []string) string {
	result := git.Git.exec(args)
	if result.exit_code != 0 {
		panic('git ${args} failed: ${result.output}')
	}
	return result.output.trim_space()
}

fn test_repository_branches_can_be_created_and_safely_deleted() {
	$if sqlite? {
		root := os.join_path(os.temp_dir(), 'gitly_branch_management_${os.getpid()}')
		os.rmdir_all(root) or {}
		os.mkdir_all(root)!
		defer {
			os.rmdir_all(root) or {}
		}
		work_dir := os.join_path(root, 'work')
		bare_dir := os.join_path(root, 'project.git')
		branch_management_git(['init', '-b', 'main', work_dir])
		branch_management_git(['-C', work_dir, 'config', 'user.name', 'Owner'])
		branch_management_git(['-C', work_dir, 'config', 'user.email', 'owner@example.com'])
		os.write_file(os.join_path(work_dir, 'README.md'), 'hello\n')!
		branch_management_git(['-C', work_dir, 'add', 'README.md'])
		branch_management_git(['-C', work_dir, 'commit', '-m', 'initial'])
		main_oid := branch_management_git(['-C', work_dir, 'rev-parse', 'HEAD'])
		branch_management_git(['clone', '--bare', work_dir, bare_dir])

		conf := config.Config{
			repo_storage_path: root
			archive_path: root
			avatars_path: root
			sqlite: config.SqliteConfig{
				path: os.join_path(root, 'test.sqlite')
			}
		}
		mut app := App{
			db: connect_db(conf)!
			config: conf
		}
		defer {
			app.db.close() or {}
		}
		app.create_tables()!
		user := User{
			id: 1
			username: 'owner'
			is_registered: true
		}
		sql app.db {
			insert user into User
		}!
		repo := Repo{
			id: 1
			git_dir: bare_dir
			name: 'project'
			user_id: 1
			user_name: 'owner'
			is_public: true
			primary_branch: 'main'
			status: .done
		}
		app.add_repo(repo)!
		app.update_repo_branch_after_change(repo.id, 'main')!

		feature := app.create_repository_branch(repo, 'feature/api', 'main')!
		assert feature.name == 'feature/api'
		assert feature.hash == main_oid
		assert branch_management_git(['-C', bare_dir, 'rev-parse', 'feature/api']) == main_oid
		assert app.get_count_repo_branches(repo.id) == 2

		mut duplicate_rejected := false
		app.create_repository_branch(repo, 'feature/api', 'main') or { duplicate_rejected = true }
		assert duplicate_rejected
		mut invalid_source_rejected := false
		app.create_repository_branch(repo, 'feature/other', 'missing') or {
			invalid_source_rejected = true
		}
		assert invalid_source_rejected

		app.protect_branch(repo.id, 'release/*', project_access_maintainer, project_access_maintainer)!
		app.create_repository_branch(repo, 'release/1.0', 'main')!
		mut protected_rejected := false
		app.delete_repository_branch(repo, 'release/1.0') or { protected_rejected = true }
		assert protected_rejected
		mut default_rejected := false
		app.delete_repository_branch(repo, 'main') or { default_rejected = true }
		assert default_rejected

		app.delete_repository_branch(repo, 'feature/api')!
		assert app.find_repo_branch_by_name(repo.id, 'feature/api').id == 0
		assert git.Git.exec_in_dir(bare_dir, ['show-ref', '--verify', '--quiet',
			'refs/heads/feature/api']).exit_code != 0
		assert app.get_count_repo_branches(repo.id) == 2
	} $else {
		assert true
	}
}
