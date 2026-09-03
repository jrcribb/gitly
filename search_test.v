module main

import config
import os

fn test_search_respects_repository_visibility_and_hides_shadow_users() {
	$if sqlite? {
		db_path := os.join_path(os.temp_dir(), 'gitly_search_${os.getpid()}.sqlite')
		os.rm(db_path) or {}
		conf := config.Config{
			repo_storage_path: os.temp_dir()
			archive_path: os.temp_dir()
			avatars_path: os.temp_dir()
			sqlite: config.SqliteConfig{
				path: db_path
			}
		}
		mut app := App{
			db: connect_db(conf)!
			config: conf
		}
		app.create_tables()!
		defer {
			app.db.close() or {}
			for suffix in ['', '-shm', '-wal'] {
				os.rm(db_path + suffix) or {}
			}
		}
		for user in [
			User{ id: 1, username: 'owner', full_name: 'Project Owner', is_registered: true },
			User{ id: 2, username: 'reporter', is_registered: true },
			User{ id: 3, username: 'outsider', is_registered: true },
			User{ id: 4, username: 'shadow-project-user', is_registered: false },
		] {
			sql app.db {
				insert user into User
			}!
		}
		app.add_repo(Repo{
			id: 1
			name: 'public-project'
			description: 'searchable public description'
			user_id: 1
			user_name: 'owner'
			is_public: true
		})!
		app.add_repo(Repo{
			id: 2
			name: 'private-project'
			description: 'searchable private description'
			user_id: 1
			user_name: 'owner'
			is_public: false
		})!
		app.add_project_member(2, 2, 'reporter')!

		assert app.search_repos('project', 0).map(it.id) == [1]
		assert app.search_repos('project', 1).map(it.id).sorted() == [1, 2]
		assert app.search_repos('private description', 2).map(it.id) == [2]
		assert app.search_repos('private-project', 3).len == 0
		assert app.search_repos('owner', 0).map(it.id) == [1]

		assert app.search_users('Project Owner').map(it.id) == [1]
		assert app.search_users('shadow-project-user').len == 0
	} $else {
		assert true
	}
}

fn test_search_query_normalization_preserves_unicode_and_removes_wildcards() {
	assert normalize_search_query('  Project_%\n   Проект  ') == 'Project Проект'
	assert normalize_search_query('%_\t') == ''
}
