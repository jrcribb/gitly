module main

import config
import os

fn issue_management_test_app() !(&App, string) {
	db_path := os.join_path(os.temp_dir(), 'gitly_issue_management_${os.getpid()}.sqlite')
	os.rm(db_path) or {}
	conf := config.Config{
		repo_storage_path: os.temp_dir()
		archive_path: os.temp_dir()
		avatars_path: os.temp_dir()
		sqlite: config.SqliteConfig{
			path: db_path
		}
	}
	mut app := &App{
		db: connect_db(conf)!
		config: conf
	}
	app.create_tables()!
	return app, db_path
}

fn cleanup_issue_management_test(mut app App, db_path string) {
	app.db.close() or {}
	for suffix in ['', '-shm', '-wal'] {
		os.rm(db_path + suffix) or {}
	}
}

fn insert_issue_management_user(mut app App, id int, username string) ! {
	user := User{
		id: id
		username: username
		is_registered: true
	}
	sql app.db {
		insert user into User
	}!
}

fn test_issue_labels_are_validated_scoped_and_idempotent() {
	$if sqlite? {
		mut app, db_path := issue_management_test_app()!
		defer {
			cleanup_issue_management_test(mut app, db_path)
		}
		insert_issue_management_user(mut app, 1, 'owner')!
		app.add_repo(Repo{
			id: 1
			name: 'one'
			user_id: 1
			user_name: 'owner'
			is_public: true
		})!
		app.add_repo(Repo{
			id: 2
			name: 'two'
			user_id: 1
			user_name: 'owner'
			is_public: true
		})!
		issue_id := app.add_issue_returning_id(1, 1, 'Before', '')!
		other_issue_id := app.add_issue_returning_id(2, 1, 'Other', '')!
		label_id := app.add_repo_label(1, ' bug ', '#AABBCC')!
		other_label_id := app.add_repo_label(2, 'other', '112233')!

		label := app.find_repo_label_by_id(1, label_id) or { panic('label missing') }
		assert label.name == 'bug'
		assert label.color == 'aabbcc'
		app.add_issue_label(issue_id, label_id)!
		app.add_issue_label(issue_id, label_id)!
		assert app.get_issue_labels(issue_id).map(it.id) == [label_id]

		mut cross_repo_rejected := false
		app.add_issue_label(issue_id, other_label_id) or { cross_repo_rejected = true }
		assert cross_repo_rejected
		mut reverse_cross_repo_rejected := false
		app.add_issue_label(other_issue_id, label_id) or { reverse_cross_repo_rejected = true }
		assert reverse_cross_repo_rejected

		app.update_repo_label(1, label_id, 'confirmed', '00FF00')!
		updated_label := app.find_repo_label_by_id(1, label_id) or { panic('label missing') }
		assert updated_label.name == 'confirmed'
		assert updated_label.color == '00ff00'
		mut invalid_color_rejected := false
		app.update_repo_label(1, label_id, 'confirmed', 'red; color:black') or {
			invalid_color_rejected = true
		}
		assert invalid_color_rejected
		mut repeated_hash_rejected := false
		app.update_repo_label(1, label_id, 'confirmed', '##ffffff') or {
			repeated_hash_rejected = true
		}
		assert repeated_hash_rejected

		app.update_issue(issue_id, ' After ', 'Updated body')!
		updated_issue := app.find_issue_by_id(issue_id) or { panic('issue missing') }
		assert updated_issue.title == 'After'
		assert updated_issue.text == 'Updated body'

		app.delete_repo_label(1, label_id)!
		assert app.get_issue_labels(issue_id).len == 0
		links := sql app.db {
			select count from IssueLabel where label_id == label_id
		}!
		assert links == 0
	} $else {
		assert true
	}
}

fn test_issue_and_discussion_mutations_require_current_private_project_access() {
	$if sqlite? {
		mut app, db_path := issue_management_test_app()!
		defer {
			cleanup_issue_management_test(mut app, db_path)
		}
		insert_issue_management_user(mut app, 1, 'owner')!
		insert_issue_management_user(mut app, 2, 'reporter')!
		app.add_repo(Repo{
			id: 1
			name: 'private-project'
			user_id: 1
			user_name: 'owner'
			is_public: false
		})!
		app.add_project_member(1, 2, 'reporter')!
		issue_id := app.add_issue_returning_id(1, 2, 'Issue', '')!
		discussion_id := app.add_discussion(1, 2, 'Discussion', '', 'general')!
		repo := app.find_repo_by_id(1) or { panic('repository missing') }
		issue := app.find_issue_by_id(issue_id) or { panic('issue missing') }
		discussion := app.find_discussion(discussion_id) or { panic('discussion missing') }
		member_ctx := Context{
			logged_in: true
			user: User{
				id: 2
				username: 'reporter'
			}
		}
		assert app.can_manage_issue(member_ctx, repo, issue)
		assert app.can_manage_discussion(member_ctx, repo, discussion)
		assert app.user_can_manage_labels(2, repo)

		member := app.find_project_members(repo.id).first().member
		app.remove_project_member(repo.id, member.id)!
		assert !app.can_read_repo(member_ctx, repo)
		assert !app.can_manage_issue(member_ctx, repo, issue)
		assert !app.can_manage_discussion(member_ctx, repo, discussion)
		assert !app.user_can_manage_labels(2, repo)
	} $else {
		assert true
	}
}

fn test_delete_repo_issues_removes_issue_metadata_and_comments() {
	$if sqlite? {
		mut app, db_path := issue_management_test_app()!
		defer {
			cleanup_issue_management_test(mut app, db_path)
		}
		insert_issue_management_user(mut app, 1, 'owner')!
		app.add_repo(Repo{
			id: 1
			name: 'project'
			user_id: 1
			user_name: 'owner'
		})!
		issue_id := app.add_issue_returning_id(1, 1, 'Issue', '')!
		label_id := app.add_repo_label(1, 'bug', 'ff0000')!
		app.add_issue_label(issue_id, label_id)!
		app.add_issue_comment(1, issue_id, 'comment')!
		app.assign_issue(issue_id, 1)!

		app.delete_repo_issues(1)!
		assert app.list_repo_labels(1).len == 0
		assert app.get_all_issue_comments(issue_id).len == 0
		assert app.get_issue_assignee_ids(issue_id).len == 0
		assert app.get_issue_labels(issue_id).len == 0
	} $else {
		assert true
	}
}
