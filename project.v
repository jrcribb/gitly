// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import time
import veb

struct Project {
	id int @[primary; sql: serial]
mut:
	repo_id      int
	name         string
	description  string
	created_at   int
	label_id     int
	milestone_id int
	iteration_id int
	assignee_id  int
}

struct ProjectColumn {
	id int @[primary; sql: serial]
mut:
	project_id int
	name       string
	position   int
	wip_limit  int
}

struct ProjectCard {
	id int @[primary; sql: serial]
mut:
	column_id  int
	title      string
	note       string
	position   int
	issue_id   int // 0 if a free-form note
	created_at int
}

fn (p &Project) formatted_name() veb.RawHtml {
	return html_escape_text(p.name)
}

fn (mut app App) add_project(repo_id int, name string, description string) !int {
	return app.add_advanced_project(repo_id, name, description, 0, 0, 0, 0)
}

fn (mut app App) add_advanced_project(repo_id int, name string, description string, label_id int,
	milestone_id int, iteration_id int, assignee_id int) !int {
	if repo_id <= 0 || !valid_short_name(name) || !valid_body(description) {
		return error('invalid project board')
	}
	if label_id > 0 && app.find_repo_label_by_id(repo_id, label_id) == none {
		return error('board label filter belongs to another project')
	}
	if milestone_id > 0 {
		milestone := app.find_milestone(milestone_id) or { return error('board milestone not found') }
		if milestone.repo_id != repo_id {
			return error('board milestone filter belongs to another project')
		}
	}
	if iteration_id > 0 {
		iteration := app.find_iteration(iteration_id) or { return error('board iteration not found') }
		repo := app.find_repo_by_id(repo_id) or { return error('project not found') }
		org := app.get_org_by_id(iteration.org_id) or { return error('iteration group not found') }
		if repo.user_name != org.name && !repo.user_name.starts_with(org.name + '/') {
			return error('board iteration filter belongs to another group')
		}
	}
	if assignee_id > 0 {
		repo := app.find_repo_by_id(repo_id) or { return error('project not found') }
		if app.repo_access_level(assignee_id, repo) < project_access_reporter {
			return error('board assignee filter is not a project member')
		}
	}
	project_id := db_insert_returning_id(mut app.db, 'Project', ['repo_id', 'name', 'description',
		'created_at', 'label_id', 'milestone_id', 'iteration_id', 'assignee_id'], [
		repo_id.str(),
		name.trim_space(),
		description,
		int(time.now().unix()).str(),
		label_id.str(),
		milestone_id.str(),
		iteration_id.str(),
		assignee_id.str(),
	])!
	if project_id != 0 {
		for i, col_name in ['Todo', 'In progress', 'Done'] {
			app.add_project_column(project_id, col_name, i) or {
				app.delete_project(project_id) or {}
				return err
			}
		}
	}
	return project_id
}

fn (mut app App) list_repo_projects(repo_id int) []Project {
	return sql app.db {
		select from Project where repo_id == repo_id order by id desc
	} or { []Project{} }
}

fn (mut app App) find_project(id int) ?Project {
	rows := sql app.db {
		select from Project where id == id limit 1
	} or { []Project{} }
	if rows.len == 0 {
		return none
	}
	return rows.first()
}

fn (mut app App) delete_project(id int) ! {
	cols := app.list_project_columns(id)
	for col in cols {
		sql app.db {
			delete from ProjectCard where column_id == col.id
		}!
	}
	sql app.db {
		delete from ProjectColumn where project_id == id
	}!
	sql app.db {
		delete from Project where id == id
	}!
}

fn (mut app App) delete_repo_projects(repo_id int) ! {
	prs := app.list_repo_projects(repo_id)
	for pr in prs {
		app.delete_project(pr.id) or {}
	}
}

fn (mut app App) add_project_column(project_id int, name string, position int) !int {
	return app.add_project_column_with_limit(project_id, name, position, 0)
}

fn (mut app App) add_project_column_with_limit(project_id int, name string, position int,
	wip_limit int) !int {
	if project_id <= 0 || !valid_short_name(name) || position < 0 || wip_limit < 0 || wip_limit > 10000 {
		return error('invalid board column')
	}
	return db_insert_returning_id(mut app.db, 'ProjectColumn', ['project_id', 'name', 'position',
		'wip_limit'], [
		project_id.str(),
		name.trim_space(),
		position.str(),
		wip_limit.str(),
	])
}

fn (mut app App) list_project_columns(project_id int) []ProjectColumn {
	return sql app.db {
		select from ProjectColumn where project_id == project_id order by position
	} or { []ProjectColumn{} }
}

fn (mut app App) find_project_column(id int) ?ProjectColumn {
	rows := sql app.db {
		select from ProjectColumn where id == id limit 1
	} or { []ProjectColumn{} }
	if rows.len == 0 {
		return none
	}
	return rows.first()
}

fn (mut app App) delete_project_column(id int) ! {
	sql app.db {
		delete from ProjectCard where column_id == id
	}!
	sql app.db {
		delete from ProjectColumn where id == id
	}!
}

fn (mut app App) add_project_card(column_id int, title string, note string) ! {
	app.add_project_card_for_issue(column_id, title, note, 0)!
}

fn (mut app App) add_project_card_for_issue(column_id int, title string, note string, issue_id int) ! {
	column := app.find_project_column(column_id) or { return error('board column not found') }
	project := app.find_project(column.project_id) or { return error('board not found') }
	if !valid_title(title) || !valid_body(note) {
		return error('invalid board card')
	}
	if issue_id > 0 {
		issue := app.find_issue_by_id(issue_id) or { return error('issue not found') }
		if issue.repo_id != project.repo_id || issue.is_pr {
			return error('issue belongs to another project')
		}
	}
	project_columns := app.list_project_columns(project.id)
	mut tx := db_begin_transaction(mut app.db)!
	mut committed := false
	defer {
		if !committed {
			tx.rollback() or {}
		}
	}
	locked := tx.execute('update ${sql_table('Project')} set ${sql_table('id')} = ${sql_table('id')}
		where ${sql_table('id')} = ${project.id} returning ${sql_table('id')}')!
	if locked.len != 1 {
		return error('board not found')
	}
	pos := sql tx {
		select count from ProjectCard where column_id == column_id
	} or { 0 }
	if column.wip_limit > 0 && pos >= column.wip_limit {
		return error('column work-in-progress limit has been reached')
	}
	if issue_id > 0 {
		for project_column in project_columns {
			project_column_id := project_column.id
			duplicate_count := sql tx {
				select count from ProjectCard where column_id == project_column_id && issue_id == issue_id
			} or { 0 }
			if duplicate_count > 0 {
				return error('issue is already on this board')
			}
		}
	}
	c := ProjectCard{
		column_id: column_id
		title: title
		note: note
		position: pos
		issue_id: issue_id
		created_at: int(time.now().unix())
	}
	sql tx {
		insert c into ProjectCard
	}!
	tx.commit()!
	committed = true
}

fn (mut app App) list_project_cards(column_id int) []ProjectCard {
	return sql app.db {
		select from ProjectCard where column_id == column_id order by position
	} or { []ProjectCard{} }
}

fn (mut app App) find_project_card(id int) ?ProjectCard {
	rows := sql app.db {
		select from ProjectCard where id == id limit 1
	} or { []ProjectCard{} }
	if rows.len == 0 {
		return none
	}
	return rows.first()
}

fn (mut app App) move_project_card(card_id int, new_column_id int) ! {
	card := app.find_project_card(card_id) or { return error('board card not found') }
	destination := app.find_project_column(new_column_id) or { return error('board column not found') }
	source := app.find_project_column(card.column_id) or { return error('board column not found') }
	if source.project_id != destination.project_id {
		return error('card cannot move to another board')
	}
	mut tx := db_begin_transaction(mut app.db)!
	mut committed := false
	defer {
		if !committed {
			tx.rollback() or {}
		}
	}
	locked := tx.execute('update ${sql_table('Project')} set ${sql_table('id')} = ${sql_table('id')}
		where ${sql_table('id')} = ${source.project_id} returning ${sql_table('id')}')!
	if locked.len != 1 {
		return error('board not found')
	}
	if card.column_id != new_column_id && destination.wip_limit > 0 {
		count := sql tx {
			select count from ProjectCard where column_id == new_column_id
		} or { 0 }
		if count >= destination.wip_limit {
			return error('column work-in-progress limit has been reached')
		}
	}
	sql tx {
		update ProjectCard set column_id = new_column_id where id == card_id
	}!
	tx.commit()!
	committed = true
}

fn (app &App) board_candidate_issues(project Project) []Issue {
	mut candidates := sql app.db {
		select from Issue where repo_id == project.repo_id && is_pr == false order by id desc
	} or { []Issue{} }
	if project.label_id > 0 {
		links := sql app.db {
			select from IssueLabel where label_id == project.label_id
		} or { []IssueLabel{} }
		ids := links.map(it.issue_id)
		candidates = candidates.filter(it.id in ids)
	}
	if project.milestone_id > 0 {
		candidates = candidates.filter(it.milestone_id == project.milestone_id)
	}
	if project.iteration_id > 0 {
		candidates = candidates.filter(it.iteration_id == project.iteration_id)
	}
	if project.assignee_id > 0 {
		links := sql app.db {
			select from IssueAssignee where user_id == project.assignee_id
		} or { []IssueAssignee{} }
		ids := links.map(it.issue_id)
		candidates = candidates.filter(it.id in ids)
	}
	return candidates
}

fn (mut app App) delete_project_card(id int) ! {
	sql app.db {
		delete from ProjectCard where id == id
	}!
}
