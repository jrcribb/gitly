// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import crypto.rand
import encoding.hex
import time

struct Epic {
	id int @[primary; sql: serial]
mut:
	org_id         int
	parent_epic_id int
	author_id      int
	title          string
	description    string
	state          string
	starts_at      int
	due_at         int
	created_at     int
	updated_at     int
}

struct EpicIssue {
	id int @[primary; sql: serial]
mut:
	epic_id  int @[unique: 'epic_issue']
	issue_id int @[unique: 'epic_issue']
}

struct Iteration {
	id int @[primary; sql: serial]
mut:
	org_id      int
	title       string
	description string
	state       string
	starts_at   int
	due_at      int
	created_at  int
	updated_at  int
}

struct IssueTask {
	id int @[primary; sql: serial]
mut:
	issue_id     int
	created_by   int
	title        string
	completed    bool
	position     int
	created_at   int
	completed_at int
}

struct IssueTimeEntry {
	id int @[primary; sql: serial]
mut:
	issue_id   int
	user_id    int
	minutes    int
	note       string
	created_at int
}

struct IssueRelationship {
	id int @[primary; sql: serial]
mut:
	source_issue_id   int @[unique: 'issue_relationship']
	target_issue_id   int @[unique: 'issue_relationship']
	relationship_type string @[unique: 'issue_relationship']
	created_by        int
	created_at        int
}

struct ServiceDeskTicket {
	id int @[primary; sql: serial]
mut:
	repo_id         int
	issue_id        int @[unique]
	requester_email string
	external_id     string
	created_at      int
}

struct IssuePlanningSummary {
	tasks         []IssueTask
	time_entries  []IssueTimeEntry
	time_spent    int
	relationships []IssueRelationship
	iteration     Iteration
}

fn valid_group_path_component(value string) bool {
	clean := value.trim_space().to_lower()
	if clean == '' || clean.len > max_username_len || clean.starts_with('-') || clean.ends_with('-') {
		return false
	}
	for ch in clean.bytes() {
		if !ch.is_alnum() && ch !in [`-`, `_`, `.`] {
			return false
		}
	}
	return true
}

fn (mut app App) add_subgroup(parent_id int, path string, display_name string, created_by int) !int {
	parent := app.get_org_by_id(parent_id) or { return error('parent group not found') }
	if !valid_group_path_component(path) || !valid_short_name(display_name) || created_by <= 0
		|| !app.user_can_admin_group(created_by, parent.id) {
		return error('invalid subgroup or permission')
	}
	full_path := '${parent.name}/${path.trim_space().to_lower()}'
	if full_path.len > 255 {
		return error('group path is too long')
	}
	row := Org{
		name: full_path
		contact_email: parent.contact_email
		kind: parent.kind
		created_at: time.now()
		created_by: created_by
		parent_id: parent.id
		display_name: display_name.trim_space()
	}
	sql app.db {
		insert row into Org
	}!
	created := app.get_org_by_name(full_path) or { return error('subgroup was not saved') }
	return created.id
}

fn (app &App) find_subgroups(parent_id int) []Org {
	return sql app.db {
		select from Org where parent_id == parent_id order by display_name
	} or { []Org{} }
}

fn (app &App) group_ancestors(org_id int) []Org {
	mut result := []Org{}
	mut current_id := org_id
	mut seen := map[int]bool{}
	for current_id > 0 && !seen[current_id] {
		seen[current_id] = true
		org := app.get_org_by_id(current_id) or { break }
		result << org
		current_id = org.parent_id
	}
	return result
}

fn (app &App) group_effective_role(org_id int, user_id int) string {
	mut is_member := false
	for org in app.group_ancestors(org_id) {
		role := app.org_member_role(org.id, user_id) or { continue }
		if role == 'admin' {
			return 'admin'
		}
		if role == 'member' {
			is_member = true
		}
	}
	return if is_member { 'member' } else { '' }
}

fn (app &App) user_can_read_group(user_id int, org_id int) bool {
	return app.get_org_by_id(org_id) != none && app.group_effective_role(org_id, user_id) != ''
}

fn (app &App) user_can_admin_group(user_id int, org_id int) bool {
	return app.group_effective_role(org_id, user_id) == 'admin'
}

fn (mut app App) add_epic(org_id int, parent_epic_id int, author_id int, title string,
	description string, starts_at int, due_at int) !int {
	if org_id <= 0 || author_id <= 0 || !valid_title(title) || !valid_body(description)
		|| starts_at < 0 || due_at < 0 || (starts_at > 0 && due_at > 0 && due_at < starts_at) {
		return error('invalid epic')
	}
	if parent_epic_id > 0 {
		parent := app.find_epic(parent_epic_id) or { return error('parent epic not found') }
		if parent.org_id != org_id {
			return error('parent epic belongs to another group')
		}
	}
	now := int(time.now().unix())
	return db_insert_returning_id(mut app.db, 'Epic', ['org_id', 'parent_epic_id', 'author_id',
		'title', 'description', 'state', 'starts_at', 'due_at', 'created_at', 'updated_at'], [
		org_id.str(),
		parent_epic_id.str(),
		author_id.str(),
		title.trim_space(),
		description,
		'open',
		starts_at.str(),
		due_at.str(),
		now.str(),
		now.str(),
	])
}

fn (app &App) find_epic(id int) ?Epic {
	rows := sql app.db {
		select from Epic where id == id limit 1
	} or { []Epic{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) find_group_epics(org_id int) []Epic {
	return sql app.db {
		select from Epic where org_id == org_id order by starts_at
	} or { []Epic{} }
}

fn (mut app App) update_epic(epic_id int, title string, description string, state string,
	starts_at int, due_at int) ! {
	if !valid_title(title) || !valid_body(description) || state !in ['open', 'closed'] || starts_at < 0 || due_at < 0 || (starts_at > 0 && due_at > 0 && due_at < starts_at) {
		return error('invalid epic')
	}
	now := int(time.now().unix())
	sql app.db {
		update Epic set title = title, description = description, state = state,
		starts_at = starts_at, due_at = due_at, updated_at = now where id == epic_id
	}!
}

fn (mut app App) delete_epic(org_id int, epic_id int) ! {
	epics := sql app.db {
		select from Epic where id == epic_id && org_id == org_id limit 1
	}!
	if epics.len != 1 {
		return error('epic not found')
	}
	sql app.db {
		delete from EpicIssue where epic_id == epic_id
	}!
	zero := 0
	sql app.db {
		update Epic set parent_epic_id = zero where parent_epic_id == epic_id
	}!
	sql app.db {
		delete from Epic where id == epic_id && org_id == org_id
	}!
}

fn (mut app App) add_issue_to_epic(epic_id int, issue_id int) ! {
	epic := app.find_epic(epic_id) or { return error('epic not found') }
	issue := app.find_issue_by_id(issue_id) or { return error('issue not found') }
	repo := app.find_repo_by_id(issue.repo_id) or { return error('repository not found') }
	org := app.get_org_by_id(epic.org_id) or { return error('group not found') }
	if repo.user_name != org.name && !repo.user_name.starts_with(org.name + '/') {
		return error('issue is outside this group')
	}
	link := EpicIssue{
		epic_id: epic_id
		issue_id: issue_id
	}
	sql app.db {
		insert link into EpicIssue
	}!
}

fn (mut app App) find_epic_issues(epic_id int) []Issue {
	links := sql app.db {
		select from EpicIssue where epic_id == epic_id order by id
	} or { []EpicIssue{} }
	mut issues := []Issue{}
	for link in links {
		issue := app.find_issue_by_id(link.issue_id) or { continue }
		issues << issue
	}
	return issues
}

fn (mut app App) add_iteration(org_id int, title string, description string, starts_at int,
	due_at int) !int {
	if org_id <= 0 || !valid_title(title) || !valid_body(description) || starts_at <= 0
		|| due_at < starts_at {
		return error('invalid iteration')
	}
	now := int(time.now().unix())
	return db_insert_returning_id(mut app.db, 'Iteration', ['org_id', 'title', 'description', 'state',
		'starts_at', 'due_at', 'created_at', 'updated_at'], [org_id.str(), title.trim_space(),
		description, 'upcoming', starts_at.str(), due_at.str(), now.str(), now.str()])
}

fn (app &App) find_iteration(id int) ?Iteration {
	rows := sql app.db {
		select from Iteration where id == id limit 1
	} or { []Iteration{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) find_group_iterations(org_id int) []Iteration {
	return sql app.db {
		select from Iteration where org_id == org_id order by starts_at desc
	} or { []Iteration{} }
}

fn (mut app App) update_iteration(iteration_id int, title string, description string, state string,
	starts_at int, due_at int) ! {
	if !valid_title(title) || !valid_body(description) || state !in ['upcoming', 'current', 'closed'] || starts_at <= 0 || due_at < starts_at {
		return error('invalid iteration')
	}
	now := int(time.now().unix())
	sql app.db {
		update Iteration set title = title, description = description, state = state,
		starts_at = starts_at, due_at = due_at, updated_at = now where id == iteration_id
	}!
}

fn (mut app App) delete_iteration(org_id int, iteration_id int) ! {
	rows := sql app.db {
		select from Iteration where id == iteration_id && org_id == org_id limit 1
	}!
	if rows.len != 1 {
		return error('iteration not found')
	}
	zero := 0
	sql app.db {
		update Issue set iteration_id = zero where iteration_id == iteration_id
	}!
	sql app.db {
		update Project set iteration_id = zero where iteration_id == iteration_id
	}!
	sql app.db {
		delete from Iteration where id == iteration_id && org_id == org_id
	}!
}

fn (mut app App) assign_issue_iteration(issue_id int, iteration_id int) ! {
	issue := app.find_issue_by_id(issue_id) or { return error('issue not found') }
	if iteration_id > 0 {
		iteration := app.find_iteration(iteration_id) or { return error('iteration not found') }
		repo := app.find_repo_by_id(issue.repo_id) or { return error('repository not found') }
		org := app.get_org_by_id(iteration.org_id) or { return error('group not found') }
		if repo.user_name != org.name && !repo.user_name.starts_with(org.name + '/') {
			return error('iteration belongs to another group')
		}
	}
	sql app.db {
		update Issue set iteration_id = iteration_id where id == issue_id
	}!
}

fn (mut app App) add_issue_task(issue_id int, created_by int, title string) !int {
	if issue_id <= 0 || created_by <= 0 || !valid_title(title) {
		return error('invalid task')
	}
	position := sql app.db {
		select count from IssueTask where issue_id == issue_id
	} or { 0 }
	return db_insert_returning_id(mut app.db, 'IssueTask', ['issue_id', 'created_by', 'title',
		'completed', 'position', 'created_at', 'completed_at'], [issue_id.str(), created_by.str(),
		title.trim_space(), db_bool_value(false), position.str(), int(time.now().unix()).str(),
		'0'])
}

fn (app &App) find_issue_tasks(issue_id int) []IssueTask {
	return sql app.db {
		select from IssueTask where issue_id == issue_id order by position
	} or { []IssueTask{} }
}

fn (mut app App) set_issue_task_completed(issue_id int, task_id int, completed bool) ! {
	completed_at := if completed { int(time.now().unix()) } else { 0 }
	sql app.db {
		update IssueTask set completed = completed, completed_at = completed_at
		where id == task_id && issue_id == issue_id
	}!
}

fn (mut app App) delete_issue_task(issue_id int, task_id int) ! {
	sql app.db {
		delete from IssueTask where id == task_id && issue_id == issue_id
	}!
}

fn (mut app App) set_issue_time_estimate(issue_id int, minutes int) ! {
	if minutes < 0 || minutes > 10 * 365 * 24 * 60 {
		return error('invalid time estimate')
	}
	sql app.db {
		update Issue set time_estimate_minutes = minutes where id == issue_id
	}!
}

fn (mut app App) add_issue_time(issue_id int, user_id int, minutes int, note string) !int {
	if issue_id <= 0 || user_id <= 0 || minutes <= 0 || minutes > 365 * 24 * 60
		|| note.len > 1000 {
		return error('invalid time entry')
	}
	return db_insert_returning_id(mut app.db, 'IssueTimeEntry', ['issue_id', 'user_id', 'minutes',
		'note', 'created_at'], [issue_id.str(), user_id.str(), minutes.str(), note.trim_space(),
		int(time.now().unix()).str()])
}

fn (app &App) find_issue_time_entries(issue_id int) []IssueTimeEntry {
	return sql app.db {
		select from IssueTimeEntry where issue_id == issue_id order by created_at desc
	} or { []IssueTimeEntry{} }
}

fn (mut app App) delete_issue_time_entry(issue_id int, entry_id int, actor_id int,
	can_admin bool) ! {
	entries := sql app.db {
		select from IssueTimeEntry where id == entry_id && issue_id == issue_id limit 1
	}!
	if entries.len != 1 || (entries.first().user_id != actor_id && !can_admin) {
		return error('time entry not found or not permitted')
	}
	sql app.db {
		delete from IssueTimeEntry where id == entry_id && issue_id == issue_id
	}!
}

fn (app &App) issue_time_spent(issue_id int) int {
	entries := app.find_issue_time_entries(issue_id)
	mut total := 0
	for entry in entries {
		total += entry.minutes
	}
	return total
}

fn normalize_issue_relationship(value string) ?string {
	clean := value.trim_space().to_lower()
	if clean in ['relates_to', 'blocks'] {
		return clean
	}
	return none
}

fn (mut app App) relate_issues(source_issue_id int, target_issue_id int, relation string,
	created_by int) !int {
	kind := normalize_issue_relationship(relation) or { return error('invalid issue relationship') }
	if source_issue_id <= 0 || target_issue_id <= 0 || source_issue_id == target_issue_id
		|| created_by <= 0 {
		return error('invalid issue relationship')
	}
	source := app.find_issue_by_id(source_issue_id) or { return error('source issue not found') }
	target := app.find_issue_by_id(target_issue_id) or { return error('target issue not found') }
	if source.repo_id != target.repo_id || source.is_pr || target.is_pr {
		return error('related issues must belong to the same project')
	}
	return db_insert_returning_id(mut app.db, 'IssueRelationship', ['source_issue_id',
		'target_issue_id', 'relationship_type', 'created_by', 'created_at'], [
		source_issue_id.str(),
		target_issue_id.str(),
		kind,
		created_by.str(),
		int(time.now().unix()).str(),
	])
}

fn (app &App) find_issue_relationships(issue_id int) []IssueRelationship {
	return sql app.db {
		select from IssueRelationship where source_issue_id == issue_id || target_issue_id == issue_id
		order by id
	} or { []IssueRelationship{} }
}

fn (mut app App) remove_issue_relationship(issue_id int, relationship_id int) ! {
	sql app.db {
		delete from IssueRelationship where id == relationship_id
		&& (source_issue_id == issue_id || target_issue_id == issue_id)
	}!
}

fn generate_service_desk_token() !string {
	return 'glsd_' + hex.encode(rand.bytes(24)!)
}

fn (mut app App) enable_service_desk(repo_id int) !string {
	secret := generate_service_desk_token()!
	hash := hash_api_token(secret)
	enabled := true
	sql app.db {
		update Repo set service_desk_enabled = enabled, service_desk_token_hash = hash
		where id == repo_id
	}!
	return secret
}

fn (mut app App) disable_service_desk(repo_id int) ! {
	disabled := false
	empty := ''
	sql app.db {
		update Repo set service_desk_enabled = disabled, service_desk_token_hash = empty
		where id == repo_id
	}!
}

fn (mut app App) create_service_desk_issue(secret string, requester_email string, subject string,
	body string, external_id string) !int {
	if !secret.starts_with('glsd_') || secret.len > 128 || !valid_title(subject)
		|| !valid_body(body) || !valid_service_desk_email(requester_email)
		|| external_id.len > 255 {
		return error('invalid service desk request')
	}
	hash := hash_api_token(secret)
	repos := sql app.db {
		select from Repo where service_desk_enabled == true && service_desk_token_hash == hash
		&& is_deleted == false limit 1
	}!
	if repos.len != 1 {
		return error('service desk endpoint not found')
	}
	repo := repos.first()
	if external_id != '' {
		existing := sql app.db {
			select from ServiceDeskTicket where repo_id == repo.id && external_id == external_id limit 1
		}!
		if existing.len > 0 {
			return existing.first().issue_id
		}
	}
	issue_id := app.add_issue_returning_id(repo.id, 0, subject.trim_space(), body)!
	row := ServiceDeskTicket{
		repo_id: repo.id
		issue_id: issue_id
		requester_email: requester_email.trim_space().to_lower()
		external_id: external_id
		created_at: int(time.now().unix())
	}
	sql app.db {
		insert row into ServiceDeskTicket
	}!
	app.sync_repo_open_issue_count(repo.id)!
	return issue_id
}

fn valid_service_desk_email(value string) bool {
	clean := value.trim_space()
	return clean.len >= 3 && clean.len <= 320 && clean.contains('@') && !clean.contains_any(' \t\r\n')
}

fn (app &App) issue_planning_summary(issue Issue) IssuePlanningSummary {
	return IssuePlanningSummary{
		tasks: app.find_issue_tasks(issue.id)
		time_entries: app.find_issue_time_entries(issue.id)
		time_spent: app.issue_time_spent(issue.id)
		relationships: app.find_issue_relationships(issue.id)
		iteration: if issue.iteration_id > 0 {
			app.find_iteration(issue.iteration_id) or { Iteration{} }
		} else {
			Iteration{}
		}
	}
}
