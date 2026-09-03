// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import time

// Project access levels intentionally use the same numeric ordering as GitLab's
// relevant repository roles. Keeping the values ordered makes permission checks
// explicit and leaves room for Guest/Planner roles when issue-only permissions
// are split out in the future.
const project_access_reporter = 20
const project_access_developer = 30
const project_access_maintainer = 40
const project_access_owner = 50
const project_access_no_one = 100

struct ProjectMember {
	id         int @[primary; sql: serial]
	repo_id    int @[unique: 'project_member']
	user_id    int @[unique: 'project_member']
	role       string
	created_at int
}

struct ProjectMemberView {
	member ProjectMember
	user   User
}

fn project_role_access_level(role string) int {
	return match role {
		'reporter' { project_access_reporter }
		'developer' { project_access_developer }
		'maintainer' { project_access_maintainer }
		else { 0 }
	}
}

fn valid_project_member_role(role string) bool {
	return role in ['reporter', 'developer', 'maintainer']
}

fn (app &App) direct_project_access_level(repo_id int, user_id int) int {
	if repo_id <= 0 || user_id <= 0 {
		return 0
	}
	rows := sql app.db {
		select from ProjectMember where repo_id == repo_id && user_id == user_id limit 1
	} or { []ProjectMember{} }
	if rows.len == 0 {
		return 0
	}
	return project_role_access_level(rows.first().role)
}

// repo_access_level combines direct project membership with inherited
// namespace access. Personal owners and organization administrators retain
// Owner-equivalent access, while ordinary organization members inherit
// Reporter access and can be promoted on an individual project.
fn (app &App) repo_access_level(user_id int, repo Repo) int {
	if user_id <= 0 {
		return 0
	}
	mut level := app.direct_project_access_level(repo.id, user_id)
	if org := app.get_org_by_name(repo.user_name) {
		if role := app.org_member_role(org.id, user_id) {
			inherited := if role == 'admin' { project_access_owner } else { project_access_reporter }
			if inherited > level {
				level = inherited
			}
		}
	} else if repo.user_id == user_id {
		level = project_access_owner
	}
	return level
}

fn (mut app App) add_project_member(repo_id int, user_id int, role string) !int {
	if repo_id <= 0 || user_id <= 0 || !valid_project_member_role(role) {
		return error('invalid project member')
	}
	return db_insert_returning_id(mut app.db, 'ProjectMember', ['repo_id', 'user_id', 'role',
		'created_at'], [repo_id.str(), user_id.str(), role, int(time.now().unix()).str()])
}

fn (app &App) find_project_members(repo_id int) []ProjectMemberView {
	members := sql app.db {
		select from ProjectMember where repo_id == repo_id order by created_at
	} or { []ProjectMember{} }
	mut result := []ProjectMemberView{cap: members.len}
	for member in members {
		user := app.get_user_by_id(member.user_id) or { continue }
		if !user.is_registered || user.is_blocked {
			continue
		}
		result << ProjectMemberView{
			member: member
			user:   user
		}
	}
	result.sort(a.user.username.to_lower() < b.user.username.to_lower())
	return result
}

fn (app &App) find_project_member_by_id(repo_id int, member_id int) ?ProjectMember {
	rows := sql app.db {
		select from ProjectMember where id == member_id && repo_id == repo_id limit 1
	} or { []ProjectMember{} }
	if rows.len == 0 {
		return none
	}
	return rows.first()
}

fn (mut app App) update_project_member_role(repo_id int, member_id int, role string) ! {
	if repo_id <= 0 || member_id <= 0 || !valid_project_member_role(role) {
		return error('invalid project member role')
	}
	rows := db_exec_values(mut app.db, 'update ${sql_table('ProjectMember')}
		set ${sql_table('role')} = ${sql_literal(role)}
		where ${sql_table('id')} = ${member_id}
			and ${sql_table('repo_id')} = ${repo_id}
		returning ${sql_table('id')}')!
	if rows.len != 1 {
		return error('project member not found')
	}
}

fn (mut app App) remove_project_member(repo_id int, member_id int) ! {
	if repo_id <= 0 || member_id <= 0 {
		return error('invalid project member')
	}
	rows := db_exec_values(mut app.db, 'delete from ${sql_table('ProjectMember')}
		where ${sql_table('id')} = ${member_id}
			and ${sql_table('repo_id')} = ${repo_id}
		returning ${sql_table('id')}')!
	if rows.len != 1 {
		return error('project member not found')
	}
}

fn (mut app App) delete_repo_project_members(repo_id int) ! {
	sql app.db {
		delete from ProjectMember where repo_id == repo_id
	}!
}
