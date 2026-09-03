// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import time

struct Org {
	id            int @[primary; sql: serial]
	name          string @[unique]
	contact_email string
	kind          string
	created_at    time.Time
	created_by    int
	parent_id     int
	display_name  string
}

struct OrgMember {
	id      int @[primary; sql: serial]
	org_id  int @[unique: 'org_member']
	user_id int @[unique: 'org_member']
	role    string
}

struct OrgMemberView {
	user User
	role string
}

pub fn (mut app App) add_org(name string, contact_email string, kind string, created_by int) !int {
	new_org := Org{
		name: name
		contact_email: contact_email
		kind: kind
		created_at: time.now()
		created_by: created_by
		display_name: name
	}
	sql app.db {
		insert new_org into Org
	}!
	row := app.get_org_by_name(name) or { return error('failed to load newly created org') }
	return row.id
}

fn (mut app App) backfill_org_display_names() ! {
	orgs := sql app.db {
		select from Org
	}!
	for org in orgs {
		if org.display_name != '' {
			continue
		}
		id := org.id
		display_name := org.name.all_after_last('/')
		sql app.db {
			update Org set display_name = display_name where id == id
		}!
	}
}

pub fn (app App) get_org_by_name(name string) ?Org {
	rows := sql app.db {
		select from Org where name == name limit 1
	} or { [] }
	if rows.len == 0 {
		return none
	}
	return rows.first()
}

pub fn (app App) get_org_by_id(id int) ?Org {
	rows := sql app.db {
		select from Org where id == id limit 1
	} or { [] }
	if rows.len == 0 {
		return none
	}
	return rows.first()
}

pub fn (mut app App) add_org_member(org_id int, user_id int, role string) ! {
	member := OrgMember{
		org_id: org_id
		user_id: user_id
		role: role
	}
	sql app.db {
		insert member into OrgMember
	}!
}

pub fn (app App) find_orgs_for_user(user_id int) []Org {
	members := sql app.db {
		select from OrgMember where user_id == user_id
	} or { [] }
	mut orgs := []Org{cap: members.len}
	for m in members {
		org := app.get_org_by_id(m.org_id) or { continue }
		orgs << org
	}
	return orgs
}

pub fn (app App) find_orgs_administered_by_user(user_id int) []Org {
	members := sql app.db {
		select from OrgMember where user_id == user_id && role == 'admin'
	} or { []OrgMember{} }
	mut orgs := []Org{cap: members.len}
	for member in members {
		org := app.get_org_by_id(member.org_id) or { continue }
		orgs << org
	}
	return orgs
}

pub fn (app App) is_org_member(org_id int, user_id int) bool {
	count := sql app.db {
		select count from OrgMember where org_id == org_id && user_id == user_id
	} or { 0 }
	return count > 0
}

pub fn (app App) find_org_members(org_id int) []OrgMemberView {
	members := sql app.db {
		select from OrgMember where org_id == org_id
	} or { []OrgMember{} }
	mut result := []OrgMemberView{cap: members.len}
	for member in members {
		user := app.get_user_by_id(member.user_id) or { continue }
		if !user.is_registered {
			continue
		}
		result << OrgMemberView{
			user: user
			role: member.role
		}
	}
	result.sort(a.user.username.to_lower() < b.user.username.to_lower())
	return result
}

pub fn (app App) find_org_repos(org_name string, include_private bool) []Repo {
	if include_private {
		return sql app.db {
			select from Repo where user_name == org_name && is_deleted == false order by name
		} or { []Repo{} }
	}
	return sql app.db {
		select from Repo where user_name == org_name && is_public == true && is_deleted == false order by name
	} or { []Repo{} }
}

pub fn (mut app App) remove_org_member(org_id int, user_id int) ! {
	sql app.db {
		delete from OrgMember where org_id == org_id && user_id == user_id
	}!
}

pub fn (mut app App) delete_org(org_id int) ! {
	sql app.db {
		delete from Org where id == org_id
	}!
}

pub fn (app App) count_org_admins(org_id int) int {
	return sql app.db {
		select count from OrgMember where org_id == org_id && role == 'admin'
	} or { 0 }
}

pub fn (app App) org_member_role(org_id int, user_id int) ?string {
	rows := sql app.db {
		select from OrgMember where org_id == org_id && user_id == user_id limit 1
	} or { []OrgMember{} }
	if rows.len == 0 {
		return none
	}
	return rows.first().role
}

// A repository currently stores its namespace in Repo.user_name. Resolve that
// namespace as an organization when present so organization repositories work
// for every member instead of only the user who originally created the row.
fn (app App) user_is_repo_org_member(user_id int, repo Repo) bool {
	org := app.get_org_by_name(repo.user_name) or { return false }
	return app.is_org_member(org.id, user_id)
}

fn (app App) user_can_admin_repo_org(user_id int, repo Repo) bool {
	org := app.get_org_by_name(repo.user_name) or { return false }
	role := app.org_member_role(org.id, user_id) or { return false }
	return role == 'admin'
}
