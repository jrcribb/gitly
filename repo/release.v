module main

import time

const releases_per_page = 20

struct Release {
	id      int @[primary; sql: serial]
	repo_id int @[unique: 'release']
mut:
	tag_id     int @[unique: 'release']
	notes      string
	tag_name   string @[skip]
	tag_hash   string @[skip]
	user       string @[skip]
	date       time.Time
	created_by int
	is_manual  bool
	is_deleted bool
}

pub fn (mut app App) add_release(tag_id int, repo_id int, date time.Time, notes string) ! {
	existing := sql app.db {
		select from Release where tag_id == tag_id && repo_id == repo_id limit 1
	} or { []Release{} }
	if existing.len > 0 {
		if existing[0].is_manual {
			return
		}
		id := existing[0].id
		sql app.db {
			update Release set notes = notes, date = date where id == id
		}!
		return
	}

	release := Release{
		tag_id: tag_id
		repo_id: repo_id
		notes: notes
		date: date
	}

	sql app.db {
		insert release into Release
	}!
}

fn (mut app App) publish_release(repo Repo, tag_name string, notes string, actor_id int) !Release {
	if actor_id <= 0 || app.repo_access_level(actor_id, repo) < project_access_maintainer
		|| !valid_body(notes) {
		return error('Maintainer access is required to publish a release')
	}
	tags := sql app.db {
		select from Tag where repo_id == repo.id && name == tag_name limit 1
	}!
	if tags.len != 1 {
		return error('release tag does not exist')
	}
	if !app.user_can_create_tag(actor_id, repo, tag_name) {
		return error('the protected tag policy does not allow this release')
	}
	app.add_release(tags.first().id, repo.id, time.now(), notes)!
	tag_id := tags.first().id
	manual := true
	now := time.now()
	sql app.db {
		update Release set notes = notes, date = now, created_by = actor_id, is_manual = manual,
		is_deleted = false
		where repo_id == repo.id && tag_id == tag_id
	}!
	rows := sql app.db {
		select from Release where repo_id == repo.id && tag_id == tags.first().id limit 1
	}!
	if rows.len != 1 {
		return error('release was not saved')
	}
	return rows.first()
}

fn (mut app App) remove_published_release(repo Repo, release_id int, actor_id int) ! {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer {
		return error('Maintainer access is required to remove a release')
	}
	repo_id := repo.id
	id := release_id
	releases := sql app.db {
		select from Release where repo_id == repo_id && id == id limit 1
	}!
	if releases.len != 1 {
		return error('release not found')
	}
	sql app.db {
		update Release set is_deleted = true where id == id && repo_id == repo_id
	}!
}

fn (mut app App) delete_release_for_tag(repo_id int, tag_id int) ! {
	sql app.db {
		delete from Release where repo_id == repo_id && tag_id == tag_id
	}!
}

pub fn (mut app App) find_repo_releases_as_page(repo_id int, offset int) []Release {
	return sql app.db {
		select from Release where repo_id == repo_id && is_deleted == false order by date desc limit releases_per_page offset offset
	} or { []Release{} }
}

pub fn (app App) get_repo_release_count(repo_id int) int {
	return sql app.db {
		select count from Release where repo_id == repo_id && is_deleted == false
	} or { 0 }
}

pub fn (mut app App) delete_repo_releases(repo_id int) ! {
	sql app.db {
		delete from Release where repo_id == repo_id
	}!
}
