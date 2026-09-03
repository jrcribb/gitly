module main

import time

const releases_per_page = 20

struct Release {
	id      int @[primary; sql: serial]
	repo_id int @[unique: 'release']
mut:
	tag_id   int @[unique: 'release']
	notes    string
	tag_name string @[skip]
	tag_hash string @[skip]
	user     string @[skip]
	date     time.Time
}

pub fn (mut app App) add_release(tag_id int, repo_id int, date time.Time, notes string) ! {
	existing := sql app.db {
		select from Release where tag_id == tag_id && repo_id == repo_id limit 1
	} or { []Release{} }
	if existing.len > 0 {
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

fn (mut app App) delete_release_for_tag(repo_id int, tag_id int) ! {
	sql app.db {
		delete from Release where repo_id == repo_id && tag_id == tag_id
	}!
}

pub fn (mut app App) find_repo_releases_as_page(repo_id int, offset int) []Release {
	return sql app.db {
		select from Release where repo_id == repo_id order by date desc limit releases_per_page offset offset
	} or { []Release{} }
}

pub fn (app App) get_repo_release_count(repo_id int) int {
	return sql app.db {
		select count from Release where repo_id == repo_id
	} or { 0 }
}

pub fn (mut app App) delete_repo_releases(repo_id int) ! {
	sql app.db {
		delete from Release where repo_id == repo_id
	}!
}
