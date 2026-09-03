module main

import time

fn test_release_views_keep_release_dates_and_do_not_leak_previous_tag_metadata() {
	release_time := time.unix(100)
	second_release_time := time.unix(200)
	releases := [
		Release{
			id: 1
			tag_id: 10
			notes: 'first'
			date: release_time
		},
		Release{
			id: 2
			tag_id: 999
			notes: 'second'
			date: second_release_time
		},
	]
	tags := [Tag{
		id: 10
		name: 'v1.0.0'
		hash: 'deadbeef'
		user_id: 7
		// This is deliberately different from the release publication date.
		created_at: 50
	}]
	users := [User{
		id: 7
		username: 'maintainer'
	}]

	views := build_release_views(releases, tags, users)
	assert views.len == 2
	assert views[0].tag_name == 'v1.0.0'
	assert views[0].tag_hash == 'deadbeef'
	assert views[0].user == 'maintainer'
	assert views[0].date.unix() == release_time.unix()
	assert views[1].tag_name == ''
	assert views[1].tag_hash == ''
	assert views[1].user == ''
	assert views[1].date.unix() == second_release_time.unix()
}
