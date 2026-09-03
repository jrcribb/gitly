module main

import veb

@['/:username/:repo_name/releases']
pub fn (mut app App) releases_default(mut ctx Context, username string, repo_name string) veb.Result {
	return app.releases(mut ctx, username, repo_name, '0')
}

@['/:username/:repo_name/releases/:page']
pub fn (mut app App) releases(mut ctx Context, username string, repo_name string, page string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }

	if !app.can_read_repo(ctx, repo) {
		return ctx.not_found()
	}

	repo_id := repo.id
	release_count := app.get_repo_release_count(repo_id)
	page_count := calculate_pages(release_count, releases_per_page)
	page_i := normalize_page(page, page_count)
	offset := releases_per_page * page_i
	is_first_page := check_first_page(page_i)
	is_last_page := check_last_page(release_count, offset, releases_per_page)
	prev_page, next_page := generate_prev_next_pages(page_i)

	tags := app.get_all_repo_tags(repo_id)
	rels := app.find_repo_releases_as_page(repo_id, offset)
	users := app.find_repo_registered_contributor(repo_id)

	releases := build_release_views(rels, tags, users)

	return $veb.html()
}

fn build_release_views(rels []Release, tags []Tag, users []User) []Release {
	mut releases := []Release{cap: rels.len}
	for rel in rels {
		mut release := rel
		mut user_id := 0

		for tag in tags {
			if tag.id == rel.tag_id {
				release.tag_name = tag.name
				release.tag_hash = tag.hash
				user_id = tag.user_id
				break
			}
		}
		for user in users {
			if user.id == user_id {
				release.user = user.username
				break
			}
		}
		releases << release
	}
	return releases
}
