// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import veb

@['/:username/:repo_name/settings/mirrors']
pub fn (mut app App) repo_mirrors(mut ctx Context, username string, repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	mirrors := app.list_repo_mirrors(repo.id)
	return $veb.html('templates/repo/mirrors.html')
}

@['/:username/:repo_name/settings/mirrors'; post]
pub fn (mut app App) handle_add_repo_mirror(mut ctx Context, username string, repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	app.add_repo_mirror(repo.id, ctx.user.id, ctx.form['url'], ctx.form['mirror_username'],
		ctx.form['mirror_password'], ctx.form['ssh_private_key'], ctx.form['ssh_known_hosts'],
		ctx.form['direction'], ctx.form['overwrite_diverged'] == 'on',
		ctx.form['only_protected'] == 'on', ctx.form['interval_minutes'].int()) or {
		ctx.error(err.str())
		return app.repo_mirrors(mut ctx, username, repo_name)
	}
	return ctx.redirect('/${username}/${repo_name}/settings/mirrors')
}

@['/:username/:repo_name/settings/mirrors/:id/sync'; post]
pub fn (mut app App) handle_sync_repo_mirror(mut ctx Context, username string, repo_name string, id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	mirror := app.find_repo_mirror(id.int()) or { return ctx.not_found() }
	if mirror.repo_id != repo.id {
		return ctx.not_found()
	}
	app.sync_repo_mirror(mirror, false) or { ctx.error(err.str()) }
	return app.repo_mirrors(mut ctx, username, repo_name)
}

@['/:username/:repo_name/settings/mirrors/:id/toggle'; post]
pub fn (mut app App) handle_toggle_repo_mirror(mut ctx Context, username string, repo_name string, id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	mirror := app.find_repo_mirror(id.int()) or { return ctx.not_found() }
	if mirror.repo_id != repo.id {
		return ctx.not_found()
	}
	app.set_repo_mirror_enabled(repo.id, mirror.id, !mirror.enabled) or {
		ctx.error('Could not update the mirror')
	}
	return ctx.redirect('/${username}/${repo_name}/settings/mirrors')
}

@['/:username/:repo_name/settings/mirrors/:id/delete'; post]
pub fn (mut app App) handle_delete_repo_mirror(mut ctx Context, username string, repo_name string, id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	mirror := app.find_repo_mirror(id.int()) or { return ctx.not_found() }
	if mirror.repo_id != repo.id {
		return ctx.not_found()
	}
	app.delete_repo_mirror(repo.id, mirror.id) or { ctx.error('Could not delete the mirror') }
	return ctx.redirect('/${username}/${repo_name}/settings/mirrors')
}
