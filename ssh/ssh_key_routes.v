module main

import veb
import validation
import api

@['/:username/settings/ssh-keys']
pub fn (mut app App) user_ssh_keys_list(mut ctx Context, username string) veb.Result {
	is_users_settings := username == ctx.user.username

	if !ctx.logged_in || !is_users_settings {
		return ctx.redirect_to_index()
	}

	ssh_keys := app.find_ssh_keys(ctx.user.id)

	return $veb.html('templates/user/ssh/keys/list.html')
}

@['/:username/settings/ssh-keys'; 'post']
pub fn (mut app App) handle_add_ssh_key(mut ctx Context, username string) veb.Result {
	is_users_settings := username == ctx.user.username

	if !ctx.logged_in || !is_users_settings {
		return ctx.redirect_to_index()
	}

	title := ctx.form['title']
	ssh_key := ctx.form['key']
	usage_type := ctx.form['usage_type'].trim_space()
	expires_at := parse_yyyy_mm_dd(ctx.form['expires_at'].trim_space())

	is_title_empty := validation.is_string_empty(title)
	is_ssh_key_empty := validation.is_string_empty(ssh_key)

	if is_title_empty || title.len > max_short_name_len {
		ctx.error('Title is empty or too long')

		return app.user_ssh_keys_new(mut ctx, username)
	}

	if is_ssh_key_empty || ssh_key.len > 16_384 || !is_valid_ssh_public_key(ssh_key) {
		ctx.error('SSH key is empty, too long, or invalid')

		return app.user_ssh_keys_new(mut ctx, username)
	}

	if !valid_ssh_usage_type(usage_type) || (ctx.form['expires_at'] != '' && expires_at <= 0) {
		ctx.error('Usage type or expiration date is invalid')
		return app.user_ssh_keys_new(mut ctx, username)
	}

	app.add_ssh_key(ctx.user.id, title, ssh_key, usage_type, expires_at) or {
		ctx.error(err.str())

		return app.user_ssh_keys_new(mut ctx, username)
	}

	return ctx.redirect('/${username}/settings/ssh-keys')
}

@['/:username/settings/ssh-keys/:id'; 'delete']
pub fn (mut app App) handle_remove_ssh_key(mut ctx Context, username string, id string) veb.Result {
	is_users_settings := username == ctx.user.username

	if !ctx.logged_in || !is_users_settings {
		return ctx.redirect_to_index()
	}

	app.remove_ssh_key(ctx.user.id, id.int()) or {
		response := api.ApiErrorResponse{
			message: 'There was an error while deleting the SSH key'
		}

		return ctx.json(response)
	}

	return ctx.ok('')
}

@['/:username/settings/ssh-keys/new']
pub fn (mut app App) user_ssh_keys_new(mut ctx Context, username string) veb.Result {
	is_users_settings := username == ctx.user.username

	if !ctx.logged_in || !is_users_settings {
		return ctx.redirect_to_index()
	}

	return $veb.html('templates/user/ssh/keys/new.html')
}

@['/:username/:repo_name/settings/deploy-keys']
pub fn (mut app App) repo_deploy_keys(mut ctx Context, username string, repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	deploy_keys := app.find_repo_deploy_keys(repo.id)
	protected_branches := app.find_protected_branches(repo.id)
	return $veb.html('templates/repo/deploy_keys.html')
}

@['/:username/:repo_name/settings/deploy-keys'; post]
pub fn (mut app App) handle_add_deploy_key(mut ctx Context, username string, repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	title := ctx.form['title'].trim_space()
	key := ctx.form['key'].trim_space()
	expires_value := ctx.form['expires_at'].trim_space()
	expires_at := parse_yyyy_mm_dd(expires_value)
	if !valid_short_name(title) || key.len > 16_384 || !is_valid_ssh_public_key(key)
		|| (expires_value != '' && expires_at <= 0) {
		ctx.error('The deploy key details are invalid')
		return app.repo_deploy_keys(mut ctx, username, repo_name)
	}
	app.add_deploy_key(repo.id, ctx.user.id, title, key, ctx.form['can_push'] == 'on',
		expires_at) or {
		ctx.error(err.str())
		return app.repo_deploy_keys(mut ctx, username, repo_name)
	}
	return ctx.redirect('/${username}/${repo_name}/settings/deploy-keys')
}

@['/:username/:repo_name/settings/deploy-keys/:id/delete'; post]
pub fn (mut app App) handle_remove_deploy_key(mut ctx Context, username string, repo_name string, id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	key := app.find_deploy_key_by_id(id.int()) or { return ctx.not_found() }
	if key.repo_id != repo.id {
		return ctx.not_found()
	}
	app.remove_deploy_key(repo.id, key.id) or { ctx.error('Could not delete the deploy key') }
	return ctx.redirect('/${username}/${repo_name}/settings/deploy-keys')
}

@['/:username/:repo_name/settings/deploy-keys/:key_id/protected-branches/:rule_id/grant'; post]
pub fn (mut app App) handle_grant_deploy_key_protected_branch(mut ctx Context, username string,
	repo_name string, key_id string, rule_id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	app.grant_deploy_key_protected_branch(repo.id, key_id.int(), rule_id.int(), ctx.user.id) or {
		ctx.error(err.str())
		return app.repo_deploy_keys(mut ctx, username, repo_name)
	}
	return ctx.redirect('/${username}/${repo_name}/settings/deploy-keys')
}

@['/:username/:repo_name/settings/deploy-keys/:key_id/protected-branches/:rule_id/revoke'; post]
pub fn (mut app App) handle_revoke_deploy_key_protected_branch(mut ctx Context, username string,
	repo_name string, key_id string, rule_id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_admin_repo(ctx, repo) {
		return ctx.not_found()
	}
	app.revoke_deploy_key_protected_branch(repo.id, key_id.int(), rule_id.int()) or {
		ctx.error('Could not revoke the protected branch grant')
		return app.repo_deploy_keys(mut ctx, username, repo_name)
	}
	return ctx.redirect('/${username}/${repo_name}/settings/deploy-keys')
}
