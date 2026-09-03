// Copyright (c) 2019-2021 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import veb
import git
import compress.deflate
import net.http
import os
import time

const max_git_http_body_len = 110 * 1024 * 1024

struct GitHttpIdentity {
	user_id         int
	access_level    int
	is_deploy_token bool
}

struct GitBodyCollector {
	limit int
mut:
	data     []u8
	exceeded bool
}

fn collect_git_body_chunk(chunk []u8, mut collector GitBodyCollector) int {
	if chunk.len > collector.limit - collector.data.len {
		collector.exceeded = true
		return 0
	}
	collector.data << chunk
	return chunk.len
}

fn decompress_git_body(body string, limit int) !string {
	mut collector := &GitBodyCollector{
		limit: limit
		data: []u8{cap: if body.len < limit { body.len } else { limit }}
	}
	deflate.decompress_with_callback(body.bytes(), collect_git_body_chunk, collector)!
	if collector.exceeded {
		return error('decompressed Git request body is too large')
	}
	return collector.data.bytestr()
}

@['/:username/:repo_name/info/refs']
fn (mut app App) handle_git_info(username string, git_repo_name string) veb.Result {
	repo_name := git.remove_git_extension_if_exists(git_repo_name)
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	app.ensure_partial_clone_config(repo) or { return ctx.server_error('Could not configure repository transport') }
	service := extract_service_from_url(ctx.req.url)

	if service == .unknown {
		return ctx.not_found()
	}

	is_receive_service := service == .receive
	is_private_repo := !repo.is_public

	if is_receive_service || is_private_repo {
		app.check_git_http_access(mut ctx, repo, is_receive_service) or { return veb.no_result() }
	}

	refs := repo.git_advertise(service.str())
	git_response := build_git_service_response(service, refs)

	ctx.set_content_type('application/x-git-${service}-advertisement')
	ctx.set_no_cache_headers()

	return ctx.ok(git_response)
}

@['/:user/:repo_name/git-upload-pack'; post]
fn (mut app App) handle_git_upload_pack(username string, git_repo_name string) veb.Result {
	body := ctx.parse_body() or {
		ctx.send_custom_error(413, 'Git request body is invalid or too large')
		return veb.no_result()
	}
	repo_name := git.remove_git_extension_if_exists(git_repo_name)
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	app.ensure_partial_clone_config(repo) or { return ctx.server_error('Could not configure repository transport') }
	is_private_repo := !repo.is_public

	if is_private_repo {
		app.check_git_http_access(mut ctx, repo, false) or { return veb.no_result() }
	}

	git_response := repo.git_smart('upload-pack', body)

	ctx.set_git_content_type_headers(.upload)

	return ctx.ok(git_response)
}

@['/:user/:repo_name/git-receive-pack'; post]
fn (mut app App) handle_git_receive_pack(username string, git_repo_name string) veb.Result {
	body := ctx.parse_body() or {
		ctx.send_custom_error(413, 'Git request body is invalid or too large')
		return veb.no_result()
	}
	repo_name := git.remove_git_extension_if_exists(git_repo_name)
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }

	identity := app.check_git_http_access(mut ctx, repo, true) or { return veb.no_result() }
	updates := git.parse_receive_updates(body) or {
		ctx.send_custom_error(400, 'Invalid Git receive request')
		return veb.no_result()
	}
	for update in updates {
		if tag_name := update.tag_name() {
			if update.is_delete() && app.tag_is_protected(repo.id, tag_name) {
				ctx.send_custom_error(403, 'Protected tags cannot be deleted')
				return veb.no_result()
			}
			if !update.is_delete() && !app.access_level_can_create_tag(identity.access_level, repo.id, tag_name) {
				ctx.send_custom_error(403, 'You are not allowed to create this tag')
				return veb.no_result()
			}
			continue
		}
		branch_name := update.branch_name() or { continue }
		if !is_safe_ref(branch_name) {
			ctx.send_custom_error(400, 'Invalid branch name')
			return veb.no_result()
		}
		if app.branch_is_protected(repo.id, branch_name) && update.is_delete() {
			ctx.send_custom_error(403, 'Protected branches cannot be deleted')
			return veb.no_result()
		}
		if !app.access_level_can_push_branch(identity.access_level, repo.id, branch_name) {
			ctx.send_custom_error(403, 'You are not allowed to push to this branch')
			return veb.no_result()
		}
	}
	app.ensure_protected_branch_hook(repo) or {
		return ctx.server_error('Could not configure protected branch enforcement')
	}

	git_response := repo.git_smart_with_env('receive-pack', body, {
		'GITLY_PROTECTED_BRANCH_RULES': app.protected_branch_rules_env(repo.id)
		'GITLY_PROTECTED_TAG_RULES':    app.protected_tag_rules_env(repo.id)
		'GITLY_USER_ACCESS_LEVEL':      identity.access_level.str()
		'GITLY_REQUIRE_SIGNED_COMMITS': if repo.require_signed_commits { '1' } else { '0' }
		'GITLY_SSH_ALLOWED_SIGNERS':    os.join_path(repo.git_dir, '.gitly-hooks', 'allowed_signers')
		'GITLY_RUN_POST_RECEIVE':       '0'
	})

	push_accepted := git.receive_updates_accepted(git_response)
	if push_accepted {
		app.update_repo_after_ref_changes(repo.id, updates) or {
			return ctx.server_error('There was an error while updating the repo')
		}

		// Language analysis reads every file in the repo and is slow; run it in
		// a background thread with its own DB connection so the git client is
		// not blocked.

		// Trigger CI if .gitly-ci.yml exists in the repo
		spawn bg_recompute_lang_stats(repo.id, app.config)
		spawn run_push_mirrors(repo.id, app.config)
		for update in updates {
			branch_name := update.branch_name() or { continue }
			if !update.is_delete() {
				spawn run_ci_trigger_if_configured(repo.id, branch_name, app.config)
			}
		}
	}

	ctx.set_git_content_type_headers(.receive)

	return ctx.ok(git_response)
}

fn (mut app App) check_git_http_access(mut ctx Context, repo Repo, require_write bool) ?GitHttpIdentity {
	has_valid_auth_header := ctx.check_basic_authorization_header()

	if !has_valid_auth_header {
		ctx.set_authenticate_headers()
		ctx.send_unauthorized()
		return none
	}

	username, credential := ctx.extract_user_credentials() or {
		ctx.send_unauthorized()
		return none
	}
	if credential.starts_with('gldt_') {
		required_scope := if require_write {
			deploy_token_scope_write_repository
		} else {
			deploy_token_scope_read_repository
		}
		token := app.authenticate_deploy_token(repo.id, username, credential, required_scope, ctx.ip()) or {
			ctx.send_unauthorized()
			return none
		}
		return GitHttpIdentity{
			access_level: if token.allows_scope(deploy_token_scope_write_repository, int(time.now().unix())) {
				project_access_developer
			} else {
				project_access_reporter
			}
			is_deploy_token: true
		}
	}
	user := app.user_from_basic_credentials(ctx, require_write) or {
		ctx.send_unauthorized()
		return none
	}

	allowed := if require_write {
		app.user_can_write_repo(user.id, repo)
	} else {
		app.user_has_repo_read_access(user.id, repo)
	}
	if allowed {
		return GitHttpIdentity{
			user_id: user.id
			access_level: app.repo_access_level(user.id, repo)
		}
	}
	ctx.send_not_found()
	return none
}

fn (ctx &Context) check_basic_authorization_header() bool {
	auth_header := ctx.get_header(.authorization) or { return false }
	auth_header_parts := auth_header.fields()
	if auth_header_parts.len != 2 {
		return false
	}
	is_basic_auth_type := auth_header_parts[0].to_lower() == 'basic'
	return is_basic_auth_type
}

fn (ctx &Context) extract_user_credentials() ?(string, string) {
	auth_header := ctx.get_header(.authorization) or { return none }
	auth_header_parts := auth_header.fields()

	if auth_header_parts.len < 2 {
		return none
	}

	return decode_basic_auth(auth_header_parts[1])
}

fn (mut app App) user_from_basic_credentials(ctx &Context, require_write bool) ?User {
	username, credential := ctx.extract_user_credentials() or { return none }
	if username.len == 0 || username.len > max_username_len || credential.len == 0
		|| credential.len > max_password_len {
		return none
	}
	user := app.get_user_by_username(username) or { return none }
	if !user.is_registered || user.is_blocked {
		return none
	}

	if !app.git_http_credential_is_valid(user, credential, require_write) {
		return none
	}
	return user
}

// Git clients cannot complete the browser TOTP challenge. A personal access
// token is therefore required when 2FA is enabled. Tokens are also accepted
// for accounts without 2FA, while their existing account passwords continue
// to work.
fn (mut app App) git_http_credential_is_valid(user User, credential string, require_write bool) bool {
	required_scope := if require_write {
		api_token_scope_write_repository
	} else {
		api_token_scope_read_repository
	}
	if credential.starts_with('glt_') {
		return app.api_token_authenticates_user(credential, user.id, required_scope)
	}
	if app.user_has_two_factor(user.id) {
		return false
	}
	return compare_password_with_hash(credential, user.salt, user.password)
}

fn (mut app Context) set_no_cache_headers() {
	app.set_header(.expires, 'Fri, 01 Jan 1980 00:00:00 GMT')
	app.set_header(.pragma, 'no-cache')
	app.set_header(.cache_control, 'no-cache, max-age=0, must-revalidate')
}

fn (mut app Context) set_authenticate_headers() {
	app.set_header(.www_authenticate, 'Basic realm="."')
}

fn (mut app Context) set_git_content_type_headers(service GitService) {
	if service == .upload {
		app.set_content_type('application/x-git-upload-pack-result')
	} else if service == .receive {
		app.set_content_type('application/x-git-receive-pack-result')
	}
}

fn (mut app Context) send_internal_error(custom_message string) {
	message := if custom_message == '' { 'Internal Server error' } else { custom_message }

	app.send_custom_error(500, message)
}

fn (mut app Context) send_unauthorized() {
	app.send_custom_error(401, 'Unauthorized')
}

fn (mut app Context) send_not_found() {
	app.send_custom_error(404, 'Not Found')
}

fn (mut app Context) send_custom_error(code int, text string) {
	app.res.set_status(unsafe { http.Status(code) })
	app.send_response_to_client(veb.mime_types['.txt'], text)
}

fn (mut app Context) parse_body() !string {
	body := app.req.data
	if body.len > max_git_http_body_len {
		return error('Git request body is too large')
	}

	if h := app.get_header(.content_encoding) {
		if h.to_lower() == 'gzip' {
			return decompress_git_body(body, max_git_http_body_len)
		}
	}

	return body
}
