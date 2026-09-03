// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import x.json2 as json
import os
import veb

struct LfsBatchRequest {
	operation string
	transfers []string
	objects   []LfsBatchObject
}

struct LfsBatchObject {
	oid  string
	size i64
}

struct LfsAction {
	href   string
	header map[string]string @[omitempty]
}

struct LfsObjectError {
	code    int
	message string
}

struct LfsBatchObjectResponse {
	oid     string
	size    i64
	actions map[string]LfsAction @[omitempty]
	error   LfsObjectError @[omitempty]
}

struct LfsBatchResponse {
	transfer string
	objects  []LfsBatchObjectResponse
}

fn (mut app App) lfs_authenticate(mut ctx Context, repo Repo, required_scope string) bool {
	username, credential := ctx.extract_user_credentials() or {
		ctx.set_authenticate_headers()
		ctx.send_unauthorized()
		return false
	}
	if credential.starts_with('gldt_') {
		if _ := app.authenticate_deploy_token(repo.id, username, credential, required_scope, ctx.ip()) {
			return true
		}
		ctx.send_unauthorized()
		return false
	}
	require_write := required_scope == deploy_token_scope_write_lfs
	user := app.user_from_basic_credentials(ctx, require_write) or {
		ctx.send_unauthorized()
		return false
	}
	allowed := if require_write {
		app.user_can_write_repo(user.id, repo)
	} else {
		app.user_has_repo_read_access(user.id, repo)
	}
	if !allowed {
		ctx.send_not_found()
	}
	return allowed
}

fn (mut app App) lfs_object_href(repo Repo, oid string, size i64) string {
	return '${app.generate_clone_url(repo)}/info/lfs/objects/${oid}?size=${size}'
}

@['/:username/:repo_name/info/lfs/objects/batch'; post]
pub fn (mut app App) lfs_batch(mut ctx Context, username string, repo_name string) veb.Result {
	clean_repo_name := if repo_name.ends_with('.git') {
		repo_name[..repo_name.len - 4]
	} else {
		repo_name
	}
	repo := app.find_repo_by_name_and_username(clean_repo_name, username) or { return ctx.not_found() }
	request := json.decode[LfsBatchRequest](ctx.req.data) or {
		return ctx.api_error_response(400, 'Bad Request', 'invalid Git LFS batch request')
	}
	if request.operation !in ['download', 'upload'] || request.objects.len > 1000 {
		return ctx.api_error_response(400, 'Bad Request', 'invalid Git LFS operation')
	}
	if request.operation == 'upload' {
		if !app.lfs_authenticate(mut ctx, repo, deploy_token_scope_write_lfs) {
			return veb.no_result()
		}
	} else if !repo.is_public && !app.lfs_authenticate(mut ctx, repo, deploy_token_scope_read_lfs) {
		return veb.no_result()
	}
	mut objects := []LfsBatchObjectResponse{cap: request.objects.len}
	for object in request.objects {
		if !valid_lfs_oid(object.oid) || object.size < 0 || object.size > max_lfs_object_size {
			objects << LfsBatchObjectResponse{
				oid: object.oid
				size: object.size
				error: LfsObjectError{
					code: 422
					message: 'invalid object id or size'
				}
			}
			continue
		}
		exists := app.repo_has_lfs_object(repo.id, object.oid)
		if request.operation == 'download' && !exists {
			objects << LfsBatchObjectResponse{
				oid: object.oid
				size: object.size
				error: LfsObjectError{
					code: 404
					message: 'LFS object not found'
				}
			}
			continue
		}
		mut actions := map[string]LfsAction{}
		if (request.operation == 'download' && exists) || (request.operation == 'upload' && !exists) {
			actions[request.operation] = LfsAction{
				href: app.lfs_object_href(repo, object.oid, object.size)
				header: {
					'Accept': 'application/vnd.git-lfs'
				}
			}
		}
		objects << LfsBatchObjectResponse{
			oid: object.oid
			size: object.size
			actions: actions
		}
	}
	ctx.set_content_type('application/vnd.git-lfs+json')
	return ctx.ok(json.encode(LfsBatchResponse{
		transfer: 'basic'
		objects: objects
	}))
}

@['/:username/:repo_name/info/lfs/objects/:oid'; put]
pub fn (mut app App) lfs_upload_object(mut ctx Context, username string, repo_name string,
	oid string) veb.Result {
	clean_repo_name := if repo_name.ends_with('.git') {
		repo_name[..repo_name.len - 4]
	} else {
		repo_name
	}
	repo := app.find_repo_by_name_and_username(clean_repo_name, username) or { return ctx.not_found() }
	if !app.lfs_authenticate(mut ctx, repo, deploy_token_scope_write_lfs) {
		return veb.no_result()
	}
	expected_size := (ctx.query['size'] or { '-1' }).i64()
	app.store_lfs_object(repo.id, oid, expected_size, ctx.req.data.bytes()) or {
		return ctx.api_error_response(422, 'Unprocessable Entity', err.msg())
	}
	ctx.res.status_code = 200
	ctx.res.status_msg = 'OK'
	return ctx.ok('')
}

@['/:username/:repo_name/info/lfs/objects/:oid']
pub fn (mut app App) lfs_download_object(mut ctx Context, username string, repo_name string,
	oid string) veb.Result {
	clean_repo_name := if repo_name.ends_with('.git') {
		repo_name[..repo_name.len - 4]
	} else {
		repo_name
	}
	repo := app.find_repo_by_name_and_username(clean_repo_name, username) or { return ctx.not_found() }
	if !repo.is_public && !app.lfs_authenticate(mut ctx, repo, deploy_token_scope_read_lfs) {
		return veb.no_result()
	}
	if !app.repo_has_lfs_object(repo.id, oid) {
		return ctx.not_found()
	}
	data := os.read_bytes(app.lfs_object_path(oid)) or { return ctx.not_found() }
	ctx.set_content_type('application/octet-stream')
	ctx.set_header(.content_length, data.len.str())
	return ctx.ok(data.bytestr())
}
