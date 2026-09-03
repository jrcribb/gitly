// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import crypto.sha256
import veb
import time

struct ContainerBlobResponse {
	digest string
	size   i64
}

fn container_upload_location(repo Repo, uuid string) string {
	return '/v2/${repo.user_name}/${repo.name}/blobs/uploads/${uuid}'
}

fn set_container_upload_headers(mut ctx Context, repo Repo, upload ContainerUpload) {
	ctx.set_custom_header('Location', container_upload_location(repo, upload.uuid)) or {}
	ctx.set_custom_header('Docker-Upload-UUID', upload.uuid) or {}
	last := if upload.size > 0 { upload.size - 1 } else { 0 }
	ctx.set_custom_header('Range', '0-${last}') or {}
}

fn (mut app App) platform_dashboard(mut ctx Context, username string, repo_name string,
	created_secret string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !app.can_read_repo(ctx, repo) {
		return ctx.not_found()
	}
	packages := app.list_repo_packages(repo.id)
	manifests := app.list_container_manifests(repo.id)
	scans := app.list_security_scans(repo.id)
	findings := app.list_security_findings(repo.id)
	security_policies := app.list_security_policies(repo.id)
	approval_policies := app.list_merge_approval_policies(repo.id)
	flags := app.list_feature_flags(repo.id)
	incidents := app.list_incidents(repo.id)
	agents := app.list_cluster_agents(repo.id)
	alert_integrations := app.list_alert_integrations(repo.id)
	schedules := app.list_on_call_schedules(repo.id)
	can_develop := ctx.logged_in
		&& app.repo_access_level(ctx.user.id, repo) >= project_access_developer
	can_maintain := ctx.logged_in
		&& app.repo_access_level(ctx.user.id, repo) >= project_access_maintainer
	return $veb.html('templates/repo/platform.html')
}

@['/:username/:repo_name/platform']
pub fn (mut app App) repo_platform(mut ctx Context, username string, repo_name string) veb.Result {
	return app.platform_dashboard(mut ctx, username, repo_name, '')
}

@['/:username/:repo_name/platform/packages'; post]
pub fn (mut app App) handle_publish_package(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_developer {
		return ctx.not_found()
	}
	app.publish_package(repo, ctx.user.id, ctx.form['package_type'], ctx.form['name'], ctx.form['version'], ctx.form['file_name'], ctx.form['content'].bytes(), ctx.form['provenance_statement'], ctx.form['provenance_signature'], ctx.form['provenance_key_id']) or { ctx.error(err.msg()) }
	return app.platform_dashboard(mut ctx, username, repo_name, '')
}

@['/:username/:repo_name/platform/package-retention'; post]
pub fn (mut app App) handle_package_retention(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_maintainer {
		return ctx.not_found()
	}
	app.set_package_retention(repo.id, 'enabled' in ctx.form, ctx.form['keep_latest'].int(), ctx.form['max_age_days'].int(), 'include_yanked' in ctx.form) or { ctx.error(err.msg()) }
	app.enqueue_platform_job('default', 'package_retention', repo.id.str(), 0, int(time.now().unix()), 3) or {}
	return app.platform_dashboard(mut ctx, username, repo_name, '')
}

@['/:username/:repo_name/platform/container-retention'; post]
pub fn (mut app App) handle_container_retention(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_maintainer {
		return ctx.not_found()
	}
	app.set_container_retention(repo, ctx.user.id, 'enabled' in ctx.form, ctx.form['keep_latest'].int(), ctx.form['max_age_days'].int(), 'delete_untagged' in ctx.form) or { ctx.error(err.msg()) }
	app.enqueue_platform_job('default', 'container_retention', repo.id.str(), 0, int(time.now().unix()), 3) or {}
	return app.platform_dashboard(mut ctx, username, repo_name, '')
}

@['/:username/:repo_name/platform/container-manifests/:id/protection'; post]
pub fn (mut app App) handle_container_manifest_protection(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_maintainer {
		return ctx.not_found()
	}
	app.set_container_manifest_protected(repo, ctx.user.id, id.int(), ctx.form['protected'] != 'false') or { ctx.error(err.msg()) }
	return app.platform_dashboard(mut ctx, username, repo_name, '')
}

@['/:username/:repo_name/platform/container-manifests/:id/delete'; post]
pub fn (mut app App) handle_delete_container_manifest(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !ctx.logged_in || app.repo_access_level(ctx.user.id, repo) < project_access_maintainer {
		return ctx.not_found()
	}
	app.delete_container_manifest(repo, ctx.user.id, id.int()) or { ctx.error(err.msg()) }
	return app.platform_dashboard(mut ctx, username, repo_name, '')
}

@['/api/v1/repos/:username/:repo_name/packages']
pub fn (mut app App) api_v1_packages(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.list_repo_packages(repo.id))
}

@['/api/v1/repos/:username/:repo_name/packages/:package_type/:name/:version/:file_name'; put]
pub fn (mut app App) api_v1_publish_package(mut ctx Context, username string, repo_name string,
	package_type string, name string, version string, file_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	artifact := app.publish_package(repo, user.id, package_type, name, version, file_name, ctx.req.data.bytes(), ctx.req.header.get_custom('X-Gitly-Provenance') or { '' }, ctx.req.header.get_custom('X-Gitly-Provenance-Signature') or { '' }, ctx.req.header.get_custom('X-Gitly-Provenance-Key-Id') or { '' }) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	app.record_audit_event('project', repo.id, user.id, 'package.publish', 'package', artifact.id.str(), '${artifact.package_type}/${artifact.name}@${artifact.version}', ctx.ip())
	return ctx.json(artifact)
}

@['/api/v1/repos/:username/:repo_name/packages/:id/download']
pub fn (mut app App) api_v1_download_package(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	artifact, data := app.download_package(repo.id, id.int()) or {
		return ctx.api_not_found()
	}
	ctx.set_content_type('application/octet-stream')
	ctx.set_header(.content_disposition, 'attachment; filename="${artifact.file_name}"')
	ctx.set_header(.content_length, data.len.str())
	return ctx.ok(data.bytestr())
}

@['/api/v1/repos/:username/:repo_name/packages/:id/yank'; post]
pub fn (mut app App) api_v1_yank_package(mut ctx Context, username string, repo_name string,
	id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	app.find_package(repo.id, id.int()) or { return ctx.api_not_found() }
	app.yank_package(repo.id, id.int(), ctx.form['yanked'] != 'false') or {
		return ctx.api_error_response(500, 'Internal Server Error', err.msg())
	}
	app.record_audit_event('project', repo.id, user.id, 'package.yank', 'package', id, '', ctx.ip())
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/package-retention'; post]
pub fn (mut app App) api_v1_package_retention(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	if app.repo_access_level(user.id, repo) < project_access_maintainer {
		return ctx.api_error_response(403, 'Forbidden', 'Maintainer access is required')
	}
	app.set_package_retention(repo.id, ctx.form['enabled'] != 'false', ctx.form['keep_latest'].int(), ctx.form['max_age_days'].int(), ctx.form['include_yanked'] == 'true') or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	job_id := app.enqueue_platform_job('default', 'package_retention', repo.id.str(), 0, int(time.now().unix()), 3) or { 0 }
	return ctx.json({
		'job_id': job_id
	})
}

@['/api/v1/repos/:username/:repo_name/container/blobs/:digest'; put]
pub fn (mut app App) api_v1_upload_container_blob(mut ctx Context, username string,
	repo_name string, digest string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	data := ctx.req.data.bytes()
	expected := sha256.sum(data).hex()
	if digest != 'sha256:${expected}' && digest != expected {
		return ctx.api_error_response(422, 'Unprocessable Entity', 'container digest mismatch')
	}
	blob := app.upload_container_blob(repo, user.id, data) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(ContainerBlobResponse{
		digest: 'sha256:${blob.oid}'
		size: blob.size
	})
}

@['/api/v1/repos/:username/:repo_name/container/manifests/:reference'; put]
pub fn (mut app App) api_v1_publish_container_manifest(mut ctx Context, username string,
	repo_name string, reference string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	media_type := ctx.get_header(.content_type) or { 'application/vnd.oci.image.manifest.v1+json' }
	manifest := app.publish_container_manifest(repo, user.id, ctx.query['image'] or { repo.name }, reference, media_type, ctx.req.data.bytes()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.json(manifest)
}

@['/api/v1/repos/:username/:repo_name/container/manifests']
pub fn (mut app App) api_v1_container_manifests(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	caller := app.api_user_from_ctx(ctx) or { User{} }
	if !app.user_has_repo_read_access(caller.id, repo) {
		return ctx.api_not_found()
	}
	return ctx.json(app.list_container_manifests(repo.id))
}

@['/v2/']
pub fn (mut app App) oci_registry_ping(mut ctx Context) veb.Result {
	ctx.set_custom_header('Docker-Distribution-Api-Version', 'registry/2.0') or {}
	return ctx.ok('')
}

@['/v2/:username/:repo_name/blobs/uploads/'; post]
pub fn (mut app App) oci_start_blob_upload(mut ctx Context, username string,
	repo_name string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	identity := app.check_git_http_access(mut ctx, repo, true) or { return veb.no_result() }
	upload := app.start_container_upload(repo, identity.user_id, identity.access_level) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	set_container_upload_headers(mut ctx, repo, upload)
	ctx.res.status_code = 202
	return ctx.ok('')
}

@['/v2/:username/:repo_name/blobs/uploads/:uuid'; 'patch']
pub fn (mut app App) oci_append_blob_upload(mut ctx Context, username string, repo_name string,
	uuid string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	identity := app.check_git_http_access(mut ctx, repo, true) or { return veb.no_result() }
	upload := app.append_container_upload(repo, uuid, identity.access_level, ctx.req.data.bytes()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	set_container_upload_headers(mut ctx, repo, upload)
	ctx.res.status_code = 202
	return ctx.ok('')
}

@['/v2/:username/:repo_name/blobs/uploads/:uuid'; put]
pub fn (mut app App) oci_finish_blob_upload(mut ctx Context, username string, repo_name string,
	uuid string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	identity := app.check_git_http_access(mut ctx, repo, true) or { return veb.no_result() }
	digest := ctx.query['digest'] or { '' }
	blob := app.finish_container_upload(repo, uuid, identity.user_id, identity.access_level, digest, ctx.req.data.bytes()) or { return ctx.api_error_response(400, 'Bad Request', err.msg()) }
	ctx.set_custom_header('Location', '/v2/${repo.user_name}/${repo.name}/blobs/sha256:${blob.oid}') or {}
	ctx.set_custom_header('Docker-Content-Digest', 'sha256:${blob.oid}') or {}
	ctx.res.status_code = 201
	return ctx.ok('')
}

@['/v2/:username/:repo_name/blobs/uploads/:uuid'; 'delete']
pub fn (mut app App) oci_cancel_blob_upload(mut ctx Context, username string, repo_name string,
	uuid string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	app.check_git_http_access(mut ctx, repo, true) or { return veb.no_result() }
	app.cancel_container_upload(repo.id, uuid) or { return ctx.not_found() }
	ctx.res.status_code = 204
	return ctx.ok('')
}

@['/v2/:username/:repo_name/blobs/:digest'; 'head']
pub fn (mut app App) oci_head_blob(mut ctx Context, username string, repo_name string,
	digest string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !repo.is_public {
		app.check_git_http_access(mut ctx, repo, false) or { return veb.no_result() }
	}
	clean := if digest.starts_with('sha256:') { digest[7..] } else { digest }
	if !app.repo_has_container_blob(repo.id, digest) {
		return ctx.not_found()
	}
	blob := app.find_platform_blob_by_oid(clean) or { return ctx.not_found() }
	ctx.set_content_type('application/octet-stream')
	ctx.set_header(.content_length, blob.size.str())
	ctx.set_custom_header('Docker-Content-Digest', 'sha256:${blob.oid}') or {}
	return ctx.ok('')
}

@['/v2/:username/:repo_name/blobs/:digest']
pub fn (mut app App) oci_get_blob(mut ctx Context, username string, repo_name string,
	digest string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !repo.is_public {
		app.check_git_http_access(mut ctx, repo, false) or { return veb.no_result() }
	}
	clean := if digest.starts_with('sha256:') { digest[7..] } else { digest }
	if !app.repo_has_container_blob(repo.id, digest) {
		return ctx.not_found()
	}
	blob := app.find_platform_blob_by_oid(clean) or { return ctx.not_found() }
	data := app.load_platform_blob(blob.id) or { return ctx.not_found() }
	ctx.set_content_type('application/octet-stream')
	ctx.set_header(.content_length, data.len.str())
	ctx.set_custom_header('Docker-Content-Digest', 'sha256:${blob.oid}') or {}
	return ctx.ok(data.bytestr())
}

@['/v2/:username/:repo_name/blobs/:digest'; put]
pub fn (mut app App) oci_put_blob(mut ctx Context, username string, repo_name string,
	digest string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	identity := app.check_git_http_access(mut ctx, repo, true) or { return veb.no_result() }
	data := ctx.req.data.bytes()
	expected := sha256.sum(data).hex()
	if digest != 'sha256:${expected}' && digest != expected {
		return ctx.api_error_response(422, 'Unprocessable Entity', 'container digest mismatch')
	}
	blob := app.upload_container_blob_with_access(repo, identity.user_id, identity.access_level, data) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	ctx.res.status_code = 201
	ctx.set_custom_header('Docker-Content-Digest', 'sha256:${blob.oid}') or {}
	return ctx.ok('')
}

@['/api/v1/repos/:username/:repo_name/container/manifests/:id/protection'; post]
pub fn (mut app App) api_v1_protect_container_manifest(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	app.set_container_manifest_protected(repo, user.id, id.int(), ctx.form['protected'] != 'false') or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/container/manifests/:id/delete'; post]
pub fn (mut app App) api_v1_delete_container_manifest(mut ctx Context, username string,
	repo_name string, id string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	app.delete_container_manifest(repo, user.id, id.int()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	app.record_audit_event('project', repo.id, user.id, 'container.manifest.delete', 'manifest', id, '', ctx.ip())
	return ctx.api_success_response()
}

@['/api/v1/repos/:username/:repo_name/container-retention'; post]
pub fn (mut app App) api_v1_container_retention(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	app.set_container_retention(repo, user.id, ctx.form['enabled'] != 'false', ctx.form['keep_latest'].int(), ctx.form['max_age_days'].int(), ctx.form['delete_untagged'] == 'true') or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	job_id := app.enqueue_platform_job('default', 'container_retention', repo.id.str(), 0, int(time.now().unix()), 3) or { 0 }
	return ctx.json({
		'job_id': job_id
	})
}

@['/v2/:username/:repo_name/manifests/:reference']
pub fn (mut app App) oci_get_manifest(mut ctx Context, username string, repo_name string,
	reference string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !repo.is_public {
		app.check_git_http_access(mut ctx, repo, false) or { return veb.no_result() }
	}
	manifest, data := app.pull_container_manifest(repo.id, repo.name, reference) or {
		return ctx.not_found()
	}
	ctx.set_content_type(manifest.media_type)
	ctx.set_custom_header('Docker-Content-Digest', manifest.digest) or {}
	return ctx.ok(data.bytestr())
}

@['/v2/:username/:repo_name/manifests/:reference'; 'head']
pub fn (mut app App) oci_head_manifest(mut ctx Context, username string, repo_name string,
	reference string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	if !repo.is_public {
		app.check_git_http_access(mut ctx, repo, false) or { return veb.no_result() }
	}
	manifest := app.find_container_manifest(repo.id, repo.name, reference) or {
		return ctx.not_found()
	}
	ctx.set_content_type(manifest.media_type)
	ctx.set_custom_header('Docker-Content-Digest', manifest.digest) or {}
	blob := app.find_platform_blob_by_oid(manifest.digest.trim_string_left('sha256:')) or {
		return ctx.not_found()
	}
	ctx.set_header(.content_length, blob.size.str())
	return ctx.ok('')
}

@['/v2/:username/:repo_name/manifests/:reference'; put]
pub fn (mut app App) oci_put_manifest(mut ctx Context, username string, repo_name string,
	reference string) veb.Result {
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.not_found() }
	identity := app.check_git_http_access(mut ctx, repo, true) or { return veb.no_result() }
	media_type := ctx.get_header(.content_type) or { 'application/vnd.oci.image.manifest.v1+json' }
	manifest := app.publish_container_manifest_with_access(repo, identity.user_id, identity.access_level, repo.name, reference, media_type, ctx.req.data.bytes()) or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	ctx.res.status_code = 201
	ctx.set_custom_header('Docker-Content-Digest', manifest.digest) or {}
	return ctx.ok('')
}

@['/api/v1/repos/:username/:repo_name/dependency-proxy'; post]
pub fn (mut app App) api_v1_dependency_proxy(mut ctx Context, username string,
	repo_name string) veb.Result {
	user := app.api_user_from_ctx(ctx) or { return ctx.api_unauthorized() }
	repo := app.find_repo_by_name_and_username(repo_name, username) or { return ctx.api_not_found() }
	entry, data := app.fetch_dependency_proxy(repo, user.id, ctx.form['url'], ctx.form['force'] == 'true') or {
		return ctx.api_error_response(400, 'Bad Request', err.msg())
	}
	ctx.set_content_type(entry.content_type)
	ctx.set_header(.content_length, data.len.str())
	return ctx.ok(data.bytestr())
}
