// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import crypto.sha256
import net.http
import net.urllib
import os
import rand
import time

const default_package_size_limit = i64(500) * 1024 * 1024
const package_types = ['generic', 'npm', 'maven', 'pypi', 'nuget', 'composer', 'helm']

struct PlatformBlob {
	id int @[primary; sql: serial]
mut:
	oid         string @[unique]
	size        i64
	storage_key string
	created_at  int
}

struct PackageArtifact {
	id int @[primary; sql: serial]
mut:
	repo_id              int @[unique: 'package_artifact']
	package_type         string @[unique: 'package_artifact']
	name                 string @[unique: 'package_artifact']
	version              string @[unique: 'package_artifact']
	file_name            string @[unique: 'package_artifact']
	blob_id              int
	created_by           int
	created_at           int
	downloads            int
	yanked               bool
	provenance_statement string
	provenance_signature string
	provenance_key_id    string
}

struct PackageRetentionPolicy {
	id int @[primary; sql: serial]
mut:
	repo_id        int @[unique]
	enabled        bool
	keep_latest    int
	max_age_days   int
	include_yanked bool
	updated_at     int
}

struct ContainerBlobLink {
	id int @[primary; sql: serial]
mut:
	repo_id    int @[unique: 'container_blob_link']
	blob_id    int @[unique: 'container_blob_link']
	created_at int
}

struct ContainerManifest {
	id int @[primary; sql: serial]
mut:
	repo_id    int @[unique: 'container_manifest']
	image_name string @[unique: 'container_manifest']
	reference  string @[unique: 'container_manifest']
	digest     string
	media_type string
	blob_id    int
	created_by int
	created_at int
	pulled_at  int
	pull_count int
	protected  bool
	is_deleted bool
}

struct ContainerRetentionPolicy {
	id int @[primary; sql: serial]
mut:
	repo_id         int @[unique]
	enabled         bool
	keep_latest     int
	max_age_days    int
	delete_untagged bool
	updated_at      int
}

struct ContainerUpload {
	id int @[primary; sql: serial]
mut:
	uuid        string @[unique]
	repo_id     int
	created_by  int
	storage_key string
	size        i64
	created_at  int
	expires_at  int
}

struct DependencyProxyEntry {
	id int @[primary; sql: serial]
mut:
	repo_id      int @[unique: 'dependency_proxy_entry']
	upstream_url string @[unique: 'dependency_proxy_entry']
	blob_id      int
	content_type string
	etag         string
	created_at   int
	expires_at   int
	last_hit_at  int
	hit_count    int
}

fn valid_registry_name(value string) bool {
	clean := value.trim_space()
	if clean == '' || clean.len > 255 || clean.starts_with('/') || clean.ends_with('/')
		|| clean.contains('..') || clean.contains_any('\\\r\n\t') {
		return false
	}
	for ch in clean.bytes() {
		if !ch.is_alnum() && ch !in [`-`, `_`, `.`, `/`, `@`, `+`, `:`] {
			return false
		}
	}
	return true
}

fn (app &App) object_store_local_root() string {
	if app.config.object_storage_path.trim_space() != '' {
		return app.config.object_storage_path
	}
	return os.join_path(app.config.repo_storage_path, '.gitly-objects')
}

fn safe_object_storage_key(key string) bool {
	return key != '' && key.len <= 512 && !key.starts_with('/') && !key.contains('..')
		&& !key.contains_any('\\\r\n')
}

fn (app &App) object_store_url(key string) string {
	return app.config.object_storage_url.trim_string_right('/') + '/' + key
}

fn (app &App) object_store_request(method http.Method, key string, data []u8) !http.Response {
	if !safe_object_storage_key(key) || app.config.object_storage_url.trim_space() == '' {
		return error('invalid external object storage request')
	}
	mut req := http.new_request(method, app.object_store_url(key), data.bytestr())
	req.read_timeout = 30 * time.second
	req.write_timeout = 30 * time.second
	req.allow_redirect = false
	req.max_retries = 1
	req.stop_receiving_limit = int(app.package_size_limit() + 1)
	if app.config.object_storage_token != '' {
		req.add_header(.authorization, 'Bearer ${app.config.object_storage_token}')
	}
	return req.do()
}

fn (app &App) object_store_put(key string, data []u8) ! {
	if !safe_object_storage_key(key) {
		return error('invalid object storage key')
	}
	if app.config.object_storage_url.trim_space() != '' {
		resp := app.object_store_request(.put, key, data)!
		if resp.status_code < 200 || resp.status_code >= 300 {
			return error('object storage returned ${resp.status_code}')
		}
		return
	}
	path := os.join_path(app.object_store_local_root(), key)
	os.mkdir_all(os.dir(path))!
	if os.exists(path) {
		return
	}
	temporary := '${path}.tmp-${os.getpid()}-${rand.ulid()}'
	os.write_file_array(temporary, data)!
	os.mv(temporary, path) or {
		os.rm(temporary) or {}
		if !os.exists(path) {
			return err
		}
	}
}

fn (app &App) object_store_replace(key string, data []u8) ! {
	if !safe_object_storage_key(key) {
		return error('invalid object storage key')
	}
	if app.config.object_storage_url.trim_space() != '' {
		resp := app.object_store_request(.put, key, data)!
		if resp.status_code < 200 || resp.status_code >= 300 {
			return error('object storage returned ${resp.status_code}')
		}
		return
	}
	path := os.join_path(app.object_store_local_root(), key)
	os.mkdir_all(os.dir(path))!
	temporary := '${path}.tmp-${os.getpid()}-${rand.ulid()}'
	os.write_file_array(temporary, data)!
	os.mv(temporary, path) or {
		os.rm(temporary) or {}
		return err
	}
}

fn (app &App) object_store_get(key string) ![]u8 {
	if !safe_object_storage_key(key) {
		return error('invalid object storage key')
	}
	if app.config.object_storage_url.trim_space() != '' {
		resp := app.object_store_request(.get, key, [])!
		if resp.status_code != 200 {
			return error('object not found')
		}
		return resp.body.bytes()
	}
	return os.read_bytes(os.join_path(app.object_store_local_root(), key))
}

fn (app &App) object_store_delete(key string) ! {
	if !safe_object_storage_key(key) {
		return error('invalid object storage key')
	}
	if app.config.object_storage_url.trim_space() != '' {
		resp := app.object_store_request(.delete, key, [])!
		if resp.status_code !in [200, 202, 204, 404] {
			return error('object storage returned ${resp.status_code}')
		}
		return
	}
	path := os.join_path(app.object_store_local_root(), key)
	if os.exists(path) {
		os.rm(path)!
	}
}

fn (app &App) package_size_limit() i64 {
	return if app.config.max_package_size_bytes > 0 {
		app.config.max_package_size_bytes
	} else {
		default_package_size_limit
	}
}

fn (app &App) find_platform_blob_by_oid(oid string) ?PlatformBlob {
	rows := sql app.db {
		select from PlatformBlob where oid == oid limit 1
	} or { []PlatformBlob{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (mut app App) store_platform_blob(namespace string, data []u8) !PlatformBlob {
	if !valid_registry_name(namespace) || i64(data.len) > app.package_size_limit() {
		return error('object exceeds the configured size limit')
	}
	oid := sha256.sum(data).hex()
	if existing := app.find_platform_blob_by_oid(oid) {
		return existing
	}
	key := '${namespace}/${oid[..2]}/${oid}'
	app.object_store_put(key, data)!
	id := db_insert_returning_id(mut app.db, 'PlatformBlob', ['oid', 'size', 'storage_key',
		'created_at'], [oid, data.len.str(), key, int(time.now().unix()).str()]) or {
		if existing := app.find_platform_blob_by_oid(oid) {
			return existing
		}
		return err
	}
	return PlatformBlob{
		id: id
		oid: oid
		size: data.len
		storage_key: key
		created_at: int(time.now().unix())
	}
}

fn (app &App) load_platform_blob(id int) ![]u8 {
	rows := sql app.db {
		select from PlatformBlob where id == id limit 1
	}!
	if rows.len != 1 {
		return error('stored object not found')
	}
	data := app.object_store_get(rows.first().storage_key)!
	if i64(data.len) != rows.first().size || sha256.sum(data).hex() != rows.first().oid {
		return error('stored object failed integrity verification')
	}
	return data
}

fn (mut app App) publish_package(repo Repo, actor_id int, package_type string, name string,
	version string, file_name string, data []u8, provenance_statement string,
	provenance_signature string, provenance_key_id string) !PackageArtifact {
	kind := package_type.trim_space().to_lower()
	if app.repo_access_level(actor_id, repo) < project_access_developer || kind !in package_types || !valid_registry_name(name) || !valid_registry_name(version)
		|| !safe_snippet_file_name(file_name) || data.len == 0 || provenance_statement.len > max_body_len
		|| provenance_signature.len > 4096 || provenance_key_id.len > 255 {
		return error('invalid package or Developer access is required')
	}
	app.ensure_namespace_storage_quota(repo.user_name, i64(data.len))!
	blob := app.store_platform_blob('packages', data)!
	id := db_insert_returning_id(mut app.db, 'PackageArtifact', ['repo_id', 'package_type', 'name',
		'version', 'file_name', 'blob_id', 'created_by', 'created_at', 'downloads', 'yanked',
		'provenance_statement', 'provenance_signature', 'provenance_key_id'], [
		repo.id.str(),
		kind,
		name.trim_space(),
		version.trim_space(),
		file_name.trim_space(),
		blob.id.str(),
		actor_id.str(),
		int(time.now().unix()).str(),
		'0',
		db_bool_value(false),
		provenance_statement,
		provenance_signature,
		provenance_key_id,
	])!
	return app.find_package(repo.id, id) or { return error('package was not saved') }
}

fn (app &App) find_package(repo_id int, id int) ?PackageArtifact {
	rows := sql app.db {
		select from PackageArtifact where repo_id == repo_id && id == id limit 1
	} or { []PackageArtifact{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) list_repo_packages(repo_id int) []PackageArtifact {
	return sql app.db {
		select from PackageArtifact where repo_id == repo_id order by id desc
	} or { []PackageArtifact{} }
}

fn (mut app App) download_package(repo_id int, id int) !(PackageArtifact, []u8) {
	artifact := app.find_package(repo_id, id) or { return error('package not found') }
	if artifact.yanked {
		return error('package has been yanked')
	}
	next := artifact.downloads + 1
	sql app.db {
		update PackageArtifact set downloads = next where id == id && repo_id == repo_id
	}!
	return artifact, app.load_platform_blob(artifact.blob_id)!
}

fn (mut app App) yank_package(repo_id int, id int, yanked bool) ! {
	sql app.db {
		update PackageArtifact set yanked = yanked where id == id && repo_id == repo_id
	}!
}

fn (mut app App) set_package_retention(repo_id int, enabled bool, keep_latest int,
	max_age_days int, include_yanked bool) ! {
	if repo_id <= 0 || keep_latest < 0 || keep_latest > 10000 || max_age_days < 0
		|| max_age_days > 36500 {
		return error('invalid package retention policy')
	}
	existing := sql app.db {
		select from PackageRetentionPolicy where repo_id == repo_id limit 1
	}!
	now := int(time.now().unix())
	if existing.len == 0 {
		row := PackageRetentionPolicy{
			repo_id: repo_id
			enabled: enabled
			keep_latest: keep_latest
			max_age_days: max_age_days
			include_yanked: include_yanked
			updated_at: now
		}
		sql app.db {
			insert row into PackageRetentionPolicy
		}!
	} else {
		sql app.db {
			update PackageRetentionPolicy set enabled = enabled, keep_latest = keep_latest,
			max_age_days = max_age_days, include_yanked = include_yanked, updated_at = now
			where repo_id == repo_id
		}!
	}
}

fn (mut app App) apply_package_retention(repo_id int) !int {
	policies := sql app.db {
		select from PackageRetentionPolicy where repo_id == repo_id && enabled == true limit 1
	}!
	if policies.len != 1 {
		return 0
	}
	policy := policies.first()
	artifacts := app.list_repo_packages(repo_id)
	cutoff := if policy.max_age_days > 0 {
		int(time.now().unix()) - policy.max_age_days * 86400
	} else {
		0
	}
	mut kept := map[string]int{}
	mut removed := 0
	for artifact in artifacts {
		key := '${artifact.package_type}/${artifact.name}'
		kept[key]++
		too_old := cutoff > 0 && artifact.created_at < cutoff
		over_latest := policy.keep_latest > 0 && kept[key] > policy.keep_latest
		if (too_old || over_latest || (policy.include_yanked && artifact.yanked))
			&& (policy.keep_latest == 0 || kept[key] > policy.keep_latest) {
			id := artifact.id
			sql app.db {
				delete from PackageArtifact where id == id && repo_id == repo_id
			}!
			removed++
		}
	}
	return removed
}

fn (mut app App) upload_container_blob(repo Repo, actor_id int, data []u8) !PlatformBlob {
	return app.upload_container_blob_with_access(repo, actor_id, app.repo_access_level(actor_id, repo), data)
}

fn (mut app App) upload_container_blob_with_access(repo Repo, _actor_id int, access_level int,
	data []u8) !PlatformBlob {
	if access_level < project_access_developer {
		return error('Developer access is required')
	}
	app.ensure_namespace_storage_quota(repo.user_name, i64(data.len))!
	blob := app.store_platform_blob('containers', data)!
	existing := sql app.db {
		select count from ContainerBlobLink where repo_id == repo.id && blob_id == blob.id
	}!
	if existing == 0 {
		link := ContainerBlobLink{
			repo_id: repo.id
			blob_id: blob.id
			created_at: int(time.now().unix())
		}
		sql app.db {
			insert link into ContainerBlobLink
		}!
	}
	return blob
}

fn (mut app App) start_container_upload(repo Repo, actor_id int, access_level int) !ContainerUpload {
	if access_level < project_access_developer {
		return error('Developer access is required')
	}
	now := int(time.now().unix())
	app.prune_expired_container_uploads(now)!
	uuid := rand.ulid()
	key := 'container-uploads/${repo.id}/${uuid}'
	app.object_store_replace(key, [])!
	id := db_insert_returning_id(mut app.db, 'ContainerUpload', ['uuid', 'repo_id', 'created_by',
		'storage_key', 'size', 'created_at', 'expires_at'], [uuid, repo.id.str(), actor_id.str(),
		key, '0', now.str(), (now + 86400).str()]) or {
		app.object_store_delete(key) or {}
		return err
	}
	upload := app.find_container_upload(repo.id, uuid) or {
		app.object_store_delete(key) or {}
		return error('container upload was not saved')
	}
	if upload.id != id {
		return error('container upload identity mismatch')
	}
	return upload
}

fn (app &App) find_container_upload(repo_id int, uuid string) ?ContainerUpload {
	rows := sql app.db {
		select from ContainerUpload where repo_id == repo_id && uuid == uuid limit 1
	} or { []ContainerUpload{} }
	if rows.len != 1 || rows.first().expires_at <= int(time.now().unix()) {
		return none
	}
	return rows.first()
}

fn (mut app App) append_container_upload(repo Repo, uuid string, access_level int,
	chunk []u8) !ContainerUpload {
	if access_level < project_access_developer {
		return error('Developer access is required')
	}
	upload := app.find_container_upload(repo.id, uuid) or { return error('container upload not found') }
	if upload.size + i64(chunk.len) > app.package_size_limit() {
		return error('container upload exceeds the configured size limit')
	}
	mut data := app.object_store_get(upload.storage_key)!
	data << chunk
	app.object_store_replace(upload.storage_key, data)!
	size := i64(data.len)
	id := upload.id
	sql app.db {
		update ContainerUpload set size = size where id == id
	}!
	return app.find_container_upload(repo.id, uuid) or { return error('container upload disappeared') }
}

fn (mut app App) finish_container_upload(repo Repo, uuid string, actor_id int, access_level int,
	digest string, final_chunk []u8) !PlatformBlob {
	if final_chunk.len > 0 {
		app.append_container_upload(repo, uuid, access_level, final_chunk)!
	}
	upload := app.find_container_upload(repo.id, uuid) or { return error('container upload not found') }
	data := app.object_store_get(upload.storage_key)!
	oid := sha256.sum(data).hex()
	if digest != oid && digest != 'sha256:${oid}' {
		return error('container digest mismatch')
	}
	blob := app.upload_container_blob_with_access(repo, actor_id, access_level, data)!
	app.cancel_container_upload(repo.id, uuid)!
	return blob
}

fn (mut app App) cancel_container_upload(repo_id int, uuid string) ! {
	upload := app.find_container_upload(repo_id, uuid) or { return error('container upload not found') }
	app.object_store_delete(upload.storage_key)!
	id := upload.id
	sql app.db {
		delete from ContainerUpload where id == id
	}!
}

fn (mut app App) prune_expired_container_uploads(now int) ! {
	uploads := sql app.db {
		select from ContainerUpload where expires_at <= now
	}!
	for upload in uploads {
		app.object_store_delete(upload.storage_key) or {}
		id := upload.id
		sql app.db {
			delete from ContainerUpload where id == id
		}!
	}
}

fn (app &App) repo_has_container_blob(repo_id int, digest string) bool {
	clean := if digest.starts_with('sha256:') { digest[7..] } else { digest }
	blob := app.find_platform_blob_by_oid(clean) or { return false }
	return sql app.db {
		select count from ContainerBlobLink where repo_id == repo_id && blob_id == blob.id
	} or { 0 } > 0
}

fn (mut app App) publish_container_manifest(repo Repo, actor_id int, image_name string,
	reference string, media_type string, payload []u8) !ContainerManifest {
	return app.publish_container_manifest_with_access(repo, actor_id, app.repo_access_level(actor_id, repo), image_name, reference, media_type, payload)
}

fn (mut app App) publish_container_manifest_with_access(repo Repo, actor_id int, access_level int,
	image_name string, reference string, media_type string, payload []u8) !ContainerManifest {
	if access_level < project_access_developer || !valid_registry_name(image_name)
		|| !valid_registry_name(reference)
		|| media_type.trim_space() == '' || media_type.len > 255 {
		return error('invalid container manifest or Developer access is required')
	}
	blob := app.upload_container_blob_with_access(repo, actor_id, access_level, payload)!
	digest := 'sha256:${blob.oid}'
	if reference.starts_with('sha256:') && reference != digest {
		return error('content-addressed manifest reference does not match its digest')
	}
	existing := sql app.db {
		select from ContainerManifest where repo_id == repo.id && image_name == image_name
		&& reference == reference limit 1
	}!
	if existing.len == 1 {
		if existing.first().protected && existing.first().digest != digest {
			return error('protected container manifest cannot be replaced')
		}
		id := existing.first().id
		now := int(time.now().unix())
		not_deleted := false
		sql app.db {
			update ContainerManifest set digest = digest, media_type = media_type,
			blob_id = blob.id, created_by = actor_id, created_at = now,
			is_deleted = not_deleted where id == id
		}!
		return app.find_container_manifest(repo.id, image_name, reference) or {
			return error('container manifest was not updated')
		}
	}
	db_insert_returning_id(mut app.db, 'ContainerManifest', ['repo_id', 'image_name', 'reference',
		'digest', 'media_type', 'blob_id', 'created_by', 'created_at', 'pulled_at', 'pull_count',
		'protected', 'is_deleted'], [repo.id.str(), image_name.trim_space(), reference.trim_space(),
		digest, media_type.trim_space(), blob.id.str(), actor_id.str(), int(time.now().unix()).str(),
		'0', '0', db_bool_value(false), db_bool_value(false)])!
	return app.find_container_manifest(repo.id, image_name, reference) or {
		return error('container manifest was not saved')
	}
}

fn (app &App) find_container_manifest(repo_id int, image_name string,
	reference string) ?ContainerManifest {
	rows := sql app.db {
		select from ContainerManifest where repo_id == repo_id && image_name == image_name
		&& reference == reference && is_deleted == false limit 1
	} or { []ContainerManifest{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) list_container_manifests(repo_id int) []ContainerManifest {
	return sql app.db {
		select from ContainerManifest where repo_id == repo_id && is_deleted == false order by id desc
	} or { []ContainerManifest{} }
}

fn (mut app App) pull_container_manifest(repo_id int, image_name string,
	reference string) !(ContainerManifest, []u8) {
	manifest := app.find_container_manifest(repo_id, image_name, reference) or {
		return error('container manifest not found')
	}
	now := int(time.now().unix())
	count := manifest.pull_count + 1
	sql app.db {
		update ContainerManifest set pulled_at = now, pull_count = count where id == manifest.id
	}!
	return manifest, app.load_platform_blob(manifest.blob_id)!
}

fn (mut app App) set_container_manifest_protected(repo Repo, actor_id int, manifest_id int,
	protected bool) ! {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer {
		return error('Maintainer access is required')
	}
	manifest := app.list_container_manifests(repo.id).filter(it.id == manifest_id)
	if manifest.len != 1 {
		return error('container manifest not found')
	}
	sql app.db {
		update ContainerManifest set protected = protected where id == manifest_id && repo_id == repo.id
	}!
}

fn (mut app App) delete_container_manifest(repo Repo, actor_id int, manifest_id int) ! {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer {
		return error('Maintainer access is required')
	}
	manifests := app.list_container_manifests(repo.id).filter(it.id == manifest_id)
	if manifests.len != 1 {
		return error('container manifest not found')
	}
	if manifests.first().protected {
		return error('protected container manifest cannot be deleted')
	}
	deleted := true
	sql app.db {
		update ContainerManifest set is_deleted = deleted where id == manifest_id && repo_id == repo.id
	}!
}

fn (mut app App) set_container_retention(repo Repo, actor_id int, enabled bool, keep_latest int,
	max_age_days int, delete_untagged bool) ! {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer || keep_latest < 0
		|| keep_latest > 10000 || max_age_days < 0 || max_age_days > 36500 {
		return error('invalid container retention policy or Maintainer access is required')
	}
	existing := sql app.db {
		select from ContainerRetentionPolicy where repo_id == repo.id limit 1
	}!
	now := int(time.now().unix())
	if existing.len == 0 {
		row := ContainerRetentionPolicy{
			repo_id: repo.id
			enabled: enabled
			keep_latest: keep_latest
			max_age_days: max_age_days
			delete_untagged: delete_untagged
			updated_at: now
		}
		sql app.db {
			insert row into ContainerRetentionPolicy
		}!
	} else {
		sql app.db {
			update ContainerRetentionPolicy set enabled = enabled, keep_latest = keep_latest,
			max_age_days = max_age_days, delete_untagged = delete_untagged, updated_at = now
			where repo_id == repo.id
		}!
	}
}

fn (mut app App) apply_container_retention(repo_id int) !int {
	policies := sql app.db {
		select from ContainerRetentionPolicy where repo_id == repo_id && enabled == true limit 1
	}!
	if policies.len != 1 {
		return 0
	}
	policy := policies.first()
	cutoff := if policy.max_age_days > 0 {
		int(time.now().unix()) - policy.max_age_days * 86400
	} else {
		0
	}
	mut seen := map[string]int{}
	mut removed := 0
	for manifest in app.list_container_manifests(repo_id) {
		seen[manifest.image_name]++
		if manifest.protected || (policy.keep_latest > 0 && seen[manifest.image_name] <= policy.keep_latest) {
			continue
		}
		is_untagged := manifest.reference.starts_with('sha256:')
		too_old := cutoff > 0 && manifest.created_at < cutoff
		over_latest := policy.keep_latest > 0 && seen[manifest.image_name] > policy.keep_latest
		if (policy.delete_untagged && is_untagged) || too_old || over_latest {
			deleted := true
			manifest_id := manifest.id
			sql app.db {
				update ContainerManifest set is_deleted = deleted where id == manifest_id
			}!
			removed++
		}
	}
	return removed
}

fn dependency_proxy_url_allowed(raw string, allowed_hosts []string) bool {
	if allowed_hosts.len == 0 || !is_safe_webhook_url(raw) {
		return false
	}
	u := urllib.parse(raw) or { return false }
	host := u.hostname().to_lower()
	return host in allowed_hosts || allowed_hosts.any(host.ends_with('.' + it))
}

fn (mut app App) fetch_dependency_proxy(repo Repo, actor_id int, raw_url string,
	force bool) !(DependencyProxyEntry, []u8) {
	if app.repo_access_level(actor_id, repo) < project_access_reporter
		|| !dependency_proxy_url_allowed(raw_url, app.config.dependency_proxy_allowed_hosts) {
		return error('dependency proxy destination is not allowed')
	}
	now := int(time.now().unix())
	existing := sql app.db {
		select from DependencyProxyEntry where repo_id == repo.id && upstream_url == raw_url limit 1
	}!
	if !force && existing.len == 1 && existing.first().expires_at > now {
		entry := existing.first()
		data := app.load_platform_blob(entry.blob_id)!
		hits := entry.hit_count + 1
		id := entry.id
		sql app.db {
			update DependencyProxyEntry set last_hit_at = now, hit_count = hits where id == id
		}!
		return entry, data
	}
	mut req := http.new_request(.get, raw_url, '')
	req.read_timeout = 20 * time.second
	req.write_timeout = 20 * time.second
	req.allow_redirect = false
	req.max_retries = 1
	req.stop_receiving_limit = int(app.package_size_limit() + 1)
	req.add_header(.user_agent, 'gitly-dependency-proxy')
	resp := req.do()!
	if resp.status_code != 200 || i64(resp.body.len) > app.package_size_limit() {
		return error('dependency upstream returned ${resp.status_code}')
	}
	app.ensure_namespace_storage_quota(repo.user_name, i64(resp.body.len))!
	blob := app.store_platform_blob('dependency-proxy', resp.body.bytes())!
	content_type := resp.header.get(.content_type) or { 'application/octet-stream' }
	etag := resp.header.get(.etag) or { '' }
	expires := now + 86400
	if existing.len == 0 {
		id := db_insert_returning_id(mut app.db, 'DependencyProxyEntry', ['repo_id', 'upstream_url',
			'blob_id', 'content_type', 'etag', 'created_at', 'expires_at', 'last_hit_at', 'hit_count'], [
			repo.id.str(),
			raw_url,
			blob.id.str(),
			content_type,
			etag,
			now.str(),
			expires.str(),
			now.str(),
			'1',
		])!
		row := sql app.db {
			select from DependencyProxyEntry where id == id limit 1
		}!
		return row.first(), resp.body.bytes()
	}
	id := existing.first().id
	hits := existing.first().hit_count + 1
	sql app.db {
		update DependencyProxyEntry set blob_id = blob.id, content_type = content_type,
		etag = etag, expires_at = expires, last_hit_at = now, hit_count = hits where id == id
	}!
	row := sql app.db {
		select from DependencyProxyEntry where id == id limit 1
	}!
	return row.first(), resp.body.bytes()
}

fn (mut app App) prune_unreferenced_platform_blobs() !int {
	cutoff := int(time.now().unix()) - 86400
	app.prune_expired_container_uploads(int(time.now().unix()))!
	app.prune_expired_platform_exports(int(time.now().unix()))!
	app.prune_unreferenced_container_links(cutoff)!
	blobs := sql app.db {
		select from PlatformBlob where created_at < cutoff
	}!
	mut removed := 0
	for blob in blobs {
		blob_id := blob.id
		package_refs := sql app.db {
			select count from PackageArtifact where blob_id == blob_id
		}!
		container_refs := sql app.db {
			select count from ContainerBlobLink where blob_id == blob_id
		}!
		proxy_refs := sql app.db {
			select count from DependencyProxyEntry where blob_id == blob_id
		}!
		bundle_refs := sql app.db {
			select count from ProjectExport where bundle_blob_id == blob_id
		}!
		metadata_refs := sql app.db {
			select count from ProjectExport where metadata_blob_id == blob_id
		}!
		group_refs := sql app.db {
			select count from GroupExport where blob_id == blob_id
		}!
		if package_refs + container_refs + proxy_refs + bundle_refs + metadata_refs + group_refs > 0 {
			continue
		}
		app.object_store_delete(blob.storage_key)!
		sql app.db {
			delete from PlatformBlob where id == blob_id
		}!
		removed++
	}
	return removed
}

fn (mut app App) prune_expired_platform_exports(now int) ! {
	sql app.db {
		delete from ProjectExport where expires_at > 0 && expires_at <= now
	}!
	sql app.db {
		delete from GroupExport where expires_at > 0 && expires_at <= now
	}!
}

fn (mut app App) prune_unreferenced_container_links(cutoff int) ! {
	manifests := sql app.db {
		select from ContainerManifest where is_deleted == false
	}!
	mut referenced := map[string]bool{}
	for manifest in manifests {
		referenced['${manifest.repo_id}/${manifest.blob_id}'] = true
		payload := app.load_platform_blob(manifest.blob_id) or { continue }
		for oid in container_payload_oids(payload.bytestr()) {
			blob := app.find_platform_blob_by_oid(oid) or { continue }
			referenced['${manifest.repo_id}/${blob.id}'] = true
		}
	}
	links := sql app.db {
		select from ContainerBlobLink where created_at < cutoff
	}!
	for link in links {
		if '${link.repo_id}/${link.blob_id}' in referenced {
			continue
		}
		link_id := link.id
		sql app.db {
			delete from ContainerBlobLink where id == link_id
		}!
	}
}

fn container_payload_oids(payload string) []string {
	mut result := []string{}
	mut remainder := payload
	for {
		position := remainder.index('sha256:') or { break }
		start := position + 7
		if remainder.len < start + 64 {
			break
		}
		oid := remainder[start..start + 64].to_lower()
		if valid_lfs_oid(oid) && oid !in result {
			result << oid
		}
		remainder = remainder[start + 64..]
	}
	return result
}
