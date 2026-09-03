// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import os
import time
import rand
import config
import git
import net
import net.urllib
import crypto.aes
import crypto.rand as crypto_rand
import crypto.sha256
import encoding.base64
import io.util

const mirror_secret_aad = 'gitly-repository-mirror-v1'
const mirror_sync_lease_seconds = 60 * 60

struct RepoMirror {
	id                   int @[primary; sql: serial]
	repo_id              int
	created_by           int
	direction            string
	url                  string
	encrypted_username   string
	encrypted_password   string
	encrypted_ssh_key    string
	ssh_known_hosts      string
	enabled              bool = true
	overwrite_diverged   bool
	only_protected       bool
	interval_minutes     int = 5
	created_at           int
	last_update_at       int
	next_update_at       int
	last_error           string
	consecutive_failures int
	is_syncing           bool
	sync_started_at      int
}

struct MirrorRefUpdate {
	ref_name string
	new_oid  string
	old_oid  string
}

fn valid_mirror_direction(direction string) bool {
	return direction in ['pull', 'push']
}

fn mirror_host_is_allowed(host string, port string, allowed_hosts []string) bool {
	lower_host := host.to_lower()
	if lower_host in allowed_hosts {
		return true
	}
	if lower_host == 'localhost' || lower_host.ends_with('.localhost') {
		return false
	}
	addrs := net.resolve_addrs('${host}:${port}', .unspec, .tcp) or { return false }
	if addrs.len == 0 {
		return false
	}
	for address in addrs {
		value := address.str()
		match address.family() {
			.ip {
				if is_blocked_ipv4(value.all_before_last(':')) {
					return false
				}
			}
			.ip6 {
				if is_blocked_ipv6(value.find_between('[', ']')) {
					return false
				}
			}
			else {
				return false
			}
		}
	}
	return true
}

fn is_safe_mirror_endpoint(raw string, allowed_hosts []string) bool {
	endpoint := urllib.parse(raw) or { return false }
	scheme := endpoint.scheme.to_lower()
	if scheme !in ['https', 'ssh'] || endpoint.hostname() == '' || endpoint.raw_query != ''
		|| endpoint.fragment != '' {
		return false
	}
	port := if endpoint.port() != '' {
		endpoint.port()
	} else if scheme == 'ssh' {
		'22'
	} else {
		'443'
	}
	return mirror_host_is_allowed(endpoint.hostname(), port, allowed_hosts)
}

fn normalize_mirror_endpoint(raw string, allowed_hosts []string) !(string, string, string, string) {
	mut endpoint := urllib.parse(raw.trim_space())!
	scheme := endpoint.scheme.to_lower()
	if scheme !in ['https', 'ssh'] || endpoint.hostname() == '' || endpoint.fragment != ''
		|| endpoint.raw_query != '' {
		return error('Mirror URLs must use HTTPS or SSH and cannot contain a query or fragment')
	}
	mut username := ''
	mut password := ''
	if user := endpoint.user {
		username = user.username
		if user.password_set {
			password = user.password
		}
	}
	if scheme == 'https' {
		endpoint.user = none
	} else if password != '' {
		return error('Passwords in SSH mirror URLs are not supported; use a private key')
	} else if !valid_ssh_mirror_username(username) {
		return error('The SSH mirror username is invalid')
	}
	clean := endpoint.str()
	if clean.len > max_clone_url_len || !is_safe_mirror_endpoint(clean, allowed_hosts) {
		return error('The mirror destination is not an allowed Git server')
	}
	return clean, username, password, scheme
}

fn valid_ssh_mirror_username(username string) bool {
	if username == '' {
		return true
	}
	if username.len > 255 || username.starts_with('-') || username.contains_any('\x00\r\n\t @/\\') {
		return false
	}
	for ch in username.bytes() {
		if ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	return true
}

fn encrypt_mirror_secret(storage_secret string, value string) !string {
	if value == '' {
		return ''
	}
	if storage_secret.len < 16 {
		return error('GITLY_STORAGE_SECRET must be configured to store mirror credentials')
	}
	key := sha256.sum(storage_secret.bytes())
	mut nonce := []u8{len: aes.gcm_nonce_size}
	crypto_rand.read(mut nonce)!
	gcm := aes.new_aes_gcm(key[..])!
	ciphertext := gcm.encrypt(value.bytes(), nonce, mirror_secret_aad.bytes())!
	mut payload := nonce.clone()
	payload << ciphertext
	return base64.encode(payload)
}

fn decrypt_mirror_secret(storage_secret string, value string) !string {
	if value == '' {
		return ''
	}
	if storage_secret.len < 16 {
		return error('Mirror credential encryption is not configured')
	}
	payload := base64.decode(value)
	if payload.len <= aes.gcm_nonce_size + aes.gcm_tag_size {
		return error('Mirror credentials are corrupted')
	}
	key := sha256.sum(storage_secret.bytes())
	gcm := aes.new_aes_gcm(key[..])!
	plain := gcm.decrypt(payload[aes.gcm_nonce_size..], payload[..aes.gcm_nonce_size], mirror_secret_aad.bytes())!
	return plain.bytestr()
}

fn (mirror RepoMirror) last_update_description() string {
	if mirror.last_update_at <= 0 {
		return 'Never'
	}
	return time.unix(mirror.last_update_at).relative()
}

fn (mirror RepoMirror) next_update_description() string {
	if !mirror.enabled {
		return 'Paused'
	}
	if mirror.next_update_at <= 0 {
		return 'Pending'
	}
	return time.unix(mirror.next_update_at).relative()
}

fn (app &App) list_repo_mirrors(repo_id int) []RepoMirror {
	return sql app.db {
		select from RepoMirror where repo_id == repo_id order by id desc
	} or { []RepoMirror{} }
}

fn (app &App) find_repo_mirror(id int) ?RepoMirror {
	rows := sql app.db {
		select from RepoMirror where id == id limit 1
	} or { []RepoMirror{} }
	if rows.len == 0 {
		return none
	}
	return rows.first()
}

fn (mut app App) add_repo_mirror(repo_id int, created_by int, raw_url string, form_username string,
	form_password string, ssh_private_key string, ssh_known_hosts string, direction string,
	overwrite_diverged bool, only_protected bool, interval_minutes int) !int {
	if repo_id <= 0 || created_by <= 0 || !valid_mirror_direction(direction) {
		return error('Invalid repository mirror')
	}
	mut clean_url, embedded_username, embedded_password, scheme := normalize_mirror_endpoint(raw_url, app.config.mirror_allowed_hosts)!
	username := if form_username != '' { form_username } else { embedded_username }
	password := if form_password != '' { form_password } else { embedded_password }
	if username.len > 1024 || password.len > 4096 {
		return error('Mirror credentials are too long')
	}
	if ssh_private_key.len > 65_536 || ssh_known_hosts.len > 65_536 {
		return error('SSH mirror credentials are too long')
	}
	if scheme == 'ssh' {
		if !valid_ssh_mirror_username(username) {
			return error('The SSH mirror username is invalid')
		}
		if ssh_known_hosts.trim_space() == '' {
			return error('SSH mirrors require a pinned known_hosts entry')
		}
		mut endpoint := urllib.parse(clean_url)!
		if username != '' {
			endpoint.user = urllib.user(username)
		}
		clean_url = endpoint.str()
	}
	interval := if interval_minutes < 5 {
		5
	} else if interval_minutes > 1440 {
		1440
	} else {
		interval_minutes
	}
	now := int(time.now().unix())
	return db_insert_returning_id(mut app.db, 'RepoMirror', ['repo_id', 'created_by', 'direction',
		'url', 'encrypted_username', 'encrypted_password', 'encrypted_ssh_key', 'ssh_known_hosts',
		'enabled', 'overwrite_diverged', 'only_protected', 'interval_minutes', 'created_at',
		'last_update_at', 'next_update_at', 'last_error', 'consecutive_failures', 'is_syncing',
		'sync_started_at'], [
		repo_id.str(),
		created_by.str(),
		direction,
		clean_url,
		encrypt_mirror_secret(app.config.storage_secret, username)!,
		encrypt_mirror_secret(app.config.storage_secret, password)!,
		encrypt_mirror_secret(app.config.storage_secret, ssh_private_key)!,
		ssh_known_hosts.trim_space(),
		db_bool_value(true),
		db_bool_value(overwrite_diverged),
		db_bool_value(only_protected),
		interval.str(),
		now.str(),
		'0',
		now.str(),
		'',
		'0',
		db_bool_value(false),
		'0',
	])
}

fn (mut app App) set_repo_mirror_enabled(repo_id int, mirror_id int, enabled bool) ! {
	if repo_id <= 0 || mirror_id <= 0 {
		return error('Invalid repository mirror')
	}
	next_update_at := int(time.now().unix())
	rows := db_exec_values(mut app.db, 'update ${sql_table('RepoMirror')}
		set ${sql_table('enabled')} = ${db_bool_value(enabled)},
			${sql_table('next_update_at')} = ${next_update_at}
		where ${sql_table('id')} = ${mirror_id}
			and ${sql_table('repo_id')} = ${repo_id}
		returning ${sql_table('id')}')!
	if rows.len != 1 {
		return error('Repository mirror not found')
	}
}

fn (mut app App) delete_repo_mirror(repo_id int, mirror_id int) ! {
	sql app.db {
		delete from RepoMirror where id == mirror_id && repo_id == repo_id
	}!
}

fn (mut app App) delete_repo_mirrors(repo_id int) ! {
	sql app.db {
		delete from RepoMirror where repo_id == repo_id
	}!
}

fn mirror_remote_name(id int) string {
	return 'gitly-mirror-${id}'
}

fn write_private_mirror_file(path string, content string, mode int) ! {
	mut file := os.open_file(path, 'w', mode)!
	defer {
		file.close()
	}
	file.write_string(content)!
}

fn prepare_mirror_auth(app &App, mirror RepoMirror) !(map[string]string, []string) {
	username := decrypt_mirror_secret(app.config.storage_secret, mirror.encrypted_username)!
	password := decrypt_mirror_secret(app.config.storage_secret, mirror.encrypted_password)!
	ssh_key := decrypt_mirror_secret(app.config.storage_secret, mirror.encrypted_ssh_key)!
	mut cleanup := []string{}
	mut keep_files := false
	defer {
		if !keep_files {
			for path in cleanup {
				os.rm(path) or {}
			}
		}
	}
	endpoint := urllib.parse(mirror.url)!
	if endpoint.scheme == 'ssh' {
		if mirror.ssh_known_hosts.trim_space() == '' {
			return error('SSH mirror host key is not configured')
		}
		known_hosts_path := os.join_path(os.temp_dir(), 'gitly-known-hosts-${os.getpid()}-${rand.ulid()}')
		cleanup << known_hosts_path
		write_private_mirror_file(known_hosts_path, mirror.ssh_known_hosts + '\n', 0o600)!
		mut ssh_key_path := ''
		if ssh_key != '' {
			ssh_key_path = os.join_path(os.temp_dir(), 'gitly-mirror-key-${os.getpid()}-${rand.ulid()}')
			cleanup << ssh_key_path
			write_private_mirror_file(ssh_key_path, ssh_key, 0o600)!
		}
		wrapper_path := os.join_path(os.temp_dir(), 'gitly-ssh-${os.getpid()}-${rand.ulid()}.sh')
		cleanup << wrapper_path
		write_private_mirror_file(wrapper_path, r'#!/bin/sh
set -- -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$GITLY_MIRROR_KNOWN_HOSTS" "$@"
if [ -n "$GITLY_MIRROR_SSH_KEY" ]; then
  set -- -i "$GITLY_MIRROR_SSH_KEY" -o IdentitiesOnly=yes "$@"
fi
exec ssh "$@"
', 0o700)!
		keep_files = true
		return {
			'GIT_SSH':                  wrapper_path
			'GIT_TERMINAL_PROMPT':      '0'
			'GITLY_MIRROR_KNOWN_HOSTS': known_hosts_path
			'GITLY_MIRROR_SSH_KEY':     ssh_key_path
		}, cleanup
	}
	if username == '' && password == '' {
		keep_files = true
		return {
			'GIT_TERMINAL_PROMPT': '0'
		}, cleanup
	}
	path := os.join_path(os.temp_dir(), 'gitly-askpass-${os.getpid()}-${rand.ulid()}.sh')
	cleanup << path
	write_private_mirror_file(path, r'#!/bin/sh
case "$1" in
  *Username*) printf "%s\n" "$GITLY_MIRROR_USERNAME" ;;
  *) printf "%s\n" "$GITLY_MIRROR_PASSWORD" ;;
esac
', 0o700)!
	keep_files = true
	return {
		'GIT_ASKPASS':           path
		'GIT_ASKPASS_REQUIRE':   'force'
		'GIT_TERMINAL_PROMPT':   '0'
		'GITLY_MIRROR_USERNAME': username
		'GITLY_MIRROR_PASSWORD': password
	}, cleanup
}

fn configure_mirror_remote(repo Repo, mirror RepoMirror) ! {
	remote := mirror_remote_name(mirror.id)
	set_url := git.Git.exec_in_dir(repo.git_dir, ['remote', 'set-url', remote, mirror.url])
	if set_url.exit_code == 0 {
		return
	}
	add := git.Git.exec_in_dir(repo.git_dir, ['remote', 'add', remote, mirror.url])
	if add.exit_code != 0 {
		return error('Could not configure the mirror remote')
	}
}

fn mirror_branch_allowed(app &App, mirror RepoMirror, branch string) bool {
	return !mirror.only_protected || app.branch_is_protected(mirror.repo_id, branch)
}

fn mirror_remote_branches(repo Repo, mirror RepoMirror) ![]string {
	remote := mirror_remote_name(mirror.id)
	refs := git.Git.exec_in_dir(repo.git_dir, ['for-each-ref', '--format=%(refname:strip=3)',
		'refs/remotes/${remote}'])
	if refs.exit_code != 0 {
		return error('Could not inspect fetched mirror branches')
	}
	return refs.output.split_into_lines().map(it.trim_space()).filter(it != '')
}

// update_mirror_refs applies a fetched snapshot as one Git reference
// transaction. A diverged tag/branch or a concurrent local push therefore
// aborts the whole publication instead of leaving a partially mirrored state.
fn update_mirror_refs(git_dir string, updates []MirrorRefUpdate) ! {
	if updates.len == 0 {
		return
	}
	mut transaction := ''
	for update in updates {
		if !update.ref_name.starts_with('refs/') || update.ref_name.contains_any('\x00\r\n ')
			|| !is_full_git_oid(update.new_oid) || !is_full_git_oid(update.old_oid) {
			return error('Invalid mirror ref transaction')
		}
		transaction += 'update ${update.ref_name} ${update.new_oid} ${update.old_oid}\n'
	}
	mut input, input_path := util.temp_file(pattern: 'gitly-mirror-refs-*.stdin')!
	input.close()
	defer {
		os.rm(input_path) or {}
	}
	os.write_file(input_path, transaction)!
	mut process := os.new_process('git')
	process.set_args(['-C', git_dir, 'update-ref', '--stdin'])
	process.set_redirect_stdio_merged()
	process.set_stdin_path(input_path)
	process.run()
	output := process.stdout_slurp()
	process.wait()
	exit_code := process.code
	process.close()
	if exit_code != 0 {
		return error('Local references changed during mirror update: ${output.trim_space()}')
	}
}

fn (mut app App) pull_repo_mirror(repo Repo, mirror RepoMirror, env map[string]string) ! {
	remote := mirror_remote_name(mirror.id)
	fetch := git.Git.exec_in_dir_with_env(repo.git_dir, ['-c', 'http.followRedirects=false', 'fetch',
		'--prune', '--no-tags', remote, '+refs/heads/*:refs/remotes/${remote}/*',
		'+refs/tags/*:refs/gitly-mirrors/${mirror.id}/tags/*'], env)
	if fetch.exit_code != 0 {
		return error('Mirror fetch failed: ${fetch.output.trim_space()}')
	}
	mut updates := []MirrorRefUpdate{}
	for branch in mirror_remote_branches(repo, mirror)! {
		if !mirror_branch_allowed(app, mirror, branch) {
			continue
		}
		local_ref := 'refs/heads/${branch}'
		remote_ref := 'refs/remotes/${remote}/${branch}'
		remote_sha := git_rev_parse(repo.git_dir, remote_ref) or {
			return error('Could not resolve mirrored branch ${branch}')
		}
		local_exists := git.Git.exec_in_dir(repo.git_dir, ['show-ref', '--verify', '--quiet',
			local_ref]).exit_code == 0
		mut expected_old_sha := zero_oid_like(remote_sha)!
		if local_exists {
			expected_old_sha = git_rev_parse(repo.git_dir, local_ref) or {
				return error('Could not resolve local branch ${branch}')
			}
			if expected_old_sha == remote_sha {
				continue
			}
			if !mirror.overwrite_diverged {
				ff := git.Git.exec_in_dir(repo.git_dir, ['merge-base', '--is-ancestor',
					expected_old_sha, remote_sha])
				if ff.exit_code != 0 {
					return error('Mirror branch ${branch} diverged; enable overwrite to replace it')
				}
			}
		}
		app.verify_commit_range_for_policy(repo, expected_old_sha, remote_sha)!
		updates << MirrorRefUpdate{
			ref_name: local_ref
			new_oid: remote_sha
			old_oid: expected_old_sha
		}
	}
	if !mirror.only_protected {
		tags := git.Git.exec_in_dir(repo.git_dir, ['for-each-ref', '--format=%(refname:strip=4)',
			'refs/gitly-mirrors/${mirror.id}/tags'])
		if tags.exit_code != 0 {
			return error('Could not inspect fetched mirror tags')
		}
		for tag in tags.output.split_into_lines().map(it.trim_space()).filter(it != '') {
			if app.tag_is_protected(repo.id, tag) {
				continue
			}
			local_ref := 'refs/tags/${tag}'
			remote_ref := 'refs/gitly-mirrors/${mirror.id}/tags/${tag}'
			remote_sha := git_rev_parse(repo.git_dir, remote_ref) or {
				return error('Could not resolve mirrored tag ${tag}')
			}
			exists := git.Git.exec_in_dir(repo.git_dir, ['show-ref', '--verify', '--quiet',
				local_ref]).exit_code == 0
			mut expected_old_sha := zero_oid_like(remote_sha)!
			if exists {
				expected_old_sha = git_rev_parse(repo.git_dir, local_ref) or {
					return error('Could not resolve local tag ${tag}')
				}
				if expected_old_sha == remote_sha {
					continue
				}
				if !mirror.overwrite_diverged {
					return error('Mirror tag ${tag} diverged; enable overwrite to replace it')
				}
			}
			app.verify_commit_range_for_policy(repo, expected_old_sha, remote_sha)!
			updates << MirrorRefUpdate{
				ref_name: local_ref
				new_oid: remote_sha
				old_oid: expected_old_sha
			}
		}
	}
	update_mirror_refs(repo.git_dir, updates)!
	mut refreshed := repo
	app.update_repo_from_fs(mut refreshed, false)!
}

fn local_repo_branches(repo Repo) []string {
	refs := git.Git.exec_in_dir(repo.git_dir, ['for-each-ref', '--format=%(refname:strip=2)',
		'refs/heads'])
	if refs.exit_code != 0 {
		return []string{}
	}
	return refs.output.split_into_lines().map(it.trim_space()).filter(it != '')
}

fn (app &App) push_repo_mirror(repo Repo, mirror RepoMirror, env map[string]string) ! {
	remote := mirror_remote_name(mirror.id)
	mut args := ['-c', 'http.followRedirects=false', 'push', '--atomic']
	if !mirror.only_protected {
		args << '--prune'
	}
	args << remote
	prefix := if mirror.overwrite_diverged { '+' } else { '' }
	if mirror.only_protected {
		for branch in local_repo_branches(repo) {
			if app.branch_is_protected(repo.id, branch) {
				args << '${prefix}refs/heads/${branch}:refs/heads/${branch}'
			}
		}
		if args.len == 5 {
			return error('No protected branches are available to mirror')
		}
	} else {
		args << '${prefix}refs/heads/*:refs/heads/*'
		args << '${prefix}refs/tags/*:refs/tags/*'
	}
	result := git.Git.exec_in_dir_with_env(repo.git_dir, args, env)
	if result.exit_code != 0 {
		return error('Mirror push failed: ${result.output.trim_space()}')
	}
}

fn (mut app App) record_mirror_result(mirror RepoMirror, message string) {
	now := int(time.now().unix())
	next := now + mirror.interval_minutes * 60
	failures := if message == '' { 0 } else { mirror.consecutive_failures + 1 }
	false_value := false
	sync_started_at := 0
	claimed_at := mirror.sync_started_at
	sql app.db {
		update RepoMirror set last_update_at = now, next_update_at = next, last_error = message,
		consecutive_failures = failures, is_syncing = false_value,
		sync_started_at = sync_started_at where id == mirror.id && sync_started_at == claimed_at
	} or {}
}

fn (mut app App) claim_repo_mirror(mirror_id int) !RepoMirror {
	if mirror_id <= 0 {
		return error('The mirror is disabled or invalid')
	}
	now := int(time.now().unix())
	stale_before := now - mirror_sync_lease_seconds
	rows := db_exec_values(mut app.db, 'update ${sql_table('RepoMirror')}
		set ${sql_table('is_syncing')} = ${db_bool_value(true)},
			${sql_table('sync_started_at')} = ${now}
		where ${sql_table('id')} = ${mirror_id}
			and ${sql_table('enabled')} = ${db_bool_value(true)}
			and (${sql_table('is_syncing')} = ${db_bool_value(false)}
				or ${sql_table('sync_started_at')} <= ${stale_before})
		returning ${sql_table('id')}')!
	if rows.len != 1 {
		return error('The mirror is disabled or already synchronizing')
	}
	return app.find_repo_mirror(mirror_id) or { error('Repository mirror not found') }
}

fn (mut app App) sync_repo_mirror(mirror RepoMirror, allow_local bool) ! {
	claimed := app.claim_repo_mirror(mirror.id)!
	if !valid_mirror_direction(claimed.direction) {
		app.record_mirror_result(claimed, 'The mirror direction is invalid')
		return error('The mirror is invalid')
	}
	if !allow_local && !is_safe_mirror_endpoint(claimed.url, app.config.mirror_allowed_hosts) {
		app.record_mirror_result(claimed, 'Blocked: destination is not an allowed Git server')
		return error('The mirror destination is no longer safe')
	}
	repo := app.find_repo_by_id(claimed.repo_id) or {
		app.record_mirror_result(claimed, 'Repository not found')
		return error('Repository not found')
	}
	configure_mirror_remote(repo, claimed) or {
		app.record_mirror_result(claimed, err.str())
		return err
	}
	env, cleanup_paths := prepare_mirror_auth(app, claimed) or {
		app.record_mirror_result(claimed, err.str())
		return err
	}
	defer {
		for path in cleanup_paths {
			os.rm(path) or {}
		}
	}
	if claimed.direction == 'pull' {
		app.pull_repo_mirror(repo, claimed, env) or {
			app.record_mirror_result(claimed, err.str())
			return err
		}
	} else {
		app.push_repo_mirror(repo, claimed, env) or {
			app.record_mirror_result(claimed, err.str())
			return err
		}
	}
	app.record_mirror_result(claimed, '')
}

fn run_push_mirrors(repo_id int, conf config.Config) {
	mut app := App{
		db: connect_db(conf) or { return }
		config: conf
	}
	defer {
		app.db.close() or {}
	}
	for mirror in app.list_repo_mirrors(repo_id) {
		if mirror.enabled && mirror.direction == 'push' {
			app.sync_repo_mirror(mirror, false) or { app.warn('Push mirror failed: ${err}') }
		}
	}
}

fn run_mirror_scheduler(conf config.Config) {
	for {
		mut app := App{
			db: connect_db(conf) or {
				time.sleep(time.minute)
				continue
			}
			config: conf
		}
		now := int(time.now().unix())
		stale_before := now - mirror_sync_lease_seconds
		mirrors := sql app.db {
			select from RepoMirror where enabled == true && next_update_at <= now
			&& (is_syncing == false || sync_started_at <= stale_before)
		} or { []RepoMirror{} }
		for mirror in mirrors {
			app.sync_repo_mirror(mirror, false) or { app.warn('Scheduled mirror failed: ${err}') }
		}
		app.db.close() or {}
		time.sleep(time.minute)
	}
}
