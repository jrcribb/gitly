module main

import crypto.sha256
import compress.gzip

// Regression tests for the input validation that guards git command
// construction in create_file_in_bare_repo (see repo/file_routes.v). These
// inputs used to be interpolated into shell strings; they are now passed to
// git as plain arguments, but we still reject values git could misread as
// flags/refs or that contain control characters.

fn test_is_valid_repo_file_path_accepts_normal_paths() {
	assert is_valid_repo_file_path('README.md')
	assert is_valid_repo_file_path('src/main.v')
	assert is_valid_repo_file_path('dir/file,with,commas.txt')
	assert is_valid_repo_file_path('a/b/c/d.e')
	assert is_valid_repo_file_path('release..notes.txt')
}

fn test_is_valid_repo_file_path_rejects_dangerous_paths() {
	assert !is_valid_repo_file_path('')
	assert !is_valid_repo_file_path('/etc/passwd') // absolute
	assert !is_valid_repo_file_path('-rf') // looks like a flag
	assert !is_valid_repo_file_path('../../etc/passwd') // traversal
	assert !is_valid_repo_file_path('a/../../b') // traversal
	assert !is_valid_repo_file_path('file\nname') // newline
	assert !is_valid_repo_file_path('file\x00name') // NUL
	assert !is_valid_repo_file_path('a\tb') // tab / control char
}

fn test_repository_url_paths_escape_special_filename_characters() {
	assert repo_url_path('feature/api') == 'feature/api'
	assert repo_url_path('docs/a file#1?.md') == 'docs/a%20file%231%3F.md'
	file := File{
		branch:      'refs/tags/release/v1'
		parent_path: 'docs'
		name:        'a file#1?.md'
	}
	assert file.url() == 'blob/refs/tags/release/v1/docs/a%20file%231%3F.md'
}

fn test_is_safe_ref_accepts_normal_branches() {
	assert is_safe_ref('master')
	assert is_safe_ref('feature/new-thing')
	assert is_safe_ref('release-1.2.3')
}

fn test_is_safe_ref_rejects_injection_attempts() {
	assert !is_safe_ref('')
	assert !is_safe_ref('--upload-pack=touch /tmp/pwned') // leading dash + space
	assert !is_safe_ref('master;rm -rf /') // shell metacharacters
	assert !is_safe_ref('master$(whoami)')
	assert !is_safe_ref('master`id`')
	assert !is_safe_ref('a..b') // ref traversal
	assert !is_safe_ref('branch with spaces')
	assert !is_safe_ref('/main')
	assert !is_safe_ref('main/')
	assert !is_safe_ref('.hidden')
	assert !is_safe_ref('release.lock')
	assert !is_safe_ref('feature//nested')
}

// Webhook SSRF guard: the IP classifiers must reject internal destinations and
// allow public ones. (is_safe_webhook_url itself does DNS and isn't unit-tested.)

fn test_is_blocked_ipv4_blocks_internal_ranges() {
	assert is_blocked_ipv4('127.0.0.1') // loopback
	assert is_blocked_ipv4('10.1.2.3') // private
	assert is_blocked_ipv4('172.16.5.5') // private
	assert is_blocked_ipv4('172.31.255.255') // private (edge)
	assert is_blocked_ipv4('192.168.0.1') // private
	assert is_blocked_ipv4('169.254.169.254') // link-local / cloud metadata
	assert is_blocked_ipv4('0.0.0.0') // unspecified
	assert is_blocked_ipv4('100.64.0.1') // CGNAT
	assert is_blocked_ipv4('224.0.0.1') // multicast
	assert is_blocked_ipv4('garbage') // unparseable -> fail closed
}

fn test_is_blocked_ipv4_allows_public() {
	assert !is_blocked_ipv4('8.8.8.8')
	assert !is_blocked_ipv4('1.1.1.1')
	assert !is_blocked_ipv4('172.32.0.1') // just outside 172.16/12
	assert !is_blocked_ipv4('172.15.0.1') // just outside 172.16/12
	assert !is_blocked_ipv4('93.184.216.34')
}

fn test_is_blocked_ipv6() {
	assert is_blocked_ipv6('::1') // loopback
	assert is_blocked_ipv6('::') // unspecified
	assert is_blocked_ipv6('fe80::1') // link-local
	assert is_blocked_ipv6('fc00::1') // unique-local
	assert is_blocked_ipv6('fd12:3456::1') // unique-local
	assert is_blocked_ipv6('::ffff:127.0.0.1') // IPv4-mapped loopback
	assert !is_blocked_ipv6('2606:4700:4700::1111') // public
	assert !is_blocked_ipv6('::ffff:8.8.8.8') // IPv4-mapped public
}

// Password hashing: new hashes must be bcrypt, and legacy salted-SHA-256 hashes
// must still verify (so existing users aren't locked out before re-login).

fn test_new_passwords_are_bcrypt() {
	h := hash_password_with_salt('s3cret-pw', 'ignored-salt')
	assert h.starts_with('$2') // bcrypt hash
	assert !password_hash_is_legacy(h)
	assert compare_password_with_hash('s3cret-pw', 'ignored-salt', h)
	assert !compare_password_with_hash('wrong-pw', 'ignored-salt', h)
}

fn test_legacy_sha256_hashes_still_verify() {
	salt := 'abc123'
	// Legacy scheme was sha256('${password}${salt}').
	legacy := sha256.sum('hunter2${salt}'.bytes()).hex()
	assert password_hash_is_legacy(legacy)
	assert compare_password_with_hash('hunter2', salt, legacy)
	assert !compare_password_with_hash('nope', salt, legacy)
}

fn test_state_changing_request_source_must_match_host() {
	assert url_source_matches_host('https://gitly.example', 'gitly.example')
	assert url_source_matches_host('https://gitly.example/repo/settings', 'gitly.example')
	assert url_source_matches_host('http://localhost:8080/new', 'localhost:8080')
	assert url_source_matches_host('https://gitly.example:443/new', 'gitly.example:443')
	assert !url_source_matches_host('https://gitly.example.attacker.test/new', 'gitly.example')
	assert !url_source_matches_host('https://attacker.test/new', 'gitly.example')
	assert !url_source_matches_host('null', 'gitly.example')
	assert !url_source_matches_host('javascript:alert(1)', 'gitly.example')
}

fn test_paypal_is_shown_only_for_gitly_org() {
	assert is_gitly_org_host('gitly.org')
	assert is_gitly_org_host('GITLY.ORG')
	assert is_gitly_org_host('gitly.org:443')
	assert !is_gitly_org_host('localhost:8080')
	assert !is_gitly_org_host('gitly.org:8443')
	assert !is_gitly_org_host('www.gitly.org')
	assert !is_gitly_org_host('gitly.org.attacker.test')
}

fn test_session_tokens_are_stored_as_hashes() {
	plain := 'a-session-token'
	hashed := hash_session_token(plain)
	assert hashed != plain
	assert hashed.len == 64
	assert hash_session_token(plain) == hashed
}

fn test_user_content_size_limits() {
	assert valid_title('A useful title')
	assert !valid_title('  ')
	assert !valid_title('x'.repeat(max_title_len + 1))
	assert valid_comment('Looks good')
	assert !valid_comment('')
	assert !valid_comment('x'.repeat(max_comment_len + 1))
	assert valid_body('x'.repeat(max_body_len))
	assert !valid_body('x'.repeat(max_body_len + 1))
}

fn test_webhook_events_are_normalized_and_restricted() {
	assert normalize_webhook_events(' issue, push,issue ')! == 'issue,push'
	assert normalize_webhook_events('')! == 'push,issue,pr,comment,release'
	mut rejected := false
	normalize_webhook_events('push,unknown') or { rejected = true }
	assert rejected
}

fn test_login_throttle_expires_without_changing_admin_block_status() {
	now := i64(2_000_000)
	user := User{
		is_blocked:            false
		login_throttled_until: now + login_throttle_seconds
	}
	assert user_login_is_throttled(user, now)
	assert !user_login_is_throttled(user, now + login_throttle_seconds)
	assert !user.is_blocked
}

fn test_daily_post_limit_expires_after_twenty_four_hours() {
	now := 2_000_000
	active := User{
		posts_count:    posts_per_day
		last_post_time: now - 60
	}
	expired := User{
		posts_count:    posts_per_day
		last_post_time: now - 24 * 60 * 60
	}

	assert user_reached_post_limit(active, now)
	assert !user_reached_post_limit(expired, now)
	assert user_post_window_expired(expired, now)
}

fn test_ssh_public_key_shape_validation() {
	valid := 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTp8P3nHx3Eu0PUM1Op46RGvl/9Ln+w8pqoW5b+RF9y test@example'
	assert is_valid_ssh_public_key(valid)
	assert ssh_key_fingerprint(valid) or { '' } == 'SHA256:pFeDxNVqoJfBCYeygw1Qlsv2xruZomuWmeYB7G9DN3k'
	assert !is_valid_ssh_public_key('')
	assert !is_valid_ssh_public_key('not-a-key AAAAB3NzaC1yc2EAAAADAQABAAABAQCexample')
	assert !is_valid_ssh_public_key('ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIPTp8P3nHx3Eu0PUM1Op46RGvl/9Ln+w8pqoW5b+RF9y')
	assert !is_valid_ssh_public_key('ssh-ed25519 ../../etc/passwd')
}

fn test_ssh_forced_command_parser_is_strict() {
	target := parse_ssh_original_command("git-upload-pack 'alice/project.git'") or {
		panic('valid command was rejected')
	}
	assert target.service == 'git-upload-pack'
	assert target.owner == 'alice'
	assert target.repo_name == 'project'
	assert parse_ssh_original_command("git-receive-pack 'team/repo.git'") != none
	assert parse_ssh_original_command("git-upload-archive 'alice/project.git'") == none
	assert parse_ssh_original_command("git-upload-pack '/etc/passwd'") == none
	assert parse_ssh_original_command("git-upload-pack 'alice/../secret.git'") == none
	assert parse_ssh_original_command("git-upload-pack 'alice/project.git'; id") == none
	assert parse_ssh_original_command("git-upload-pack 'alice/project.git' extra") == none
	assert parse_ssh_original_command('git-upload-pack alice/project.git') == none
	assert parse_ssh_original_command("git-upload-pack 'alice/project/extra.git'") == none
	assert parse_ssh_original_command("git-upload-pack 'alice/project.git'\nid") == none
}

fn test_ssh_connection_metadata_only_accepts_an_ip_address() {
	assert ssh_client_ip('192.0.2.10 53210 192.0.2.20 22') == '192.0.2.10'
	assert ssh_client_ip('2001:db8::10 53210 2001:db8::20 22') == '2001:db8::10'
	assert ssh_client_ip('client.example 53210 192.0.2.20 22') == ''
	assert ssh_client_ip('999.0.0.1 53210 192.0.2.20 22') == ''
	assert ssh_client_ip('2001:::10 53210 2001:db8::20 22') == ''
	assert ssh_client_ip("192.0.2.10\nINJECTED=1 53210 192.0.2.20 22") == ''
}

fn test_forced_git_service_uses_an_allowlisted_environment() {
	environment := git_service_environment('/usr/bin/git', {
		'GITLY_REPO_ID':       '42'
		'GITLY_UNRECOGNIZED':   'not allowlisted'
		'GIT_CONFIG_COUNT':     '1'
		'LD_PRELOAD':           '/tmp/evil.so'
		'SSH_ORIGINAL_COMMAND': 'arbitrary command'
	}, 'version=2')
	assert environment['GITLY_REPO_ID'] == '42'
	assert environment['GIT_PROTOCOL'] == 'version=2'
	assert environment['GIT_CONFIG_NOSYSTEM'] == '1'
	assert environment['GIT_CONFIG_GLOBAL'] == '/dev/null'
	assert 'GIT_CONFIG_COUNT' !in environment
	assert 'GITLY_UNRECOGNIZED' !in environment
	assert 'LD_PRELOAD' !in environment
	assert 'SSH_ORIGINAL_COMMAND' !in environment
	assert 'HOME' !in environment
}

fn test_authorized_keys_managed_block_preserves_admin_keys() {
	existing := 'ssh-ed25519 external-admin admin@example\n\n${ssh_authorized_keys_begin}\nold managed key\n${ssh_authorized_keys_end}\n'
	updated := replace_managed_authorized_keys(existing, [
		'restrict,command="gitly" ssh-ed25519 managed',
	])
	assert updated.contains('ssh-ed25519 external-admin admin@example')
	assert !updated.contains('old managed key')
	assert updated.contains('restrict,command="gitly" ssh-ed25519 managed')
	assert updated.count(ssh_authorized_keys_begin) == 1
	assert updated.count(ssh_authorized_keys_end) == 1
}

fn test_commit_messages_are_escaped_before_rendering() {
	plain := File{
		last_msg: '<img src=x onerror=alert(1)>'
	}.format_commit_message().str()
	assert !plain.contains('<img')
	assert plain.contains('&lt;img')

	linked := File{
		last_msg: '<b>fix</b> #42'
	}.format_commit_message().str()
	assert linked.contains('&lt;b&gt;fix&lt;/b&gt;')
	assert linked.contains('>#42</a>')
}

fn test_commit_hash_validation_rejects_git_options() {
	assert is_valid_commit_hash('deadbeef')
	assert is_valid_commit_hash('0123456789abcdef0123456789abcdef01234567')
	assert !is_valid_commit_hash('')
	assert !is_valid_commit_hash('--help')
	assert !is_valid_commit_hash('deadbeef;touch')
	assert !is_valid_commit_hash('not-a-hash')
}

fn test_git_gzip_body_decompression_is_bounded() {
	original := 'git-pack-data'.repeat(10_000)
	compressed := gzip.compress(original.bytes())!
	decoded := decompress_git_body(compressed.bytestr(), original.len)!
	assert decoded == original

	mut rejected := false
	decompress_git_body(compressed.bytestr(), 1024) or {
		rejected = true
		assert err.msg().contains('too large')
	}
	assert rejected
}
