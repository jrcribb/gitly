// Integration tests for every /api/v1/ endpoint exposed by gitly.
//
// The suite spawns its own gitly process on a non-default port using a
// dedicated sqlite database, so it can be executed independently of any
// long-running dev instance (run with `v test api/` or `v test .`).
//
// Endpoints covered:
//   GET  /api/v1/me
//   GET  /api/v1/users/:username
//   GET  /api/v1/users/:username/repos
//   GET  /api/v1/repos/:username/:repo_name
//   GET  /api/v1/repos/:username/:repo_name/issues
//   POST /api/v1/repos/:username/:repo_name/issues
//   GET  /api/v1/repos/:username/:repo_name/issues/:id
//   POST /api/v1/repos/:username/:repo_name/issues/:id
//   GET  /api/v1/repos/:username/:repo_name/issues/:id/comments
//   POST /api/v1/repos/:username/:repo_name/issues/:id/comments
//   POST /api/v1/repos/:username/:repo_name/issues/:id/close
//   POST /api/v1/repos/:username/:repo_name/issues/:id/reopen
//   GET  /api/v1/repos/:username/:repo_name/labels
//   POST /api/v1/repos/:username/:repo_name/labels
//   POST /api/v1/repos/:username/:repo_name/labels/:id
//   POST /api/v1/repos/:username/:repo_name/labels/:id/delete
//   GET  /api/v1/repos/:username/:repo_name/pulls
//   GET  /api/v1/repos/:username/:repo_name/pulls/:id
//   GET  /api/v1/repos/:username/:repo_name/pulls/:id/comments
//   POST /api/v1/repos/:repo_id/star
//   POST /api/v1/repos/:repo_id/watch
//   GET  /api/v1/repos/:repo_id_str/tree/files
//   GET  /api/v1/:user/:repo_name/branches/count
//   GET  /api/v1/repos/:username/:repo_name/branches
//   POST /api/v1/repos/:username/:repo_name/branches
//   POST /api/v1/repos/:username/:repo_name/branches/delete
//   GET  /api/v1/:user/:repo_name/:branch_name/commits/count
//   GET  /api/v1/:username/:repo_name/issues/count
//   POST /api/v1/users/avatar
//   POST /api/v1/ci/status
module api

import os
import log
import net.http
import time
import x.json2 as json

const test_port = 8765
const test_url = 'http://127.0.0.1:${test_port}'
const test_username = 'apitester'
const test_password = '1234zxcv'
const test_email = 'apitester@example.com'
const test_repo = 'apitest'
const test_private_repo = 'private-api-test'
const test_org = 'api-test-org'
const test_org_repo = 'private-org-test'
const test_other_user = 'apitester2'
const test_other_password = '5678qwer'
const test_other_email = 'apitester2@example.com'

const test_binary = 'gitly_apitest.exe'
const test_sqlite_path = 'gitly_apitest.sqlite'

// Test-wide state is passed between testsuite_begin and individual tests via
// environment variables, since `v test` does not allow `__global` declarations
// in module test files.
const env_session = 'GITLY_APITEST_SESSION'
const env_other_session = 'GITLY_APITEST_OTHER_SESSION'
const env_bearer = 'GITLY_APITEST_BEARER'
const env_repo_id = 'GITLY_APITEST_REPO_ID'

fn session_cookie() string {
	return os.getenv(env_session)
}

fn other_session_cookie() string {
	return os.getenv(env_other_session)
}

fn bearer_token() string {
	return os.getenv(env_bearer)
}

fn repo_id() int {
	return os.getenv(env_repo_id).int()
}

// -- testsuite plumbing -------------------------------------------------------
fn testsuite_begin() {
	chdir_to_project_root()
	kill_test_gitly()
	cleanup_test_state()
	ensure_gitly_binary()
	spawn_test_gitly()
	wait_for_test_gitly()

	session := register(test_username, test_password, test_email) or {
		fail('register primary user: ${err}')
	}
	os.setenv(env_session, session, true)

	other := register(test_other_user, test_other_password, test_other_email) or {
		fail('register secondary user: ${err}')
	}
	os.setenv(env_other_session, other, true)

	token := create_api_token(session, test_username) or { fail('create api token: ${err}') }
	os.setenv(env_bearer, token, true)

	create_repo(session, test_repo) or { fail('create repo: ${err}') }
	create_repo_with_owner(session, test_private_repo, 'private', test_username) or {
		fail('create private repo: ${err}')
	}
	create_organization(session, test_org) or { fail('create organization: ${err}') }
	add_organization_member(session, test_org, test_other_user) or {
		fail('add organization member: ${err}')
	}
	create_repo_with_owner(session, test_org_repo, 'private', test_org) or {
		fail('create private organization repo: ${err}')
	}

	rid := fetch_test_repo_id() or { fail('fetch repo id: ${err}') }
	os.setenv(env_repo_id, rid.str(), true)
}

fn testsuite_end() {
	kill_test_gitly()
	cleanup_test_state()
}

@[noreturn]
fn fail(msg string) {
	log.error('api endpoints_test: ${msg}')
	kill_test_gitly()
	cleanup_test_state()
	exit(1)
}

fn chdir_to_project_root() {
	project_root := os.real_path(os.join_path(os.dir(@FILE), '..'))
	os.chdir(project_root) or { fail('chdir to project root ${project_root}: ${err}') }
}

fn cleanup_test_state() {
	if os.exists(test_binary) {
		os.rm(test_binary) or {}
	}
	for ext in ['', '-shm', '-wal'] {
		path := test_sqlite_path + ext
		if os.exists(path) {
			os.rm(path) or {}
		}
	}
	for user in [test_username, test_other_user, test_org] {
		repo_path := os.join_path('repos', user)
		if os.exists(repo_path) {
			os.rmdir_all(repo_path) or {}
		}
	}
}

fn ensure_gitly_binary() {
	log.info('building ${test_binary} ...')
	res := os.execute('v -d sqlite -d use_libbacktrace -d use_openssl -o ${test_binary} .')
	if res.exit_code != 0 {
		fail('failed to build gitly: ${res.output}')
	}
}

fn spawn_test_gitly() {
	os.setenv('GITLY_PORT', test_port.str(), true)
	os.setenv('GITLY_SQLITE_PATH', test_sqlite_path, true)
	spawn fn () {
		os.execute('./${test_binary}')
	}()
}

fn wait_for_test_gitly() {
	for i := 0; i < 100; i++ {
		time.sleep(100 * time.millisecond)
		http.get(test_url + '/') or { continue }
		return
	}
	fail('gitly did not start listening on ${test_url}')
}

fn kill_test_gitly() {
	os.execute('pkill -9 ${test_binary}')
}

// -- helpers ------------------------------------------------------------------
fn url(path string) string {
	if path.starts_with('/') {
		return '${test_url}${path}'
	}
	return '${test_url}/${path}'
}

fn extract_token_cookie(h http.Header) string {
	for v in h.values(.set_cookie) {
		t := v.find_between('token=', ';')
		if t != '' {
			return t
		}
	}
	return ''
}

fn extract_cookie(h http.Header, name string) string {
	for v in h.values(.set_cookie) {
		value := v.find_between('${name}=', ';')
		if value != '' {
			return value
		}
	}
	return ''
}

fn register(username string, password string, email string) !string {
	body := 'username=${username}&password=${password}&email=${email}&no_redirect=1'
	resp := http.post(url('/register'), body)!
	if resp.status_code != 200 {
		return error('register returned ${resp.status_code}: ${resp.body}')
	}
	tok := extract_token_cookie(resp.header)
	if tok == '' {
		return error('no session token cookie in register response')
	}
	return tok
}

fn create_repo(token string, name string) ! {
	return create_repo_with_owner(token, name, 'public', test_username)
}

fn create_repo_with_owner(token string, name string, visibility string, owner string) ! {
	resp := http.fetch(
		method: .post
		url: url('/new')
		cookies: {
			'token': token
		}
		data: 'name=${name}&description=api+test&clone_url=&repo_visibility=${visibility}&owner=${owner}&no_redirect=1'
	)!
	if resp.status_code != 200 || resp.body != 'ok' {
		return error('unexpected response ${resp.status_code}: ${resp.body}')
	}
}

fn create_organization(token string, name string) ! {
	resp := http.fetch(
		method: .post
		url: url('/organizations/new')
		cookies: {
			'token': token
		}
		data: 'org_name=${name}&contact_email=org%40example.com&org_kind=personal&accept_terms=1'
		allow_redirect: false
	)!
	if resp.status_code != 302 && resp.status_code != 303 {
		return error('organization create returned ${resp.status_code}: ${resp.body}')
	}
}

fn add_organization_member(token string, org_name string, username string) ! {
	resp := http.fetch(
		method: .post
		url: url('/organizations/${org_name}/members')
		cookies: {
			'token': token
		}
		data: 'username=${username}&role=member'
		allow_redirect: false
	)!
	if resp.status_code != 302 && resp.status_code != 303 {
		return error('add organization member returned ${resp.status_code}: ${resp.body}')
	}
}

fn create_api_token(token string, username string) !string {
	return create_api_token_with_form(token, username, 'name=api-test&scope_api=on&expires_in_days=30')
}

fn create_api_token_with_form(token string, username string, form string) !string {
	resp := http.fetch(
		method: .post
		url: url('/${username}/settings/api-tokens')
		cookies: {
			'token': token
		}
		data: form
		allow_redirect: false
	)!
	if resp.status_code != 302 && resp.status_code != 303 {
		return error('expected redirect, got ${resp.status_code}: ${resp.body}')
	}
	location := resp.header.get(.location) or { return error('no Location header') }
	if location.contains('new_token=') {
		return error('API token leaked in redirect URL: ${location}')
	}
	plain := extract_cookie(resp.header, 'new_api_token')
	if plain == '' {
		return error('no one-time API token cookie in response')
	}
	return plain
}

fn fetch_test_repo_id() !int {
	resp := http.get(url('/api/v1/users/${test_username}/repos'))!
	if resp.status_code != 200 {
		return error('listing returned ${resp.status_code}')
	}
	repos := json.decode[[]ApiRepoSummary](resp.body)!
	for r in repos {
		if r.name == test_repo {
			return r.id
		}
	}
	return error('repo not found in listing')
}

pub struct ApiRepoSummary {
	id        int
	name      string
	user_name string
}

pub struct ApiUserSummary {
	id        int
	username  string
	full_name string
	avatar    string
}

pub struct ApiIssueSummary {
	id        int
	number    int
	repo_id   int
	title     string
	body      string
	author    string
	status    string
	assignees []string
	labels    []string
}

pub struct ApiLabelSummary {
	id    int
	name  string
	color string
}

pub struct ApiPullSummary {
	id          int
	repo_id     int
	title       string
	description string
	status      string
}

pub struct ApiCommentSummary {
	id     int
	author string
	text   string
}

pub struct ApiProjectMemberSummary {
	id           int
	user_id      int
	username     string
	role         string
	access_level int
}

pub struct ApiProtectedBranchSummary {
	id           int
	pattern      string
	push_access  int
	merge_access int
}

pub struct ApiBranchSummary {
	name         string
	hash         string
	is_default   bool
	is_protected bool
}

pub struct ApiBoolResult {
	success bool
	result  bool
}

pub struct ApiStatusSummary {
	success bool
	message string
}

pub struct ApiFilesResult {
	success bool
	result  []FileSummary
}

pub struct FileSummary {
	name      string
	last_msg  string
	last_hash string
	last_time string
	size      string
}

fn bearer_header() http.Header {
	return http.new_header(key: .authorization, value: 'Bearer ${bearer_token()}')
}

// -- tests --------------------------------------------------------------------
fn test_api_v1_me_requires_auth() {
	resp := http.get(url('/api/v1/me')) or { panic(err) }
	assert resp.status_code == 401
	error_response := json.decode[ApiStatusSummary](resp.body) or { panic(err) }
	assert !error_response.success
	assert error_response.message == 'authentication required'
	assert resp.body.contains('"success":false')
	assert !resp.body.contains('"success":"false"')
}

fn test_api_v1_me_with_bearer() {
	resp := http.fetch(
		method: .get
		url: url('/api/v1/me')
		header: bearer_header()
	) or { panic(err) }
	assert resp.status_code == 200
	user := json.decode[ApiUserSummary](resp.body) or { panic(err) }
	assert user.username == test_username
}

fn test_api_v1_read_only_token_cannot_mutate() {
	read_token := create_api_token_with_form(session_cookie(), test_username, 'name=read-only&scope_read_api=on&expires_in_days=7') or { panic(err) }
	read_header := http.new_header(key: .authorization, value: 'Bearer ${read_token}')
	me := http.fetch(
		method: .get
		url: url('/api/v1/me')
		header: read_header
	) or { panic(err) }
	assert me.status_code == 200

	star := http.fetch(
		method: .post
		url: url('/api/v1/repos/${repo_id()}/star')
		header: read_header
	) or { panic(err) }
	assert star.status_code == 401
}

fn test_api_v1_me_with_session_cookie() {
	resp := http.fetch(
		method: .get
		url: url('/api/v1/me')
		cookies: {
			'token': session_cookie()
		}
	) or { panic(err) }
	assert resp.status_code == 200
	user := json.decode[ApiUserSummary](resp.body) or { panic(err) }
	assert user.username == test_username
}

fn test_api_v1_user_lookup() {
	resp := http.get(url('/api/v1/users/${test_username}')) or { panic(err) }
	assert resp.status_code == 200
	user := json.decode[ApiUserSummary](resp.body) or { panic(err) }
	assert user.username == test_username

	missing := http.get(url('/api/v1/users/ghost_user')) or { panic(err) }
	assert missing.status_code == 404
}

fn test_api_v1_user_repos() {
	resp := http.get(url('/api/v1/users/${test_username}/repos')) or { panic(err) }
	assert resp.status_code == 200
	repos := json.decode[[]ApiRepoSummary](resp.body) or { panic(err) }
	assert repos.len >= 1
	mut found := false
	mut leaked_private := false
	for r in repos {
		if r.name == test_repo {
			found = true
		}
		if r.name == test_private_repo {
			leaked_private = true
		}
	}
	assert found
	assert !leaked_private

	token := os.getenv(env_bearer)
	owner_resp := http.fetch(
		method: .get
		url: url('/api/v1/users/${test_username}/repos')
		header: http.new_header(key: .authorization, value: 'Bearer ${token}')
	) or { panic(err) }
	assert owner_resp.status_code == 200
	owner_repos := json.decode[[]ApiRepoSummary](owner_resp.body) or { panic(err) }
	assert owner_repos.any(it.name == test_private_repo)
}

fn test_api_v1_repo_show() {
	resp := http.get(url('/api/v1/repos/${test_username}/${test_repo}')) or { panic(err) }
	assert resp.status_code == 200
	r := json.decode[ApiRepoSummary](resp.body) or { panic(err) }
	assert r.name == test_repo
	assert r.user_name == test_username

	missing := http.get(url('/api/v1/repos/${test_username}/nope')) or { panic(err) }
	assert missing.status_code == 404
}

fn test_api_v1_repo_issues_list_empty() {
	resp := http.get(url('/api/v1/repos/${test_username}/${test_repo}/issues')) or { panic(err) }
	assert resp.status_code == 200
	issues := json.decode[[]ApiIssueSummary](resp.body) or { panic(err) }
	assert issues.len == 0
}

fn test_api_v1_create_issue_requires_auth() {
	resp := http.post_form(url('/api/v1/repos/${test_username}/${test_repo}/issues'), {
		'title': 'should-fail'
		'body':  'no token'
	}) or { panic(err) }
	assert resp.status_code == 401
}

fn test_api_v1_create_issue_requires_title() {
	resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/issues')
		header: http.new_header_from_map({
			.authorization: 'Bearer ${bearer_token()}'
			.content_type:  'application/x-www-form-urlencoded'
		})
		data: 'body=missing-title'
	) or { panic(err) }
	assert resp.status_code == 400
	error_response := json.decode[ApiStatusSummary](resp.body) or { panic(err) }
	assert !error_response.success
	assert error_response.message.contains('title is required')
	assert resp.body.contains('"success":false')
}

fn test_api_v1_create_issue_succeeds() {
	resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/issues')
		header: http.new_header_from_map({
			.authorization: 'Bearer ${bearer_token()}'
			.content_type:  'application/x-www-form-urlencoded'
		})
		data: 'title=first-issue&body=hello'
	) or { panic(err) }
	assert resp.status_code == 200
	issue := json.decode[ApiIssueSummary](resp.body) or { panic(err) }
	assert issue.title == 'first-issue'
	assert issue.status == 'open'

	listing := http.get(url('/api/v1/repos/${test_username}/${test_repo}/issues')) or { panic(err) }
	issues := json.decode[[]ApiIssueSummary](listing.body) or { panic(err) }
	assert issues.len >= 1

	single := http.get(url('/api/v1/repos/${test_username}/${test_repo}/issues/${issue.id}')) or {
		panic(err)
	}
	assert single.status_code == 200
	got := json.decode[ApiIssueSummary](single.body) or { panic(err) }
	assert got.id == issue.id
}

fn test_api_v1_repo_issue_not_found() {
	resp := http.get(url('/api/v1/repos/${test_username}/${test_repo}/issues/99999')) or {
		panic(err)
	}
	assert resp.status_code == 404
}

fn test_api_v1_issue_comments_and_lifecycle() {
	listing := http.get(url('/api/v1/repos/${test_username}/${test_repo}/issues')) or { panic(err) }
	issues := json.decode[[]ApiIssueSummary](listing.body) or { panic(err) }
	issue := issues.filter(it.title == 'first-issue').first()

	created := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/issues/${issue.id}/comments')
		header: http.new_header_from_map({
			.authorization: 'Bearer ${bearer_token()}'
			.content_type:  'application/x-www-form-urlencoded'
		})
		data: 'text=API+comment'
	) or { panic(err) }
	assert created.status_code == 200

	comments_resp := http.get(url('/api/v1/repos/${test_username}/${test_repo}/issues/${issue.id}/comments')) or {
		panic(err)
	}
	comments := json.decode[[]ApiCommentSummary](comments_resp.body) or { panic(err) }
	assert comments.any(it.author == test_username && it.text == 'API comment')

	updated_resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/issues/${issue.id}')
		header: http.new_header_from_map({
			.authorization: 'Bearer ${bearer_token()}'
			.content_type:  'application/x-www-form-urlencoded'
		})
		data: 'title=edited-issue&body='
	) or { panic(err) }
	assert updated_resp.status_code == 200
	updated := json.decode[ApiIssueSummary](updated_resp.body) or { panic(err) }
	assert updated.title == 'edited-issue'
	assert updated.body == ''

	closed_resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/issues/${issue.id}/close')
		header: bearer_header()
	) or { panic(err) }
	assert closed_resp.status_code == 200
	closed := json.decode[ApiIssueSummary](closed_resp.body) or { panic(err) }
	assert closed.status == 'closed'

	reopened_resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/issues/${issue.id}/reopen')
		header: bearer_header()
	) or { panic(err) }
	reopened := json.decode[ApiIssueSummary](reopened_resp.body) or { panic(err) }
	assert reopened.status == 'open'
}

fn test_api_v1_project_labels_and_issue_assignment() {
	created_resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/labels')
		header: http.new_header_from_map({
			.authorization: 'Bearer ${bearer_token()}'
			.content_type:  'application/x-www-form-urlencoded'
		})
		data: 'name=bug&color=%23AABBCC'
	) or { panic(err) }
	assert created_resp.status_code == 200
	created := json.decode[ApiLabelSummary](created_resp.body) or { panic(err) }
	assert created.name == 'bug'
	assert created.color == '#aabbcc'

	listing_resp := http.get(url('/api/v1/repos/${test_username}/${test_repo}/labels')) or {
		panic(err)
	}
	assert listing_resp.status_code == 200
	labels := json.decode[[]ApiLabelSummary](listing_resp.body) or { panic(err) }
	assert labels.any(it.id == created.id && it.name == 'bug')

	updated_resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/labels/${created.id}')
		header: http.new_header_from_map({
			.authorization: 'Bearer ${bearer_token()}'
			.content_type:  'application/x-www-form-urlencoded'
		})
		data: 'name=confirmed&color=00ff00'
	) or { panic(err) }
	assert updated_resp.status_code == 200
	updated := json.decode[ApiLabelSummary](updated_resp.body) or { panic(err) }
	assert updated.name == 'confirmed'
	assert updated.color == '#00ff00'

	issues_resp := http.get(url('/api/v1/repos/${test_username}/${test_repo}/issues')) or {
		panic(err)
	}
	issues := json.decode[[]ApiIssueSummary](issues_resp.body) or { panic(err) }
	issue := issues.filter(it.title == 'edited-issue').first()
	assigned_resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/issues/${issue.id}/labels')
		header: http.new_header_from_map({
			.authorization: 'Bearer ${bearer_token()}'
			.content_type:  'application/x-www-form-urlencoded'
		})
		data: 'label_id=${created.id}'
	) or { panic(err) }
	assert assigned_resp.status_code == 200
	assigned := json.decode[ApiIssueSummary](assigned_resp.body) or { panic(err) }
	assert assigned.labels == ['confirmed']

	removed_resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/issues/${issue.id}/labels/${created.id}/delete')
		header: bearer_header()
	) or { panic(err) }
	assert removed_resp.status_code == 200
	removed := json.decode[ApiIssueSummary](removed_resp.body) or { panic(err) }
	assert removed.labels.len == 0

	deleted_resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/labels/${created.id}/delete')
		header: bearer_header()
	) or { panic(err) }
	assert deleted_resp.status_code == 200
}

fn test_api_v1_repo_pulls_empty() {
	resp := http.get(url('/api/v1/repos/${test_username}/${test_repo}/pulls')) or { panic(err) }
	assert resp.status_code == 200
	prs := json.decode[[]ApiPullSummary](resp.body) or { panic(err) }
	assert prs.len == 0
}

fn test_api_v1_repo_pull_not_found() {
	resp := http.get(url('/api/v1/repos/${test_username}/${test_repo}/pulls/1')) or { panic(err) }
	assert resp.status_code == 404
}

fn test_api_v1_pull_comments_not_found() {
	resp := http.get(url('/api/v1/repos/${test_username}/${test_repo}/pulls/1/comments')) or {
		panic(err)
	}
	assert resp.status_code == 404
}

fn test_api_v1_issues_count() {
	resp := http.fetch(
		method: .get
		url: url('/api/v1/${test_username}/${test_repo}/issues/count')
		header: bearer_header()
	) or { panic(err) }
	assert resp.status_code == 200
	decoded := json.decode[ApiIssueCount](resp.body) or { panic(err) }
	assert decoded.success
	assert decoded.result >= 1
}

fn test_api_v1_public_issues_count_is_accessible_unauthenticated() {
	resp := http.get(url('/api/v1/${test_username}/${test_repo}/issues/count')) or { panic(err) }
	decoded := json.decode[ApiIssueCount](resp.body) or { panic(err) }
	assert decoded.success
	assert decoded.result >= 1
}

fn test_api_v1_branches_count() {
	resp := http.fetch(
		method: .get
		url: url('/api/v1/${test_username}/${test_repo}/branches/count')
		header: bearer_header()
	) or { panic(err) }
	assert resp.status_code == 200
	decoded := json.decode[ApiBranchCount](resp.body) or { panic(err) }
	assert decoded.success
	assert decoded.result == 0
}

fn test_api_v1_repository_branch_management_validates_empty_repositories() {
	listing := http.get(url('/api/v1/repos/${test_username}/${test_repo}/branches')) or {
		panic(err)
	}
	assert listing.status_code == 200
	branches := json.decode[[]ApiBranchSummary](listing.body) or { panic(err) }
	assert branches.len == 0

	unauthorized := http.post_form(url('/api/v1/repos/${test_username}/${test_repo}/branches'), {
		'name':   'feature/api'
		'source': 'main'
	}) or { panic(err) }
	assert unauthorized.status_code == 401

	missing_source := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/branches')
		header: http.new_header_from_map({
			.authorization: 'Bearer ${bearer_token()}'
			.content_type:  'application/x-www-form-urlencoded'
		})
		data: 'name=feature%2Fapi&source=main'
	) or { panic(err) }
	assert missing_source.status_code == 400
	assert missing_source.body.contains('source revision')

	missing_delete := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/branches/delete')
		header: http.new_header_from_map({
			.authorization: 'Bearer ${bearer_token()}'
			.content_type:  'application/x-www-form-urlencoded'
		})
		data: 'name=feature%2Fmissing'
	) or { panic(err) }
	assert missing_delete.status_code == 400
}

fn test_api_v1_commits_count() {
	resp := http.fetch(
		method: .get
		url: url('/api/v1/${test_username}/${test_repo}/main/commits/count')
		header: bearer_header()
	) or { panic(err) }
	assert resp.status_code == 200
	decoded := json.decode[ApiCommitCount](resp.body) or { panic(err) }
	assert decoded.success
	assert decoded.result == 0
}

fn test_api_v1_count_endpoints_hide_unknown_and_private_repos() {
	unknown := http.get(url('/api/v1/ghost_user/ghost_repo/branches/count')) or { panic(err) }
	assert unknown.status_code == 404

	private := http.get(url('/api/v1/${test_username}/${test_private_repo}/issues/count')) or {
		panic(err)
	}
	assert private.status_code == 404
}

fn test_api_v1_repo_star_toggle() {
	rid := repo_id()
	resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${rid}/star')
		header: bearer_header()
	) or { panic(err) }
	assert resp.status_code == 200
	first := json.decode[ApiBoolResult](resp.body) or { panic(err) }
	assert first.success
	assert first.result == true

	resp2 := http.fetch(
		method: .post
		url: url('/api/v1/repos/${rid}/star')
		header: bearer_header()
	) or { panic(err) }
	second := json.decode[ApiBoolResult](resp2.body) or { panic(err) }
	assert second.result == false

	missing := http.fetch(
		method: .post
		url: url('/api/v1/repos/9999999/star')
		header: bearer_header()
	) or { panic(err) }
	assert missing.status_code == 404
}

fn test_api_v1_repo_watch_toggle() {
	rid := repo_id()
	resp := http.fetch(
		method: .post
		url: url('/api/v1/repos/${rid}/watch')
		header: bearer_header()
	) or { panic(err) }
	assert resp.status_code == 200
	first := json.decode[ApiBoolResult](resp.body) or { panic(err) }
	assert first.success
}

fn test_api_v1_repo_tree_files_requires_branch() {
	rid := repo_id()
	resp := http.get(url('/api/v1/repos/${rid}/tree/files')) or { panic(err) }
	assert resp.status_code == 400
	assert resp.body.contains('branch is required')
}

fn test_api_v1_repo_tree_files_with_branch() {
	rid := repo_id()
	resp := http.get(url('/api/v1/repos/${rid}/tree/files?branch=main')) or { panic(err) }
	assert resp.status_code == 200
	decoded := json.decode[ApiFilesResult](resp.body) or { panic(err) }
	assert decoded.success
}

fn test_api_v1_repo_tree_files_unknown_repo() {
	resp := http.get(url('/api/v1/repos/9999999/tree/files?branch=main')) or { panic(err) }
	assert resp.status_code == 404
	error_response := json.decode[ApiStatusSummary](resp.body) or { panic(err) }
	assert !error_response.success
}

fn test_api_v1_users_avatar_requires_auth() {
	resp := http.post_multipart_form(url('/api/v1/users/avatar'),
		files: {
			'file': [
				http.FileData{
					filename: 'a.png'
					content_type: 'image/png'
					data: 'x'
				},
			]
		}
	) or { panic(err) }
	assert resp.status_code == 404
}

fn test_api_v1_ci_status_callback_requires_signature() {
	rid := repo_id()
	payload := '{"run_id":"123","repo_id":"${rid}","commit_hash":"deadbeef","branch":"main","status":"running"}'
	resp := http.fetch(
		method: .post
		url: url('/api/v1/ci/status')
		header: http.new_header(key: .content_type, value: 'application/json')
		data: payload
	) or { panic(err) }
	assert resp.status_code == 401
	assert resp.body.contains('Invalid or missing CI callback signature')
}

fn test_api_v1_ci_status_callback_rejects_bad_json() {
	resp := http.fetch(
		method: .post
		url: url('/api/v1/ci/status')
		header: http.new_header(key: .content_type, value: 'application/json')
		data: 'not-json'
	) or { panic(err) }
	assert resp.status_code == 401
	assert resp.body.contains('Invalid or missing CI callback signature')
}

fn test_api_v1_private_repo_visibility_from_other_user() {
	// A second authenticated user can see the public test repo.
	resp := http.fetch(
		method: .get
		url: url('/api/v1/repos/${test_username}/${test_repo}')
		cookies: {
			'token': other_session_cookie()
		}
	) or { panic(err) }
	assert resp.status_code == 200

	private_resp := http.fetch(
		method: .get
		url: url('/api/v1/repos/${test_username}/${test_private_repo}')
		cookies: {
			'token': other_session_cookie()
		}
	) or { panic(err) }
	assert private_resp.status_code == 404
	private_label_create := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_private_repo}/labels')
		header: http.new_header_from_map({
			.content_type: 'application/x-www-form-urlencoded'
		})
		cookies: {
			'token': other_session_cookie()
		}
		data: 'name=hidden&color=ff0000'
	) or { panic(err) }
	assert private_label_create.status_code == 404
	private_branch_create := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_private_repo}/branches')
		header: http.new_header_from_map({
			.content_type: 'application/x-www-form-urlencoded'
		})
		cookies: {
			'token': other_session_cookie()
		}
		data: 'name=hidden&source=main'
	) or { panic(err) }
	assert private_branch_create.status_code == 404

	owner_resp := http.fetch(
		method: .get
		url: url('/api/v1/repos/${test_username}/${test_private_repo}')
		header: bearer_header()
	) or { panic(err) }
	assert owner_resp.status_code == 200
}

fn test_api_v1_organization_member_can_read_private_repo() {
	member_resp := http.fetch(
		method: .get
		url: url('/api/v1/repos/${test_org}/${test_org_repo}')
		cookies: {
			'token': other_session_cookie()
		}
	) or { panic(err) }
	assert member_resp.status_code == 200

	anon_resp := http.get(url('/api/v1/repos/${test_org}/${test_org_repo}')) or { panic(err) }
	assert anon_resp.status_code == 404
}

fn test_api_v1_project_members_and_role_based_private_access() {
	create := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_private_repo}/members')
		header: http.new_header_from_map({
			.authorization: 'Bearer ${bearer_token()}'
			.content_type:  'application/x-www-form-urlencoded'
		})
		data: 'username=${test_other_user}&role=reporter'
	) or { panic(err) }
	assert create.status_code == 200
	member := json.decode[ApiProjectMemberSummary](create.body) or { panic(err) }
	assert member.username == test_other_user
	assert member.role == 'reporter'
	assert member.access_level == 20

	listing := http.fetch(
		method: .get
		url: url('/api/v1/repos/${test_username}/${test_private_repo}/members')
		cookies: {
			'token': other_session_cookie()
		}
	) or { panic(err) }
	assert listing.status_code == 200
	members := json.decode[[]ApiProjectMemberSummary](listing.body) or { panic(err) }
	assert members.any(it.username == test_other_user && it.role == 'reporter')

	private_repo := http.fetch(
		method: .get
		url: url('/api/v1/repos/${test_username}/${test_private_repo}')
		cookies: {
			'token': other_session_cookie()
		}
	) or { panic(err) }
	assert private_repo.status_code == 200
}

fn test_api_v1_protected_branches() {
	create := http.fetch(
		method: .post
		url: url('/api/v1/repos/${test_username}/${test_repo}/protected-branches')
		header: http.new_header_from_map({
			.authorization: 'Bearer ${bearer_token()}'
			.content_type:  'application/x-www-form-urlencoded'
		})
		data: 'pattern=release%2F*&push_access=40&merge_access=30'
	) or { panic(err) }
	assert create.status_code == 200
	rule := json.decode[ApiProtectedBranchSummary](create.body) or { panic(err) }
	assert rule.pattern == 'release/*'
	assert rule.push_access == 40
	assert rule.merge_access == 30

	listing := http.fetch(
		method: .get
		url: url('/api/v1/repos/${test_username}/${test_repo}/protected-branches')
		header: bearer_header()
	) or { panic(err) }
	assert listing.status_code == 200
	rules := json.decode[[]ApiProtectedBranchSummary](listing.body) or { panic(err) }
	assert rules.any(it.pattern == 'main')
	assert rules.any(it.pattern == 'release/*')
}
