// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import time
import veb

enum PrStatus {
	open   = 0
	closed = 1
	merged = 2
}

struct PullRequest {
	id int @[primary; sql: serial]
mut:
	repo_id           int
	head_repo_id      int
	author_id         int
	title             string
	description       string
	head_branch       string
	base_branch       string
	status            int
	comments_count    int
	created_at        int
	merged_at         int
	merge_commit_hash string
	repo_author       string @[skip]
	repo_name         string @[skip]
}

struct PrComment {
	id int @[primary; sql: serial]
mut:
	pr_id      int
	author_id  int
	created_at int
	text       string
}

struct PrReview {
	id int @[primary; sql: serial]
mut:
	pr_id      int
	author_id  int
	state      int // 0 comment, 1 approved, 2 changes requested
	body       string
	created_at int
}

struct PrReviewComment {
	id int @[primary; sql: serial]
mut:
	pr_id       int
	author_id   int
	review_id   int // 0 if standalone (not part of a submitted review)
	file_path   string
	line_number int
	side        string // 'old' or 'new'
	text        string
	created_at  int
}

// An approval is current merge-gating state, separate from the immutable
// review timeline. The unique pair ensures one person can contribute at most
// one approval regardless of how many reviews they submit.
struct PrApproval {
	id                int @[primary; sql: serial]
	pr_id             int @[unique: 'pr_approval']
	user_id           int @[unique: 'pr_approval']
	approved_head_oid string
	created_at        int
}

struct PrApprovalView {
	approval PrApproval
	user     User
}

fn (p &PullRequest) is_open() bool {
	return p.status == int(PrStatus.open)
}

fn (p &PullRequest) is_merged() bool {
	return p.status == int(PrStatus.merged)
}

fn (p &PullRequest) is_closed() bool {
	return p.status == int(PrStatus.closed)
}

fn (p &PullRequest) status_label() string {
	return match unsafe { PrStatus(p.status) } {
		.open { 'Open' }
		.closed { 'Closed' }
		.merged { 'Merged' }
	}
}

fn (p &PullRequest) status_class() string {
	return match unsafe { PrStatus(p.status) } {
		.open { 'pr-status--open' }
		.closed { 'pr-status--closed' }
		.merged { 'pr-status--merged' }
	}
}

fn (p &PullRequest) relative_time() string {
	return time.unix(p.created_at).relative()
}

fn (p &PullRequest) head_ref() string {
	if p.head_repo_id > 0 && p.head_repo_id != p.repo_id {
		return 'refs/merge-requests/${p.id}/head'
	}
	return p.head_branch
}

fn (p &PullRequest) formatted_title() veb.RawHtml {
	parts := p.title.split('`')
	mut out := ''
	for idx, part in parts {
		if idx % 2 == 0 {
			out += html_escape_text(part)
		} else if idx == parts.len - 1 {
			out += '`' + html_escape_text(part)
		} else {
			out += '<code>' + html_escape_text(part) + '</code>'
		}
	}
	return out
}

fn (c &PrComment) relative() string {
	return time.unix(c.created_at).relative()
}

fn (r &PrReview) relative() string {
	return time.unix(r.created_at).relative()
}

fn (r &PrReview) state_label() string {
	return match r.state {
		1 { 'approved' }
		2 { 'requested changes' }
		else { 'commented' }
	}
}

fn (r &PrReview) state_class() string {
	return match r.state {
		1 { 'pr-review--approved' }
		2 { 'pr-review--changes' }
		else { 'pr-review--comment' }
	}
}

fn (rc &PrReviewComment) relative() string {
	return time.unix(rc.created_at).relative()
}

fn (mut app App) add_pull_request_with_created_at(repo_id int, author_id int, title string, description string, head string, base string, created_at int) !int {
	return app.add_pull_request_from_repo_with_created_at(repo_id, 0, author_id, title, description, head, base, created_at)
}

fn (mut app App) add_pull_request_from_repo_with_created_at(repo_id int, head_repo_id int,
	author_id int, title string, description string, head string, base string, created_at int) !int {
	return db_insert_returning_id(mut app.db, 'PullRequest', ['repo_id', 'head_repo_id', 'author_id',
		'title', 'description', 'head_branch', 'base_branch', 'status', 'comments_count', 'created_at',
		'merged_at', 'merge_commit_hash'], [repo_id.str(), head_repo_id.str(), author_id.str(),
		title, description, head, base, int(PrStatus.open).str(), '0', created_at.str(), '0', ''])
}

fn (mut app App) add_pull_request_from_repo(repo_id int, head_repo_id int, author_id int,
	title string, description string, head string, base string) !int {
	return app.add_pull_request_from_repo_with_created_at(repo_id, head_repo_id, author_id, title, description, head, base, int(time.now().unix()))
}

fn (mut app App) add_pull_request(repo_id int, author_id int, title string, description string, head string, base string) !int {
	return app.add_pull_request_with_created_at(repo_id, author_id, title, description, head, base, int(time.now().unix()))
}

fn (mut app App) add_imported_pull_request(repo_id int, author_id int, title string, description string, head string, base string, created_at int) !int {
	return app.add_pull_request_with_created_at(repo_id, author_id, title, description, head, base, created_at)
}

fn (mut app App) pull_request_exists_for_head(repo_id int, head string) bool {
	rows := sql app.db {
		select count from PullRequest where repo_id == repo_id && head_branch == head
	} or { 0 }
	return rows > 0
}

fn (mut app App) pull_request_exists_for_source(repo_id int, head_repo_id int, head string) bool {
	wanted := int(PrStatus.open)
	return sql app.db {
		select count from PullRequest where repo_id == repo_id && head_repo_id == head_repo_id
		&& head_branch == head && status == wanted
	} or { 0 } > 0
}

fn (mut app App) find_pull_request_by_id(pr_id int) ?PullRequest {
	rows := sql app.db {
		select from PullRequest where id == pr_id limit 1
	} or { []PullRequest{} }
	if rows.len == 0 {
		return none
	}
	return rows.first()
}

fn (mut app App) find_repo_pull_requests(repo_id int, pr_status PrStatus) []PullRequest {
	wanted := int(pr_status)
	return sql app.db {
		select from PullRequest where repo_id == repo_id && status == wanted order by created_at desc
	} or { []PullRequest{} }
}

fn (mut app App) find_user_pull_requests(user_id int) []PullRequest {
	return sql app.db {
		select from PullRequest where author_id == user_id order by created_at desc
	} or { []PullRequest{} }
}

fn (mut app App) get_repo_open_pr_count(repo_id int) int {
	wanted := int(PrStatus.open)
	return sql app.db {
		select count from PullRequest where repo_id == repo_id && status == wanted
	} or { 0 }
}

fn (mut app App) sync_repo_open_pr_count(repo_id int) ! {
	open_prs_count := app.get_repo_open_pr_count(repo_id)
	sql app.db {
		update Repo set nr_open_prs = open_prs_count where id == repo_id
	}!
}

fn (mut app App) set_pr_status(pr_id int, new_status PrStatus) ! {
	wanted := int(new_status)
	sql app.db {
		update PullRequest set status = wanted where id == pr_id
	}!
}

fn (mut app App) set_pr_merged(pr_id int, merge_hash string) ! {
	wanted := int(PrStatus.merged)
	merged_at := int(time.now().unix())
	sql app.db {
		update PullRequest set status = wanted, merge_commit_hash = merge_hash, merged_at = merged_at
		where id == pr_id
	}!
}

fn (mut app App) increment_pr_comments(pr_id int) ! {
	sql app.db {
		update PullRequest set comments_count = comments_count + 1 where id == pr_id
	}!
}

fn (mut app App) increment_repo_open_prs(repo_id int) ! {
	sql app.db {
		update Repo set nr_open_prs = nr_open_prs + 1 where id == repo_id
	}!
}

fn (mut app App) decrement_repo_open_prs(repo_id int) ! {
	sql app.db {
		update Repo set nr_open_prs = nr_open_prs - 1 where id == repo_id
	}!
}

fn (mut app App) add_pr_comment(pr_id int, author_id int, text string) ! {
	comment := PrComment{
		pr_id: pr_id
		author_id: author_id
		created_at: int(time.now().unix())
		text: text
	}
	sql app.db {
		insert comment into PrComment
	}!
}

fn (mut app App) get_pr_comments(pr_id int) []PrComment {
	return sql app.db {
		select from PrComment where pr_id == pr_id order by created_at
	} or { []PrComment{} }
}

fn (mut app App) add_pr_review(pr_id int, author_id int, state int, body string) !int {
	return db_insert_returning_id(mut app.db, 'PrReview', ['pr_id', 'author_id', 'state', 'body',
		'created_at'], [pr_id.str(), author_id.str(), state.str(), body,
		int(time.now().unix()).str()])
}

fn (mut app App) get_pr_reviews(pr_id int) []PrReview {
	return sql app.db {
		select from PrReview where pr_id == pr_id order by created_at
	} or { []PrReview{} }
}

fn (mut app App) approve_pull_request(pr_id int, user_id int) ! {
	if pr_id <= 0 || user_id <= 0 {
		return error('invalid approval')
	}
	pr := app.find_pull_request_by_id(pr_id) or { return error('merge request not found') }
	if !pr.is_open() {
		return error('merge request is not open')
	}
	repo := app.find_repo_by_id(pr.repo_id) or { return error('repository not found') }
	// Imported fork refs can lag their source. Refresh before resolving the OID
	// so the approval records the exact candidate the reviewer is approving.
	app.refresh_cross_fork_pr_head(repo, pr)!
	head_oid := app.pull_request_head_oid(pr)!
	now := int(time.now().unix())
	existing := sql app.db {
		select count from PrApproval where pr_id == pr_id && user_id == user_id
	}!
	if existing > 0 {
		sql app.db {
			update PrApproval set approved_head_oid = head_oid, created_at = now where pr_id == pr_id
			&& user_id == user_id
		}!
		return
	}
	approval := PrApproval{
		pr_id: pr_id
		user_id: user_id
		approved_head_oid: head_oid
		created_at: now
	}
	sql app.db {
		insert approval into PrApproval
	}!
}

fn (mut app App) revoke_pull_request_approval(pr_id int, user_id int) ! {
	sql app.db {
		delete from PrApproval where pr_id == pr_id && user_id == user_id
	}!
}

fn (mut app App) pull_request_approval_count(pr_id int) int {
	pr := app.find_pull_request_by_id(pr_id) or { return 0 }
	head_oid := app.pull_request_head_oid(pr) or { return 0 }
	return app.find_pull_request_approvals_for_head(pr, head_oid).len
}

fn (mut app App) user_approved_pull_request(pr_id int, user_id int) bool {
	pr := app.find_pull_request_by_id(pr_id) or { return false }
	head_oid := app.pull_request_head_oid(pr) or { return false }
	return app.user_approved_pull_request_at_head(pr_id, user_id, head_oid)
}

fn (app &App) user_approved_pull_request_at_head(pr_id int, user_id int, head_oid string) bool {
	if !is_full_git_oid(head_oid) {
		return false
	}
	count := sql app.db {
		select count from PrApproval where pr_id == pr_id && user_id == user_id
		&& approved_head_oid == head_oid
	} or { 0 }
	return count > 0
}

fn (mut app App) find_pull_request_approvals(pr_id int) []PrApprovalView {
	pr := app.find_pull_request_by_id(pr_id) or { return []PrApprovalView{} }
	head_oid := app.pull_request_head_oid(pr) or { return []PrApprovalView{} }
	return app.find_pull_request_approvals_for_head(pr, head_oid)
}

fn (mut app App) find_pull_request_approvals_for_head(pr PullRequest, head_oid string) []PrApprovalView {
	if !is_full_git_oid(head_oid) {
		return []PrApprovalView{}
	}
	repo := app.find_repo_by_id(pr.repo_id) or { return []PrApprovalView{} }
	pr_id := pr.id
	approvals := sql app.db {
		select from PrApproval where pr_id == pr_id && approved_head_oid == head_oid order by created_at
	} or { []PrApproval{} }
	mut result := []PrApprovalView{cap: approvals.len}
	for approval in approvals {
		user := app.get_user_by_id(approval.user_id) or { continue }
		if !user.is_registered || user.is_blocked || user.id == pr.author_id
			|| app.repo_access_level(user.id, repo) < project_access_developer {
			continue
		}
		result << PrApprovalView{
			approval: approval
			user: user
		}
	}
	return result
}

fn (mut app App) pull_request_approvals_satisfied(pr PullRequest, repo Repo) bool {
	head_oid := app.pull_request_head_oid(pr) or { return false }
	return app.pull_request_approvals_satisfied_at_head(pr, repo, head_oid)
}

fn (mut app App) pull_request_approvals_satisfied_at_head(pr PullRequest, repo Repo, head_oid string) bool {
	return app.approval_policies_satisfied_at_head(pr, repo, head_oid)
}

fn (app &App) pull_request_head_oid(pr PullRequest) !string {
	repo := app.find_repo_by_id(pr.repo_id) or { return error('repository not found') }
	head_oid := git_rev_parse(repo.git_dir, pr.head_ref())!
	if !is_full_git_oid(head_oid) {
		return error('merge request head is not a full object id')
	}
	return head_oid
}

fn is_full_git_oid(oid string) bool {
	if oid.len !in [40, 64] {
		return false
	}
	for ch in oid.to_lower() {
		if !ch.is_digit() && (ch < `a` || ch > `f`) {
			return false
		}
	}
	return true
}

fn (mut app App) clear_pull_request_approvals(pr_id int) ! {
	sql app.db {
		delete from PrApproval where pr_id == pr_id
	}!
}

// New commits invalidate approvals for every open merge request sourced from
// the updated branch. This mirrors GitLab's safe default and prevents approval
// of one revision from silently authorizing a different one.
fn (mut app App) clear_open_pr_approvals_for_head(repo_id int, branch string) ! {
	wanted := int(PrStatus.open)
	prs := sql app.db {
		select from PullRequest where
		(head_repo_id == repo_id || (head_repo_id == 0 && repo_id == repo_id))
		&& head_branch == branch && status == wanted
	} or { []PullRequest{} }
	for pr in prs {
		app.clear_pull_request_approvals(pr.id)!
	}
}

fn (mut app App) add_pr_review_comment(pr_id int, author_id int, review_id int, file_path string, line_number int, side string, text string) ! {
	c := PrReviewComment{
		pr_id: pr_id
		author_id: author_id
		review_id: review_id
		file_path: file_path
		line_number: line_number
		side: side
		text: text
		created_at: int(time.now().unix())
	}
	sql app.db {
		insert c into PrReviewComment
	}!
}

fn (mut app App) get_pr_review_comments(pr_id int) []PrReviewComment {
	return sql app.db {
		select from PrReviewComment where pr_id == pr_id order by created_at
	} or { []PrReviewComment{} }
}

fn (mut app App) delete_repo_pull_requests(repo_id int) ! {
	prs := sql app.db {
		select from PullRequest where repo_id == repo_id
	} or { []PullRequest{} }
	for pr in prs {
		pr_id := pr.id
		sql app.db {
			delete from PrApproval where pr_id == pr_id
		}!
		sql app.db {
			delete from PrComment where pr_id == pr_id
		}!
		sql app.db {
			delete from PrReview where pr_id == pr_id
		}!
		sql app.db {
			delete from PrReviewComment where pr_id == pr_id
		}!
	}
	sql app.db {
		delete from PullRequest where repo_id == repo_id
	}!
}
