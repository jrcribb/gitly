// Copyright (c) 2019-2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
module main

import crypto.sha256
import time
import x.json2 as json

const security_scan_types = ['sast', 'dast', 'dependency', 'container', 'secret', 'license']
const security_severities = ['info', 'low', 'medium', 'high', 'critical']
const vulnerability_states = ['detected', 'confirmed', 'resolved', 'dismissed']

struct SecurityScan {
	id int @[primary; sql: serial]
mut:
	repo_id       int
	scan_type     string
	ref_name      string
	commit_sha    string
	status        string
	scanner       string
	report_format string
	created_by    int
	created_at    int
	finished_at   int
	error_message string
}

struct SecurityFinding {
	id int @[primary; sql: serial]
mut:
	repo_id          int @[unique: 'security_finding']
	fingerprint      string @[unique: 'security_finding']
	scan_id          int
	category         string
	severity         string
	title            string
	description      string
	location         string
	identifiers      string
	evidence         string
	state            string
	first_seen_at    int
	last_seen_at     int
	resolved_by      int
	resolved_at      int
	dismissal_reason string
}

struct SecurityPolicy {
	id int @[primary; sql: serial]
mut:
	repo_id             int
	name                string
	branch_pattern      string
	required_scan_types string
	blocked_severities  string
	max_scan_age_hours  int
	allowed_licenses    string
	block_unresolved    bool
	enabled             bool
	created_by          int
	created_at          int
	updated_at          int
}

struct MergeApprovalPolicy {
	id int @[primary; sql: serial]
mut:
	repo_id            int
	name               string
	branch_pattern     string
	required_approvals int
	approver_role      string
	enabled            bool
	created_by         int
	created_at         int
}

struct ComplianceFramework {
	id int @[primary; sql: serial]
mut:
	name         string @[unique]
	description  string
	requirements string
	created_by   int
	created_at   int
}

struct RepoComplianceFramework {
	id int @[primary; sql: serial]
mut:
	repo_id      int @[unique]
	framework_id int
	assigned_by  int
	assigned_at  int
}

struct AuditEvent {
	id int @[primary; sql: serial]
mut:
	scope_type  string
	scope_id    int
	actor_id    int
	action      string
	target_type string
	target_id   string
	details     string
	ip          string
	created_at  int
}

struct SecurityGateResult {
	allowed bool
	reasons []string
}

fn normalize_csv_values(raw string, allowed []string, allow_empty bool) !string {
	mut seen := map[string]bool{}
	mut values := []string{}
	for part in raw.split(',') {
		value := part.trim_space().to_lower()
		if value == '' {
			continue
		}
		if allowed.len > 0 && value !in allowed {
			return error('unsupported value `${value}`')
		}
		if !seen[value] {
			seen[value] = true
			values << value
		}
	}
	if !allow_empty && values.len == 0 {
		return error('at least one value is required')
	}
	return values.join(',')
}

fn (mut app App) start_security_scan(repo Repo, actor_id int, scan_type string, ref_name string,
	commit_sha string, scanner string, report_format string) !int {
	kind := scan_type.trim_space().to_lower()
	if app.repo_access_level(actor_id, repo) < project_access_developer || kind !in security_scan_types || !is_safe_ref(ref_name) || !is_git_object_id(commit_sha) || !valid_short_name(scanner)
		|| report_format.len > 100 {
		return error('invalid security scan or Developer access is required')
	}
	return db_insert_returning_id(mut app.db, 'SecurityScan', ['repo_id', 'scan_type', 'ref_name',
		'commit_sha', 'status', 'scanner', 'report_format', 'created_by', 'created_at', 'finished_at',
		'error_message'], [repo.id.str(), kind, ref_name, commit_sha, 'running',
		scanner.trim_space(), report_format.trim_space(), actor_id.str(),
		int(time.now().unix()).str(), '0', ''])
}

fn (app &App) find_security_scan(repo_id int, scan_id int) ?SecurityScan {
	rows := sql app.db {
		select from SecurityScan where repo_id == repo_id && id == scan_id limit 1
	} or { []SecurityScan{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) list_security_scans(repo_id int) []SecurityScan {
	return sql app.db {
		select from SecurityScan where repo_id == repo_id order by id desc limit 200
	} or { []SecurityScan{} }
}

fn security_finding_fingerprint(scan_type string, title string, location string,
	identifiers string) string {
	return sha256.sum('${scan_type}\x00${title}\x00${location}\x00${identifiers}'.bytes()).hex()
}

fn (mut app App) record_security_finding(scan SecurityScan, title string, description string,
	severity string, location string, identifiers string, evidence string,
	provided_fingerprint string) !SecurityFinding {
	level := severity.trim_space().to_lower()
	if scan.status != 'running' || !valid_title(title) || !valid_body(description)
		|| level !in security_severities || location.len > 2048 || identifiers.len > 4096
		|| evidence.len > max_body_len {
		return error('invalid security finding')
	}
	fingerprint := if provided_fingerprint == '' {
		security_finding_fingerprint(scan.scan_type, title.trim_space(), location, identifiers)
	} else {
		provided_fingerprint.trim_space().to_lower()
	}
	if !valid_lfs_oid(fingerprint) {
		return error('finding fingerprint must be a SHA-256 value')
	}
	now := int(time.now().unix())
	existing := sql app.db {
		select from SecurityFinding where repo_id == scan.repo_id && fingerprint == fingerprint limit 1
	}!
	if existing.len == 0 {
		id := db_insert_returning_id(mut app.db, 'SecurityFinding', ['repo_id', 'fingerprint',
			'scan_id', 'category', 'severity', 'title', 'description', 'location', 'identifiers',
			'evidence', 'state', 'first_seen_at', 'last_seen_at', 'resolved_by', 'resolved_at',
			'dismissal_reason'], [scan.repo_id.str(), fingerprint, scan.id.str(), scan.scan_type,
			level, title.trim_space(), description, location, identifiers, evidence, 'detected',
			now.str(), now.str(), '0', '0', ''])!
		return app.find_security_finding(scan.repo_id, id) or {
			return error('security finding was not saved')
		}
	}
	id := existing.first().id
	state := if existing.first().state in ['resolved', 'dismissed'] {
		'detected'
	} else {
		existing.first().state
	}
	zero := 0
	empty := ''
	sql app.db {
		update SecurityFinding set scan_id = scan.id, category = scan.scan_type, severity = level,
		title = title, description = description, location = location, identifiers = identifiers,
		evidence = evidence, state = state, last_seen_at = now, resolved_by = zero,
		resolved_at = zero, dismissal_reason = empty where id == id
	}!
	return app.find_security_finding(scan.repo_id, id) or {
		return error('security finding was not updated')
	}
}

fn (app &App) find_security_finding(repo_id int, id int) ?SecurityFinding {
	rows := sql app.db {
		select from SecurityFinding where repo_id == repo_id && id == id limit 1
	} or { []SecurityFinding{} }
	if rows.len != 1 {
		return none
	}
	return rows.first()
}

fn (app &App) list_security_findings(repo_id int) []SecurityFinding {
	return sql app.db {
		select from SecurityFinding where repo_id == repo_id order by id desc limit 1000
	} or { []SecurityFinding{} }
}

fn (mut app App) finish_security_scan(scan SecurityScan, succeeded bool, error_message string) ! {
	if scan.status != 'running' || error_message.len > 4096 {
		return error('security scan is not running or the error is too long')
	}
	status := if succeeded { 'success' } else { 'failed' }
	finished := int(time.now().unix())
	sql app.db {
		update SecurityScan set status = status, finished_at = finished,
		error_message = error_message where id == scan.id && repo_id == scan.repo_id
	}!
}

fn (mut app App) set_vulnerability_state(repo_id int, finding_id int, actor_id int, state string,
	reason string) ! {
	clean := state.trim_space().to_lower()
	if clean !in vulnerability_states || reason.len > 4096 {
		return error('invalid vulnerability state')
	}
	app.find_security_finding(repo_id, finding_id) or { return error('finding not found') }
	now := if clean in ['resolved', 'dismissed'] { int(time.now().unix()) } else { 0 }
	resolver := if now > 0 { actor_id } else { 0 }
	sql app.db {
		update SecurityFinding set state = clean, resolved_by = resolver, resolved_at = now,
		dismissal_reason = reason where id == finding_id && repo_id == repo_id
	}!
}

fn (mut app App) add_security_policy(repo Repo, actor_id int, name string, branch_pattern string,
	required_scan_types string, blocked_severities string, max_scan_age_hours int,
	allowed_licenses string, block_unresolved bool) !int {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer || !valid_short_name(name)
		|| !valid_protected_branch_pattern(branch_pattern) || max_scan_age_hours < 0
		|| max_scan_age_hours > 24 * 365 || allowed_licenses.len > 10000 {
		return error('invalid security policy or Maintainer access is required')
	}
	scans := normalize_csv_values(required_scan_types, security_scan_types, true)!
	severities := normalize_csv_values(blocked_severities, security_severities, true)!
	licenses := normalize_csv_values(allowed_licenses, [], true)!
	now := int(time.now().unix())
	return db_insert_returning_id(mut app.db, 'SecurityPolicy', ['repo_id', 'name', 'branch_pattern',
		'required_scan_types', 'blocked_severities', 'max_scan_age_hours', 'allowed_licenses',
		'block_unresolved', 'enabled', 'created_by', 'created_at', 'updated_at'], [
		repo.id.str(),
		name.trim_space(),
		branch_pattern.trim_space(),
		scans,
		severities,
		max_scan_age_hours.str(),
		licenses,
		db_bool_value(block_unresolved),
		db_bool_value(true),
		actor_id.str(),
		now.str(),
		now.str(),
	])
}

fn (app &App) list_security_policies(repo_id int) []SecurityPolicy {
	return sql app.db {
		select from SecurityPolicy where repo_id == repo_id order by id
	} or { []SecurityPolicy{} }
}

fn (mut app App) delete_security_policy(repo_id int, id int) ! {
	sql app.db {
		delete from SecurityPolicy where repo_id == repo_id && id == id
	}!
}

fn (app &App) security_gate(repo Repo, branch string, commit_sha string) SecurityGateResult {
	mut reasons := []string{}
	now := int(time.now().unix())
	for policy in app.list_security_policies(repo.id) {
		if !policy.enabled || !branch_pattern_matches(policy.branch_pattern, branch) {
			continue
		}
		for scan_type in policy.required_scan_types.split(',').filter(it != '') {
			scans := sql app.db {
				select from SecurityScan where repo_id == repo.id && scan_type == scan_type
				&& commit_sha == commit_sha order by id desc limit 1
			} or { []SecurityScan{} }
			if scans.len != 1 || scans.first().status != 'success' {
				reasons << 'A successful ${scan_type} scan is required by ${policy.name}.'
				continue
			}
			if policy.max_scan_age_hours > 0
				&& scans.first().finished_at < now - policy.max_scan_age_hours * 3600 {
				reasons << 'The ${scan_type} scan required by ${policy.name} is stale.'
			}
		}
		if policy.block_unresolved {
			blocked := policy.blocked_severities.split(',')
			for finding in app.list_security_findings(repo.id) {
				if finding.state in ['detected', 'confirmed'] && finding.severity in blocked {
					reasons << '${policy.name} blocks ${finding.severity} finding: ${finding.title}'
				}
			}
		}
		if policy.allowed_licenses != '' {
			allowed := policy.allowed_licenses.split(',')
			for finding in app.list_security_findings(repo.id) {
				if finding.category == 'license' && finding.state in ['detected', 'confirmed']
					&& finding.identifiers.to_lower() !in allowed {
					reasons << '${policy.name} does not allow license ${finding.identifiers}.'
				}
			}
		}
	}
	return SecurityGateResult{
		allowed: reasons.len == 0
		reasons: reasons
	}
}

fn (mut app App) enforce_security_gate(repo Repo, branch string, commit_sha string) ! {
	result := app.security_gate(repo, branch, commit_sha)
	if !result.allowed {
		return error(result.reasons.join(' '))
	}
}

fn (mut app App) add_merge_approval_policy(repo Repo, actor_id int, name string,
	branch_pattern string, required_approvals int, approver_role string) !int {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer || !valid_short_name(name)
		|| !valid_protected_branch_pattern(branch_pattern) || required_approvals < 0
		|| required_approvals > 100 || approver_role !in ['developer', 'maintainer'] {
		return error('invalid approval policy or Maintainer access is required')
	}
	return db_insert_returning_id(mut app.db, 'MergeApprovalPolicy', ['repo_id', 'name',
		'branch_pattern', 'required_approvals', 'approver_role', 'enabled', 'created_by', 'created_at'], [
		repo.id.str(),
		name.trim_space(),
		branch_pattern.trim_space(),
		required_approvals.str(),
		approver_role,
		db_bool_value(true),
		actor_id.str(),
		int(time.now().unix()).str(),
	])
}

fn (app &App) list_merge_approval_policies(repo_id int) []MergeApprovalPolicy {
	return sql app.db {
		select from MergeApprovalPolicy where repo_id == repo_id order by id
	} or { []MergeApprovalPolicy{} }
}

fn (mut app App) delete_merge_approval_policy(repo Repo, actor_id int, id int) ! {
	if app.repo_access_level(actor_id, repo) < project_access_maintainer {
		return error('Maintainer access is required')
	}
	sql app.db {
		delete from MergeApprovalPolicy where repo_id == repo.id && id == id
	}!
}

fn (app &App) required_approvals_for_branch(repo Repo, branch string) int {
	mut required := repo.required_approvals
	for policy in app.list_merge_approval_policies(repo.id) {
		if policy.enabled && branch_pattern_matches(policy.branch_pattern, branch)
			&& policy.required_approvals > required {
			required = policy.required_approvals
		}
	}
	return required
}

fn (mut app App) approval_policies_satisfied_at_head(pr PullRequest, repo Repo,
	head_oid string) bool {
	approvals := app.find_pull_request_approvals_for_head(pr, head_oid)
	if approvals.len < repo.required_approvals {
		return false
	}
	for policy in app.list_merge_approval_policies(repo.id) {
		if !policy.enabled || !branch_pattern_matches(policy.branch_pattern, pr.base_branch) {
			continue
		}
		minimum := project_role_access_level(policy.approver_role)
		eligible := approvals.filter(app.repo_access_level(it.user.id, repo) >= minimum).len
		if eligible < policy.required_approvals {
			return false
		}
	}
	return true
}

fn (mut app App) add_compliance_framework(name string, description string, requirements string,
	actor_id int) !int {
	if !valid_short_name(name) || !valid_body(description) || !valid_body(requirements)
		|| actor_id <= 0 {
		return error('invalid compliance framework')
	}
	return db_insert_returning_id(mut app.db, 'ComplianceFramework', ['name', 'description',
		'requirements', 'created_by', 'created_at'], [name.trim_space(), description, requirements,
		actor_id.str(), int(time.now().unix()).str()])
}

fn (app &App) list_compliance_frameworks() []ComplianceFramework {
	return sql app.db {
		select from ComplianceFramework order by name
	} or { []ComplianceFramework{} }
}

fn (mut app App) assign_compliance_framework(repo_id int, framework_id int, actor_id int) ! {
	frameworks := sql app.db {
		select from ComplianceFramework where id == framework_id limit 1
	}!
	if frameworks.len != 1 {
		return error('compliance framework not found')
	}
	existing := sql app.db {
		select from RepoComplianceFramework where repo_id == repo_id limit 1
	}!
	now := int(time.now().unix())
	if existing.len == 0 {
		row := RepoComplianceFramework{
			repo_id: repo_id
			framework_id: framework_id
			assigned_by: actor_id
			assigned_at: now
		}
		sql app.db {
			insert row into RepoComplianceFramework
		}!
	} else {
		sql app.db {
			update RepoComplianceFramework set framework_id = framework_id,
			assigned_by = actor_id, assigned_at = now where repo_id == repo_id
		}!
	}
}

fn (mut app App) record_audit_event(scope_type string, scope_id int, actor_id int, action string,
	target_type string, target_id string, details string, ip string) {
	if scope_type !in ['instance', 'group', 'project'] || scope_id < 0 || action.trim_space() == ''
		|| action.len > 255 || target_type.len > 100 || target_id.len > 255
		|| details.len > max_body_len {
		return
	}
	event := AuditEvent{
		scope_type: scope_type
		scope_id: scope_id
		actor_id: actor_id
		action: action.trim_space()
		target_type: target_type
		target_id: target_id
		details: details
		ip: ip[..if ip.len < 255 { ip.len } else { 255 }]
		created_at: int(time.now().unix())
	}
	sql app.db {
		insert event into AuditEvent
	} or {}
}

fn (app &App) list_audit_events(scope_type string, scope_id int, after_id int) []AuditEvent {
	return sql app.db {
		select from AuditEvent where scope_type == scope_type && scope_id == scope_id && id > after_id
		order by id limit 10000
	} or { []AuditEvent{} }
}

fn (app &App) export_audit_events(scope_type string, scope_id int, after_id int) string {
	return json.encode(app.list_audit_events(scope_type, scope_id, after_id))
}
