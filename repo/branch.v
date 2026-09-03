module main

import time
import git

struct Branch {
mut:
	id           int @[primary; sql: serial]
	repo_id      int @[unique: 'branch']
	name         string @[unique: 'branch']
	author       string // author of latest commit on branch
	hash         string // hash of latest commit on branch
	date         int // time of latest commit on branch
	is_protected bool @[skip]
	can_delete   bool @[skip]
}

struct ApiBranchView {
	name         string
	hash         string
	author       string
	updated_at   int
	is_default   bool
	is_protected bool
}

fn (branch Branch) to_api(repo Repo) ApiBranchView {
	return ApiBranchView{
		name: branch.name
		hash: branch.hash
		author: branch.author
		updated_at: branch.date
		is_default: branch.name == repo.primary_branch
		is_protected: branch.is_protected
	}
}

fn is_safe_branch_name(name string) bool {
	return is_safe_ref(name) && !name.starts_with('refs/')
}

fn (mut app App) fetch_branches(repo Repo) ! {
	result := git.Git.exec_in_dir(repo.git_dir, ['for-each-ref', '--format=%(refname:short)',
		'refs/heads'])
	if result.exit_code != 0 {
		return error('could not list repository branches')
	}
	mut present := map[string]bool{}
	for line in result.output.split_into_lines() {
		branch_name := line.trim_space()
		if branch_name == '' || !is_safe_ref(branch_name) {
			continue
		}
		present[branch_name] = true
		app.fetch_branch(repo, branch_name)!
	}
	for existing in app.get_all_repo_branches(repo.id) {
		if existing.name !in present {
			app.delete_repo_branch_by_name(repo.id, existing.name)!
		}
	}
}

fn (mut app App) fetch_branch(repo Repo, branch_name string) ! {
	last_commit_hash := repo.get_last_branch_commit_hash(branch_name)

	branch_data := repo.git('log ${branch_name} -1 --pretty="%aE${log_field_separator}%cD" ${last_commit_hash}')
	log_parts := branch_data.split(log_field_separator)

	author_email := log_parts[0]
	committed_at := time.parse_rfc2822(log_parts[1]) or {
		app.info('Error: ${err}')

		return
	}

	user := app.get_user_by_email(author_email) or {
		User{
			username: author_email
		}
	}

	app.create_branch_or_update(repo.id, branch_name, user.username, last_commit_hash, int(committed_at.unix()))!
}

fn (mut app App) create_branch_or_update(repository_id int, branch_name string, author string, hash string, date int) ! {
	branches := sql app.db {
		select from Branch where repo_id == repository_id && name == branch_name limit 1
	} or { []Branch{} }

	// app.debug("branches: ${branches}")
	if branches.len != 0 {
		branch := branches.first()
		app.update_branch(branch.id, author, hash, date)!

		return
	}

	new_branch := Branch{
		repo_id: repository_id
		name: branch_name
		author: author
		hash: hash
		date: date
	}

	app.debug('inserting branch: ${new_branch}')

	sql app.db {
		insert new_branch into Branch
	}!
}

fn (mut app App) update_branch(branch_id int, author string, hash string, date int) ! {
	sql app.db {
		update Branch set author = author, hash = hash, date = date where id == branch_id
	}!
}

fn (mut app App) find_repo_branch_by_name(repo_id int, name string) Branch {
	branches := sql app.db {
		select from Branch where name == name && repo_id == repo_id limit 1
	} or { []Branch{} }

	if branches.len == 0 {
		return Branch{}
	}

	return branches.first()
}

fn (mut app App) find_repo_branch_by_id(repo_id int, id int) Branch {
	branches := sql app.db {
		select from Branch where id == id && repo_id == repo_id limit 1
	} or { []Branch{} }

	if branches.len == 0 {
		return Branch{}
	}

	return branches.first()
}

fn (app App) get_all_repo_branches(repo_id int) []Branch {
	return sql app.db {
		select from Branch where repo_id == repo_id order by date desc
	} or { []Branch{} }
}

fn (mut app App) get_count_repo_branches(repo_id int) int {
	return sql app.db {
		select count from Branch where repo_id == repo_id
	} or { 0 }
}

fn (mut app App) contains_repo_branch(repo_id int, name string) bool {
	count := sql app.db {
		select count from Branch where repo_id == repo_id && name == name
	} or { 0 }

	return count == 1
}

fn (mut app App) delete_repo_branches(repo_id int) ! {
	sql app.db {
		delete from Branch where repo_id == repo_id
	}!
}

fn (mut app App) delete_repo_branch_by_name(repo_id int, branch_name string) ! {
	branch := app.find_repo_branch_by_name(repo_id, branch_name)
	if branch.id == 0 {
		return
	}
	branch_id := branch.id
	sql app.db {
		delete from BranchCommit where branch_id == branch_id
	}!
	sql app.db {
		delete from Branch where id == branch_id && repo_id == repo_id
	}!
}

fn (mut app App) sync_repo_branch_count(repo_id int) ! {
	count := app.get_count_repo_branches(repo_id)
	sql app.db {
		update Repo set nr_branches = count where id == repo_id
	}!
}

fn (mut app App) create_repository_branch(repo Repo, name string, source string) !Branch {
	clean_name := name.trim_space()
	clean_source := source.trim_space()
	if !is_safe_branch_name(clean_name) || !is_safe_ref(clean_source) {
		return error('invalid branch name or source revision')
	}
	if app.contains_repo_branch(repo.id, clean_name) {
		return error('a branch with that name already exists')
	}
	source_result := git.Git.exec_in_dir(repo.git_dir, ['rev-parse', '--verify',
		'${clean_source}^{commit}'])
	if source_result.exit_code != 0 {
		return error('source revision does not resolve to a commit')
	}
	source_oid := source_result.output.trim_space()
	if !is_full_git_oid(source_oid) {
		return error('source revision does not resolve to a commit')
	}
	update_git_ref_expected(repo.git_dir, 'refs/heads/${clean_name}', source_oid, zero_oid_like(source_oid)!)!
	app.update_repo_branch_after_change(repo.id, clean_name) or {
		index_error := err
		// Keep the Git ref and relational branch index atomic from the caller's
		// perspective. The expected-old value prevents this rollback from deleting
		// a branch that another push advanced in the meantime.
		rollback := git.Git.exec_in_dir(repo.git_dir, ['update-ref', '-d',
			'refs/heads/${clean_name}', source_oid])
		if rollback.exit_code == 0 {
			app.delete_repo_branch_by_name(repo.id, clean_name) or {}
			app.sync_repo_branch_count(repo.id) or {}
		} else {
			// A concurrent push owns the ref now. Retain and re-index it rather than
			// deleting relational state for a branch that still exists.
			app.update_repo_branch_after_change(repo.id, clean_name) or {}
		}
		return error('branch could not be indexed: ${index_error}')
	}
	mut branch := app.find_repo_branch_by_name(repo.id, clean_name)
	if branch.id == 0 {
		return error('branch was created but could not be loaded')
	}
	branch.is_protected = app.branch_is_protected(repo.id, clean_name)
	return branch
}

fn (mut app App) delete_repository_branch(repo Repo, name string) ! {
	clean_name := name.trim_space()
	if !is_safe_branch_name(clean_name) {
		return error('invalid branch name')
	}
	if clean_name == repo.primary_branch {
		return error('the default branch cannot be deleted')
	}
	if app.branch_is_protected(repo.id, clean_name) {
		return error('protected branches cannot be deleted')
	}
	current_oid := git_rev_parse(repo.git_dir, 'refs/heads/${clean_name}')!
	if !is_full_git_oid(current_oid) {
		return error('branch does not resolve to a commit')
	}
	result := git.Git.exec_in_dir(repo.git_dir, ['update-ref', '-d', 'refs/heads/${clean_name}',
		current_oid])
	if result.exit_code != 0 {
		return error('branch changed while it was being deleted')
	}
	app.delete_repository_files_in_branch(repo.id, clean_name) or {
		delete_error := err
		app.restore_repository_branch(repo, clean_name, current_oid) or {
			return error('${delete_error}; branch restoration failed: ${err}')
		}
		return delete_error
	}
	app.clear_open_pr_approvals_for_head(repo.id, clean_name) or {
		delete_error := err
		app.restore_repository_branch(repo, clean_name, current_oid) or {
			return error('${delete_error}; branch restoration failed: ${err}')
		}
		return delete_error
	}
	app.delete_repo_branch_by_name(repo.id, clean_name) or {
		delete_error := err
		app.restore_repository_branch(repo, clean_name, current_oid) or {
			return error('${delete_error}; branch restoration failed: ${err}')
		}
		return delete_error
	}
	app.sync_repo_branch_count(repo.id) or {
		delete_error := err
		app.restore_repository_branch(repo, clean_name, current_oid) or {
			return error('${delete_error}; branch restoration failed: ${err}')
		}
		return delete_error
	}
}

fn (mut app App) restore_repository_branch(repo Repo, name string, oid string) ! {
	empty_oid := zero_oid_like(oid)!
	update_git_ref_expected(repo.git_dir, 'refs/heads/${name}', oid, empty_oid)!
	// Rebuild all derived branch rows that may have been changed before the
	// database error. Cleared approvals stay cleared, which is the safe outcome.
	app.update_repo_branch_after_change(repo.id, name)!
}

fn (branch Branch) relative() string {
	return time.unix(branch.date).relative()
}
