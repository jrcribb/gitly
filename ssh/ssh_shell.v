module main

import os
import config
import git
import time

fn cli_app(config_path string) !&App {
	conf := config.read_config(config_path)!
	return &App{
		db:     connect_db(conf)!
		config: conf
	}
}

fn ssh_environment(app &App, repo Repo, access_level int, protected_branch_grants string,
	config_path string) map[string]string {
	return {
		'GITLY_PROTECTED_BRANCH_RULES': app.protected_branch_rules_env(repo.id)
		'GITLY_PROTECTED_BRANCH_GRANTS': protected_branch_grants
		'GITLY_USER_ACCESS_LEVEL':      access_level.str()
		'GITLY_RUN_POST_RECEIVE':       '1'
		'GITLY_EXECUTABLE':             os.executable()
		'GITLY_REPO_ID':                repo.id.str()
		'GITLY_CONFIG_PATH':            os.real_path(config_path)
	}
}

fn deploy_key_access_level(key DeployKey) int {
	if !key.can_push {
		return project_access_reporter
	}
	return project_access_developer
}

fn run_ssh_shell(kind string, key_id int, config_path string) int {
	if kind !in ['user', 'deploy'] || key_id <= 0 || config_path.trim_space() == '' {
		eprintln('Gitly: invalid SSH identity')
		return 1
	}
	mut app := cli_app(config_path) or {
		eprintln('Gitly: service unavailable')
		return 1
	}
	defer {
		app.db.close() or {}
	}
	target := parse_ssh_original_command(os.getenv('SSH_ORIGINAL_COMMAND')) or {
		eprintln('Gitly: interactive shell access is disabled')
		return 1
	}
	repo := app.find_repo_by_name_and_username(target.repo_name, target.owner) or {
		eprintln('Gitly: repository not found')
		return 1
	}
	mut access_level := 0
	mut protected_branch_grants := ''
	if kind == 'user' {
		key := app.find_ssh_key_by_id(key_id) or {
			eprintln('Gitly: SSH key is not active')
			return 1
		}
		if !key.usable_for_auth(int(time.now().unix())) {
			eprintln('Gitly: SSH key is expired or not enabled for authentication')
			return 1
		}
		user := app.get_user_by_id(key.user_id) or {
			eprintln('Gitly: account not found')
			return 1
		}
		if !user.is_registered || user.is_blocked {
			eprintln('Gitly: account is unavailable')
			return 1
		}
		access_level = app.repo_access_level(user.id, repo)
		if target.service == 'git-upload-pack' && !app.user_has_repo_read_access(user.id, repo) {
			eprintln('Gitly: repository not found')
			return 1
		}
		if target.service == 'git-receive-pack' && access_level < project_access_developer {
			eprintln('Gitly: push access denied')
			return 1
		}
	} else {
		key := app.find_deploy_key_by_id(key_id) or {
			eprintln('Gitly: deploy key is not active')
			return 1
		}
		if !key.usable_for_auth(int(time.now().unix())) || key.repo_id != repo.id {
			eprintln('Gitly: repository not found')
			return 1
		}
		access_level = deploy_key_access_level(key)
		protected_branch_grants = app.deploy_key_protected_branch_grants_env(repo.id, key.id)
		if target.service == 'git-receive-pack' && !key.can_push {
			eprintln('Gitly: deploy key is read-only')
			return 1
		}
	}
	if target.service == 'git-receive-pack' {
		app.ensure_protected_branch_hook(repo) or {
			eprintln('Gitly: protected branch enforcement is unavailable')
			return 1
		}
	}
	app.mark_ssh_key_used(kind, key_id, ssh_client_ip(os.getenv('SSH_CONNECTION')))
	return run_git_service(repo, target, ssh_environment(app, repo, access_level,
		protected_branch_grants, config_path))
}

fn run_ssh_post_receive(repo_id int, config_path string) int {
	if repo_id <= 0 {
		return 1
	}
	updates := git.parse_post_receive_updates(os.get_lines()) or { return 1 }
	mut app := cli_app(config_path) or { return 1 }
	defer {
		app.db.close() or {}
	}
	app.update_repo_after_ref_changes(repo_id, updates) or { return 1 }
	for update in updates {
		branch := update.branch_name() or { continue }
		if !update.is_delete() {
			app.trigger_ci_if_configured(repo_id, branch)
		}
	}
	spawn run_push_mirrors(repo_id, app.config)
	return 0
}
