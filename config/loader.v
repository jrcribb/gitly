module config

import os
import x.json2 as json

pub struct Config {
pub:
	repo_storage_path string
	archive_path      string
	avatars_path      string
	hostname          string
	ci_service_url    string
	// ci_callback_url is the externally reachable callback endpoint handed to
	// the CI service. When empty, Gitly derives it from hostname and
	// cookie_secure.
	ci_callback_url string
	usdt_wallet     string
	// ci_secret is the shared secret used to authenticate CI status callbacks
	// from gitly_ci (HMAC-SHA256 over the request body). Must match gitly_ci's
	// ci_secret. When empty, callbacks fail closed.
	ci_secret string
	// Set when Gitly is served over HTTPS so authentication and one-time-secret
	// cookies are never sent over a clear-text connection.
	cookie_secure bool
	// storage_secret encrypts mirror credentials at rest. Credentialed mirrors
	// fail closed when this is empty.
	storage_secret       string
	mirror_allowed_hosts []string
	// Binary artifacts use a content-addressed local store by default. Setting
	// object_storage_url switches to an authenticated HTTP object-store adapter.
	object_storage_path            string
	object_storage_url             string
	object_storage_token           string
	max_package_size_bytes         i64 = 524288000
	dependency_proxy_allowed_hosts []string
	instance_id                    string
	ssh_enabled                    bool
	ssh_hostname                   string
	ssh_port                       int = 22
	ssh_user                       string = 'git'
	ssh_authorized_keys_path       string
	port                           int
	pg                             PgConfig
	sqlite                         SqliteConfig
}

pub struct PgConfig {
pub:
	host     string = 'localhost'
	port     int = 5432
	dbname   string = 'gitly'
	user     string = 'gitly'
	password string = 'gitly'
	conninfo string
}

pub struct SqliteConfig {
pub:
	path string = 'gitly.sqlite'
}

pub fn read_config(path string) !Config {
	config_raw := os.read_file(path)!
	base := json.decode[Config](config_raw)!

	return Config{
		repo_storage_path: env_or('GITLY_REPO_STORAGE_PATH', base.repo_storage_path)
		archive_path: env_or('GITLY_ARCHIVE_PATH', base.archive_path)
		avatars_path: env_or('GITLY_AVATARS_PATH', base.avatars_path)
		hostname: env_or('GITLY_HOSTNAME', base.hostname)
		ci_service_url: env_or('GITLY_CI_SERVICE_URL', base.ci_service_url)
		ci_callback_url: env_or('GITLY_CI_CALLBACK_URL', base.ci_callback_url)
		usdt_wallet: base.usdt_wallet
		ci_secret: env_or('GITLY_CI_SECRET', base.ci_secret)
		cookie_secure: base.cookie_secure
		storage_secret: env_or('GITLY_STORAGE_SECRET', base.storage_secret)
		mirror_allowed_hosts: env_list_or('GITLY_MIRROR_ALLOWED_HOSTS', base.mirror_allowed_hosts)
		object_storage_path: env_or('GITLY_OBJECT_STORAGE_PATH', base.object_storage_path)
		object_storage_url: env_or('GITLY_OBJECT_STORAGE_URL', base.object_storage_url)
		object_storage_token: env_or('GITLY_OBJECT_STORAGE_TOKEN', base.object_storage_token)
		max_package_size_bytes: env_i64_or('GITLY_MAX_PACKAGE_SIZE_BYTES', base.max_package_size_bytes)
		dependency_proxy_allowed_hosts: env_list_or('GITLY_DEPENDENCY_PROXY_ALLOWED_HOSTS', base.dependency_proxy_allowed_hosts)
		instance_id: env_or('GITLY_INSTANCE_ID', base.instance_id)
		ssh_enabled: env_bool_or('GITLY_SSH_ENABLED', base.ssh_enabled)
		ssh_hostname: env_or('GITLY_SSH_HOSTNAME', base.ssh_hostname)
		ssh_port: env_int_or('GITLY_SSH_PORT', base.ssh_port)
		ssh_user: env_or('GITLY_SSH_USER', base.ssh_user)
		ssh_authorized_keys_path: env_or('GITLY_SSH_AUTHORIZED_KEYS_PATH', base.ssh_authorized_keys_path)
		port: base.port
		pg: base.pg
		sqlite: base.sqlite
	}
}

fn env_bool_or(name string, fallback bool) bool {
	value := os.getenv(name).trim_space().to_lower()
	if value == '' {
		return fallback
	}
	return value in ['1', 'true', 'yes', 'on']
}

fn env_int_or(name string, fallback int) int {
	value := os.getenv(name).trim_space()
	return if value == '' { fallback } else { value.int() }
}

fn env_i64_or(name string, fallback i64) i64 {
	value := os.getenv(name).trim_space()
	return if value == '' { fallback } else { value.i64() }
}

fn env_or(name string, fallback string) string {
	value := os.getenv(name)
	return if value != '' { value } else { fallback }
}

fn env_list_or(name string, fallback []string) []string {
	value := os.getenv(name).trim_space()
	if value == '' {
		return fallback
	}
	return value.split(',').map(it.trim_space().to_lower()).filter(it != '')
}
