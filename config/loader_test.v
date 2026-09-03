module config

import os

fn test_read_config_uses_database_defaults() {
	path := os.join_path(os.temp_dir(), 'gitly_config_defaults_${os.getpid()}.json')
	os.write_file(path, '{"repo_storage_path":"./repos","archive_path":"./archives","avatars_path":"./avatars","hostname":"gitly.test","ci_service_url":"http://localhost:8081"}')!
	defer {
		os.rm(path) or {}
	}

	conf := read_config(path)!

	assert conf.pg.host == 'localhost'
	assert conf.pg.port == 5432
	assert conf.pg.dbname == 'gitly'
	assert conf.pg.user == 'gitly'
	assert conf.pg.password == 'gitly'
	assert conf.sqlite.path == 'gitly.sqlite'
	assert conf.usdt_wallet == ''
	assert conf.ci_secret == ''
	assert conf.ci_callback_url == ''
	assert !conf.cookie_secure
	assert conf.object_storage_path == ''
	assert conf.object_storage_url == ''
	assert conf.max_package_size_bytes == 524288000
	assert conf.dependency_proxy_allowed_hosts == []
}

fn test_read_config_allows_ci_callback_url_override() {
	path := os.join_path(os.temp_dir(), 'gitly_config_ci_callback_${os.getpid()}.json')
	os.write_file(path, '{"repo_storage_path":"./repos","archive_path":"./archives","avatars_path":"./avatars","hostname":"gitly.test","ci_service_url":"http://localhost:8081","ci_callback_url":"https://configured.test/api/v1/ci/status"}')!
	defer {
		os.rm(path) or {}
		os.unsetenv('GITLY_CI_CALLBACK_URL')
	}
	os.setenv('GITLY_CI_CALLBACK_URL', 'https://runtime.test/hooks/ci', true)
	conf := read_config(path)!
	assert conf.ci_callback_url == 'https://runtime.test/hooks/ci'
}

fn test_read_config_allows_runtime_path_overrides() {
	path := os.join_path(os.temp_dir(), 'gitly_config_env_${os.getpid()}.json')
	os.write_file(path, '{"repo_storage_path":"./repos","archive_path":"./archives","avatars_path":"./avatars","hostname":"gitly.test","ci_service_url":"http://localhost:8081"}')!
	defer {
		os.rm(path) or {}
		os.unsetenv('GITLY_REPO_STORAGE_PATH')
		os.unsetenv('GITLY_ARCHIVE_PATH')
		os.unsetenv('GITLY_AVATARS_PATH')
	}
	os.setenv('GITLY_REPO_STORAGE_PATH', '/tmp/gitly-test-repos', true)
	os.setenv('GITLY_ARCHIVE_PATH', '/tmp/gitly-test-archives', true)
	os.setenv('GITLY_AVATARS_PATH', '/tmp/gitly-test-avatars', true)
	conf := read_config(path)!
	assert conf.repo_storage_path == '/tmp/gitly-test-repos'
	assert conf.archive_path == '/tmp/gitly-test-archives'
	assert conf.avatars_path == '/tmp/gitly-test-avatars'
}

fn test_read_config_allows_ssh_and_mirror_runtime_overrides() {
	path := os.join_path(os.temp_dir(), 'gitly_config_transport_${os.getpid()}.json')
	os.write_file(path, '{"repo_storage_path":"./repos","archive_path":"./archives","avatars_path":"./avatars","hostname":"gitly.test","ci_service_url":"","mirror_allowed_hosts":[]}')!
	defer {
		os.rm(path) or {}
		for key in ['GITLY_STORAGE_SECRET', 'GITLY_SSH_ENABLED', 'GITLY_SSH_HOSTNAME',
			'GITLY_SSH_PORT', 'GITLY_SSH_USER', 'GITLY_SSH_AUTHORIZED_KEYS_PATH',
			'GITLY_MIRROR_ALLOWED_HOSTS'] {
			os.unsetenv(key)
		}
	}
	os.setenv('GITLY_STORAGE_SECRET', 'runtime-secret', true)
	os.setenv('GITLY_SSH_ENABLED', 'true', true)
	os.setenv('GITLY_SSH_HOSTNAME', 'ssh.gitly.test', true)
	os.setenv('GITLY_SSH_PORT', '2222', true)
	os.setenv('GITLY_SSH_USER', 'forge', true)
	os.setenv('GITLY_SSH_AUTHORIZED_KEYS_PATH', '/tmp/gitly-authorized-keys', true)
	os.setenv('GITLY_MIRROR_ALLOWED_HOSTS', 'git.internal.test, Mirror.Example ', true)
	conf := read_config(path)!
	assert conf.storage_secret == 'runtime-secret'
	assert conf.ssh_enabled
	assert conf.ssh_hostname == 'ssh.gitly.test'
	assert conf.ssh_port == 2222
	assert conf.ssh_user == 'forge'
	assert conf.ssh_authorized_keys_path == '/tmp/gitly-authorized-keys'
	assert conf.mirror_allowed_hosts == ['git.internal.test', 'mirror.example']
}

fn test_read_config_allows_platform_runtime_overrides() {
	path := os.join_path(os.temp_dir(), 'gitly_config_platform_${os.getpid()}.json')
	os.write_file(path, '{"repo_storage_path":"./repos","archive_path":"./archives","avatars_path":"./avatars","hostname":"gitly.test"}')!
	defer {
		os.rm(path) or {}
		for key in ['GITLY_OBJECT_STORAGE_PATH', 'GITLY_OBJECT_STORAGE_URL',
			'GITLY_OBJECT_STORAGE_TOKEN', 'GITLY_MAX_PACKAGE_SIZE_BYTES',
			'GITLY_DEPENDENCY_PROXY_ALLOWED_HOSTS', 'GITLY_INSTANCE_ID'] {
			os.unsetenv(key)
		}
	}
	os.setenv('GITLY_OBJECT_STORAGE_PATH', '/var/lib/gitly/objects', true)
	os.setenv('GITLY_OBJECT_STORAGE_URL', 'https://objects.example.test/gitly', true)
	os.setenv('GITLY_OBJECT_STORAGE_TOKEN', 'object-token', true)
	os.setenv('GITLY_MAX_PACKAGE_SIZE_BYTES', '1048576', true)
	os.setenv('GITLY_DEPENDENCY_PROXY_ALLOWED_HOSTS', 'registry.npmjs.org, Pypi.org ', true)
	os.setenv('GITLY_INSTANCE_ID', 'web-1', true)
	conf := read_config(path)!
	assert conf.object_storage_path == '/var/lib/gitly/objects'
	assert conf.object_storage_url == 'https://objects.example.test/gitly'
	assert conf.object_storage_token == 'object-token'
	assert conf.max_package_size_bytes == 1048576
	assert conf.dependency_proxy_allowed_hosts == ['registry.npmjs.org', 'pypi.org']
	assert conf.instance_id == 'web-1'
}
