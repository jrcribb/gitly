module git

import strings
import net.http
import os
import time
import strconv

pub struct GitRefUpdate {
pub:
	old_hash string
	new_hash string
	ref_name string
}

pub fn (update GitRefUpdate) branch_name() ?string {
	if !update.ref_name.starts_with('refs/heads/') {
		return none
	}
	name := update.ref_name['refs/heads/'.len..]
	if name == '' {
		return none
	}
	return name
}

pub fn (update GitRefUpdate) tag_name() ?string {
	if !update.ref_name.starts_with('refs/tags/') {
		return none
	}
	name := update.ref_name['refs/tags/'.len..]
	if name == '' {
		return none
	}
	return name
}

pub fn (update GitRefUpdate) is_delete() bool {
	if !valid_object_id(update.new_hash) {
		return false
	}
	for ch in update.new_hash {
		if ch != `0` {
			return false
		}
	}
	return true
}

fn valid_object_id(value string) bool {
	if value.len !in [40, 64] {
		return false
	}
	for ch in value {
		if !(ch >= `0` && ch <= `9`) && !(ch >= `a` && ch <= `f`) {
			return false
		}
	}
	return true
}

fn is_hex_digit(ch u8) bool {
	return (ch >= `0` && ch <= `9`) || (ch >= `a` && ch <= `f`) || (ch >= `A` && ch <= `F`)
}

// parse_receive_updates reads only the pkt-line command section before the
// packfile. Parsing every command is security-sensitive: checking only the
// first ref lets a multi-ref push smuggle an update to a protected branch.
pub fn parse_receive_updates(upload string) ![]GitRefUpdate {
	mut updates := []GitRefUpdate{}
	mut offset := 0
	mut saw_flush := false
	for offset + 4 <= upload.len {
		prefix := upload[offset..offset + 4]
		for ch in prefix {
			if !is_hex_digit(ch) {
				return error('invalid pkt-line length')
			}
		}
		packet_len := int(strconv.parse_uint(prefix, 16, 16) or {
			return error('invalid pkt-line length')
		})
		if packet_len == 0 {
			saw_flush = true
			break
		}
		if packet_len < 4 || offset + packet_len > upload.len {
			return error('truncated pkt-line')
		}
		packet := upload[offset + 4..offset + packet_len]
		nul := packet.index_u8(0)
		command := if nul >= 0 { packet[..nul].trim_space() } else { packet.trim_space() }
		parts := command.fields()
		if parts.len != 3 || !valid_object_id(parts[0]) || !valid_object_id(parts[1])
			|| parts[0].len != parts[1].len || !parts[2].starts_with('refs/')
			|| parts[2].contains_any('\x00\r\n ') {
			return error('invalid receive command')
		}
		updates << GitRefUpdate{
			old_hash: parts[0]
			new_hash: parts[1]
			ref_name: parts[2]
		}
		offset += packet_len
	}
	if updates.len == 0 {
		return error('no receive commands')
	}
	if !saw_flush {
		return error('missing receive command flush packet')
	}
	return updates
}

pub fn receive_updates_accepted(response string) bool {
	return response.contains('unpack ok\n') && response.contains('ok refs/')
		&& !response.contains('ng refs/')
}

pub fn parse_post_receive_updates(lines []string) ![]GitRefUpdate {
	mut updates := []GitRefUpdate{}
	for line in lines {
		parts := line.trim_space().fields()
		if parts.len != 3 || !valid_object_id(parts[0]) || !valid_object_id(parts[1])
			|| !parts[2].starts_with('refs/') || parts[2].contains_any('\x00\r\n ') {
			return error('invalid post-receive command')
		}
		updates << GitRefUpdate{
			old_hash: parts[0]
			new_hash: parts[1]
			ref_name: parts[2]
		}
	}
	if updates.len == 0 {
		return error('no post-receive commands')
	}
	return updates
}

pub fn parse_branch_name_from_receive_upload(upload string) ?string {
	updates := parse_receive_updates(upload) or { return none }
	for update in updates {
		if branch := update.branch_name() {
			return branch
		}
	}
	return none
}

// parse_git_branch_with_last_hash parses output from `git branch -a`
// returns the branch name
pub fn parse_git_branch_output(output string) string {
	output_parts := output.fields()
	if output_parts.len == 0 {
		return ''
	}
	asterisk_or_branch_name := output_parts[0]
	if asterisk_or_branch_name == '*' {
		if output_parts.len < 2 || output_parts[1].starts_with('(HEAD') {
			return ''
		}
		return output_parts[1]
	}
	if output_parts.len > 1 && output_parts[1] == '->' {
		return ''
	}
	return output_parts[0]
}

pub fn flush_packet() string {
	return '0000'
}

pub fn write_packet(value string) string {
	packet_length := (value.len + 4).hex()
	return strings.repeat(`0`, 4 - packet_length.len) + packet_length + value
}

pub fn check_git_repo_url(url string) bool {
	refs_url := git_info_refs_url(url)
	mut headers := http.new_header()
	headers.add_custom('User-Agent', 'git/2.30.0') or {}
	headers.add_custom('Git-Protocol', 'version=2') or {}
	config := http.FetchConfig{
		url: refs_url
		header: headers
		read_timeout: 10 * time.second
		write_timeout: 10 * time.second
		allow_redirect: false
		max_retries: 1
		stop_receiving_limit: 1024 * 1024
	}
	response := http.fetch(config) or { return false }
	if response.status_code != 200 {
		return false
	}
	return response.body.contains('service=git-upload-pack')
}

fn git_info_refs_url(url string) string {
	// `.git` is part of the repository path on many servers. Only normalize a
	// trailing slash before appending the smart-HTTP discovery endpoint.
	repo_url := url.trim_string_right('/')
	return '${repo_url}/info/refs?service=git-upload-pack'
}

pub fn get_git_executable_path() ?string {
	return os.find_abs_path_of_executable('git') or { none }
}

pub fn remove_git_extension_if_exists(git_repository_name string) string {
	return git_repository_name.trim_string_right('.git')
}

fn get_branch_name_from_reference(value string) string {
	return value.after('refs/heads/')
}
