module main

import time

// Visit retains the request attributes needed to investigate traffic sources.
// The values are captured before route dispatch, so unsuccessful requests are
// included too.
struct Visit {
mut:
	id         int @[primary; sql: serial]
	url        string
	referrer   string
	ip         string
	user_agent string
	created_at int
}

fn limit_visit_field(value string, max_runes int) string {
	runes := value.runes()
	return if runes.len > max_runes { runes[..max_runes].string() } else { value }
}

fn (mut app App) record_visit(url string, referrer string, ip string, user_agent string) ! {
	visit := Visit{
		url: limit_visit_field(url, max_visit_url_len)
		referrer: limit_visit_field(referrer, max_visit_referrer_len)
		ip: limit_visit_field(ip, max_visit_ip_len)
		user_agent: limit_visit_field(user_agent, max_visit_user_agent_len)
		created_at: int(time.now().unix())
	}

	sql app.db {
		insert visit into Visit
	}!
}
