module main

import config

fn test_record_visit_persists_request_attribution() {
	$if sqlite ? {
		conf := config.Config{
			sqlite: config.SqliteConfig{
				path: ':memory:'
			}
		}
		mut app := App{
			db: connect_db(conf)!
		}
		defer {
			app.db.close() or {}
		}
		app.create_tables()!
		app.record_visit('/vlang/v/tree/main?tab=readme', 'https://search.example/results?q=vlang', '203.0.113.7', 'ExampleBrowser/1.0')!

		visits := sql app.db {
			select from Visit order by id
		}!
		assert visits.len == 1
		assert visits[0].url == '/vlang/v/tree/main?tab=readme'
		assert visits[0].referrer == 'https://search.example/results?q=vlang'
		assert visits[0].ip == '203.0.113.7'
		assert visits[0].user_agent == 'ExampleBrowser/1.0'
		assert visits[0].created_at > 0
	} $else {
		assert true
	}
}

fn test_record_visit_bounds_untrusted_header_values() {
	$if sqlite ? {
		conf := config.Config{
			sqlite: config.SqliteConfig{
				path: ':memory:'
			}
		}
		mut app := App{
			db: connect_db(conf)!
		}
		defer {
			app.db.close() or {}
		}
		app.create_tables()!
		app.record_visit('/' + 'u'.repeat(max_visit_url_len + 1), 'r'.repeat(max_visit_referrer_len + 1), 'i'.repeat(max_visit_ip_len + 1), 'a'.repeat(max_visit_user_agent_len + 1))!

		visits := sql app.db {
			select from Visit
		}!
		assert visits.len == 1
		assert visits[0].url.runes().len == max_visit_url_len
		assert visits[0].referrer.runes().len == max_visit_referrer_len
		assert visits[0].ip.runes().len == max_visit_ip_len
		assert visits[0].user_agent.runes().len == max_visit_user_agent_len
	} $else {
		assert true
	}
}
