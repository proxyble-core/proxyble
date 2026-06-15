# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_cache_src_fullurl_5m
RUNNING count, count_distinct
FROM http_log_on_request_completion.full_url
WHEN method = 'GET'
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
