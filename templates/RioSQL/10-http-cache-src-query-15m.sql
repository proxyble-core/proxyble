# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_cache_src_query_15m
RUNNING count, count_distinct
FROM http_log_on_request_completion.query_string
WHEN method = 'GET'
PARTITION BY source_ip
  EXPIRE 1h
RANGE 15m;
