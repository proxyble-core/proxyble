# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_read_src_url_15m
RUNNING count, count_distinct
FROM http_log_on_request_completion.full_url
WHEN method = 'GET'
  AND status_code >= 200
  AND status_code <= 299
PARTITION BY source_ip
  EXPIRE 1h
RANGE 15m;
