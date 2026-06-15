# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_discovery_src_miss_60s
RUNNING count
FROM http_log_on_request_completion.status_code
WHEN status_code = 400
   OR status_code = 404
   OR status_code = 405
PARTITION BY source_ip
  EXPIRE 30m
RANGE 60s;
