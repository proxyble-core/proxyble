# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_src_flood_error_30s
RUNNING count
FROM http_log_on_request_completion.status_code
WHEN status_code = 429
   OR status_code >= 500
PARTITION BY source_ip
  EXPIRE 30m
RANGE 30s;
