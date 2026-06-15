# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_hostile_src_malformed_15m
RUNNING count
FROM http_log_on_request_completion.status_code
WHEN status_code = 400
   OR status_code = 408
PARTITION BY source_ip
  EXPIRE 1h
RANGE 15m;
