# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_slow_src_timeout_5m
RUNNING count
FROM http_log_on_request_completion.status_code
WHEN status_code = 408
   OR status_code = 504
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
