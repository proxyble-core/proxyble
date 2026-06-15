# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_src_success_2m
RUNNING count
FROM http_log_on_request_completion.status_code
WHEN status_code >= 200
  AND status_code <= 399
PARTITION BY source_ip
  EXPIRE 45m
RANGE 2m;
