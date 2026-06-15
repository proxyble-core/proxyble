# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_discovery_src_miss_5m
RUNNING count
FROM http_log_on_request_completion.status_code
WHEN status_code = 400
   OR status_code = 404
   OR status_code = 405
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
