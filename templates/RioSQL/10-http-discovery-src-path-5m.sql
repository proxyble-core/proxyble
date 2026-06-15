# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_discovery_src_path_5m
RUNNING count, count_distinct
FROM http_log_on_request_completion.path
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
