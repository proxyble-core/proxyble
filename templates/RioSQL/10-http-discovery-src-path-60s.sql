# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_discovery_src_path_60s
RUNNING count, count_distinct
FROM http_log_on_request_completion.path
PARTITION BY source_ip
  EXPIRE 30m
RANGE 60s;
