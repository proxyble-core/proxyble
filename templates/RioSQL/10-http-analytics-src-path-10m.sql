# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_analytics_src_path_10m
RUNNING count, count_distinct
FROM http_log_on_request_completion.path
PARTITION BY source_ip
  EXPIRE 1h
RANGE 10m;
