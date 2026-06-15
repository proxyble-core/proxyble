# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_src_ts_30s
RUNNING count, first, last
FROM http_log_on_request_completion.request_ts_ms
PARTITION BY source_ip
  EXPIRE 30m
RANGE 30s;
