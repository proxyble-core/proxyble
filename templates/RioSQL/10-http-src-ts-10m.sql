# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_src_ts_10m
RUNNING count, first, last
FROM http_log_on_request_completion.request_ts_ms
PARTITION BY source_ip
  EXPIRE 1h
RANGE 10m;
