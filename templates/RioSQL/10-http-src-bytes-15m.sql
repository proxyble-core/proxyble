# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_src_bytes_15m
RUNNING count, sum, avg, max
FROM http_log_on_request_completion.bytes_sent
PARTITION BY source_ip
  EXPIRE 1h
RANGE 15m;
