# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_slow_src_lowbytes_5m
RUNNING count
FROM http_log_on_request_completion.total_time_ms
WHEN total_time_ms > 30000
  AND bytes_sent < 1024
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
