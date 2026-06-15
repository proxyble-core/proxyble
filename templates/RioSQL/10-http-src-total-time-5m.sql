# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_src_total_time_5m
RUNNING count, sum, avg, max
FROM http_log_on_request_completion.total_time_ms
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
