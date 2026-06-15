# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_gray_src_rate_usage_5m
RUNNING count, avg, max
FROM NUMBER ((http_log_on_request_completion.endpoint_rate_current * 100) / http_log_on_request_completion.endpoint_rate_limit)
WHEN endpoint_rate_limit > 0
PARTITION BY source_ip
  EXPIRE 2h
RANGE 5m;
