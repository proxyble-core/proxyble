# Dependencies: 01-stream-http-on-arrival.sql

CREATE WINDOW http_arrival_src_rate_usage_10s
RUNNING count, avg, max
FROM NUMBER ((http_log_on_request_arrival.endpoint_rate_current * 100) / http_log_on_request_arrival.endpoint_rate_limit)
WHEN endpoint_rate_limit > 0
PARTITION BY source_ip
  EXPIRE 30m
RANGE 10s;
