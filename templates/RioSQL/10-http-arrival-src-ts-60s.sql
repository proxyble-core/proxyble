# Dependencies: 01-stream-http-on-arrival.sql

CREATE WINDOW http_arrival_src_ts_60s
RUNNING count, first, last
FROM http_log_on_request_arrival.request_ts_ms
PARTITION BY source_ip
  EXPIRE 30m
RANGE 60s;
