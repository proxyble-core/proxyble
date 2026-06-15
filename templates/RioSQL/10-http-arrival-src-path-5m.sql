# Dependencies: 01-stream-http-on-arrival.sql

CREATE WINDOW http_arrival_src_path_5m
RUNNING count, count_distinct
FROM http_log_on_request_arrival.path
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
