# Dependencies: 01-stream-http-on-arrival.sql

CREATE WINDOW http_arrival_src_post_5m
RUNNING count
FROM http_log_on_request_arrival.method
WHEN method = 'POST'
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
