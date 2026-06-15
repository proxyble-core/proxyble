# Dependencies: 01-stream-tcp-on-arrival.sql

CREATE WINDOW tcp_arrival_src_current_1m
RUNNING count, max
FROM tcp_log_on_request_arrival.source_conn_cur
PARTITION BY source_ip
  EXPIRE 30m
RANGE 1m;
