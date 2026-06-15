# Dependencies: 01-stream-tcp-on-arrival.sql

CREATE WINDOW tcp_arrival_src_conn_10s
RUNNING count
FROM tcp_log_on_request_arrival.source_ip
PARTITION BY source_ip
  EXPIRE 30m
RANGE 10s;
