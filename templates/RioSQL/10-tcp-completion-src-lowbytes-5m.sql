# Dependencies: 01-stream-tcp-on-completion.sql

CREATE WINDOW tcp_completion_src_lowbytes_5m
RUNNING count
FROM tcp_log_on_request_completion.bytes_sent
WHEN bytes_sent < 1024
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
