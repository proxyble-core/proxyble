# Dependencies: 01-stream-tcp-on-completion.sql

CREATE WINDOW tcp_completion_src_session_5m
RUNNING count, sum, avg, max
FROM tcp_log_on_request_completion.session_duration_ms
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
