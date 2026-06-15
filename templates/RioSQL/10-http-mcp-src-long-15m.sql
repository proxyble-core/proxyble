# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_mcp_src_long_15m
RUNNING count
FROM http_log_on_request_completion.total_time_ms
WHEN total_time_ms > 30000
  AND (path LIKE '%mcp%'
    OR length(mcp_session_id) > 0)
PARTITION BY source_ip
  EXPIRE 1h
RANGE 15m;
