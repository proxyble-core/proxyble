# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_mcp_src_session_15m
RUNNING count, count_distinct
FROM http_log_on_request_completion.mcp_session_id
WHEN path LIKE '%mcp%'
   OR length(mcp_session_id) > 0
PARTITION BY source_ip
  EXPIRE 1h
RANGE 15m;
