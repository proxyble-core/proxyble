# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_mcp_src_tool_5m
RUNNING count, count_distinct
FROM http_log_on_request_completion.mcp_tool_name
WHEN path LIKE '%mcp%'
   OR length(mcp_tool_name) > 0
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
