# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_mcp_src_error_5m
RUNNING count
FROM http_log_on_request_completion.status_code
WHEN (status_code = 429 OR status_code >= 500)
  AND (path LIKE '%mcp%'
    OR length(mcp_tool_name) > 0)
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
