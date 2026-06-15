# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_expensive_src_timeout_5m
RUNNING count
FROM http_log_on_request_completion.status_code
WHEN (status_code = 408 OR status_code = 504)
  AND (path LIKE '%search%'
    OR path LIKE '%report%'
    OR path LIKE '%export%'
    OR path LIKE '%mcp%'
    OR path LIKE '%ai%'
    OR path LIKE '%aggregate%'
    OR path LIKE '%batch%')
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
