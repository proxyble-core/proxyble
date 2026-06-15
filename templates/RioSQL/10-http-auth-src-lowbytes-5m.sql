# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_auth_src_lowbytes_5m
RUNNING count
FROM http_log_on_request_completion.bytes_sent
WHEN bytes_sent < 1024
  AND (path LIKE '%login%'
    OR path LIKE '%token%'
    OR path LIKE '%auth%'
    OR path LIKE '%session%')
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
