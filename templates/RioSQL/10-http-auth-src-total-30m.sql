# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_auth_src_total_30m
RUNNING count
FROM http_log_on_request_completion.path
WHEN path LIKE '%login%'
   OR path LIKE '%token%'
   OR path LIKE '%auth%'
   OR path LIKE '%session%'
PARTITION BY source_ip
  EXPIRE 2h
RANGE 30m;
