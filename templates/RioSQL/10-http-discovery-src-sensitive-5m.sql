# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_discovery_src_sensitive_5m
RUNNING count, count_distinct
FROM http_log_on_request_completion.path
WHEN path LIKE '%admin%'
   OR path LIKE '%.env%'
   OR path LIKE '%config%'
   OR path LIKE '%backup%'
   OR path LIKE '%wp-%'
   OR path LIKE '%.php%'
   OR path LIKE '%.git%'
   OR path LIKE '%.svn%'
   OR path LIKE '%debug%'
   OR path LIKE '%internal%'
   OR path LIKE '%/old/%'
   OR path LIKE '%/v1/%'
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
