# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_hostile_src_pattern_15m
RUNNING count, count_distinct
FROM http_log_on_request_completion.path
WHEN path LIKE '%.env%'
   OR path LIKE '%config%'
   OR path LIKE '%backup%'
   OR path LIKE '%/shell%'
   OR path LIKE '%../%'
   OR path LIKE '%admin%'
   OR path LIKE '%wp-%'
   OR path LIKE '%.php%'
   OR path LIKE '%.git%'
   OR path LIKE '%debug%'
PARTITION BY source_ip
  EXPIRE 1h
RANGE 15m;
