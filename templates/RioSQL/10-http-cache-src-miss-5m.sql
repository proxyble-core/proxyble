# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_cache_src_miss_5m
RUNNING count
FROM http_log_on_request_completion.cache_status
WHEN cache_status = 'MISS'
   OR cache_status = 'BYPASS'
   OR cache_status = 'EXPIRED'
   OR cache_status = 'DYNAMIC'
   OR x_cache = 'MISS'
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
