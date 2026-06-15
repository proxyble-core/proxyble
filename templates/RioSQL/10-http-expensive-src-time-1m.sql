# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_expensive_src_time_1m
RUNNING count, sum, avg, max
FROM http_log_on_request_completion.total_time_ms
WHEN path LIKE '%search%'
   OR path LIKE '%report%'
   OR path LIKE '%export%'
   OR path LIKE '%mcp%'
   OR path LIKE '%ai%'
   OR path LIKE '%aggregate%'
   OR path LIKE '%batch%'
PARTITION BY source_ip
  EXPIRE 30m
RANGE 1m;
