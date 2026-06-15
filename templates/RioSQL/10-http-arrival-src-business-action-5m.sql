# Dependencies: 01-stream-http-on-arrival.sql

CREATE WINDOW http_arrival_src_business_action_5m
RUNNING count, count_distinct
FROM http_log_on_request_arrival.path
WHEN path LIKE '%search%'
   OR path LIKE '%select%'
   OR path LIKE '%reserve%'
   OR path LIKE '%hold%'
   OR path LIKE '%checkout%'
   OR path LIKE '%vote%'
   OR path LIKE '%submit%'
   OR path LIKE '%create%'
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
