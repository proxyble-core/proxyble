# Dependencies: 01-stream-http-on-arrival.sql

CREATE WINDOW http_arrival_business_global_5m
RUNNING count
FROM http_log_on_request_arrival.path
WHEN path LIKE '%search%'
   OR path LIKE '%select%'
   OR path LIKE '%reserve%'
   OR path LIKE '%hold%'
   OR path LIKE '%checkout%'
   OR path LIKE '%vote%'
   OR path LIKE '%submit%'
   OR path LIKE '%create%'
RANGE 5m;
