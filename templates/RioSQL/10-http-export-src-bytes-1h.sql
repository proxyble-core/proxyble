# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_export_src_bytes_1h
RUNNING count, sum, avg, max
FROM http_log_on_request_completion.bytes_sent
WHEN path LIKE '%export%'
   OR path LIKE '%download%'
   OR path LIKE '%archive%'
   OR path LIKE '%report%'
   OR path LIKE '%backup%'
   OR path LIKE '%file%'
PARTITION BY source_ip
  EXPIRE 3h
RANGE 1h;
