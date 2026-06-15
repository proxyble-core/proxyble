# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_read_src_get_15m
RUNNING count
FROM http_log_on_request_completion.method
WHEN method = 'GET'
  AND status_code >= 200
  AND status_code <= 299
  AND (path LIKE '%content%'
    OR path LIKE '%product%'
    OR path LIKE '%catalog%'
    OR path LIKE '%search%'
    OR path LIKE '%listing%'
    OR path LIKE '%docs%'
    OR path LIKE '%article%')
PARTITION BY source_ip
  EXPIRE 1h
RANGE 15m;
