# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_retry_src_failed_signature_30s
RUNNING count, count_distinct
FROM STRING (concat(http_log_on_request_completion.method, ' ', http_log_on_request_completion.full_url))
WHEN status_code = 429
   OR status_code = 503
   OR status_code >= 500
PARTITION BY source_ip
  EXPIRE 30m
RANGE 30s;
