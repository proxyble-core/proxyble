# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_read_src_write_15m
RUNNING count
FROM http_log_on_request_completion.method
WHEN method = 'POST'
   OR method = 'PUT'
   OR method = 'PATCH'
   OR method = 'DELETE'
PARTITION BY source_ip
  EXPIRE 1h
RANGE 15m;
