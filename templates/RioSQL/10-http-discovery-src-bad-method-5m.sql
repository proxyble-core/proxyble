# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_discovery_src_bad_method_5m
RUNNING count
FROM http_log_on_request_completion.method
WHEN NOT (method = 'GET'
       OR method = 'POST'
       OR method = 'PUT'
       OR method = 'PATCH'
       OR method = 'DELETE'
       OR method = 'OPTIONS'
       OR method = 'HEAD')
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
