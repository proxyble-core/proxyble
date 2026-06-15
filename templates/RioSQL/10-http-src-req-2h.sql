# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_src_req_2h
RUNNING count
FROM http_log_on_request_completion.source_ip
PARTITION BY source_ip
  EXPIRE 4h
RANGE 2h;
