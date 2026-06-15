# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_global_req_2m
RUNNING count
FROM http_log_on_request_completion.source_ip
RANGE 2m;
