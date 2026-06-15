# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_analytics_global_10m
RUNNING count
FROM http_log_on_request_completion.source_ip
RANGE 10m;
