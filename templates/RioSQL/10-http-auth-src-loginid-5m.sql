# Dependencies: 01-stream-http-on-completion.sql

CREATE WINDOW http_auth_src_loginid_5m
RUNNING count, count_distinct
FROM http_log_on_request_completion.login_identifier
WHEN (status_code = 401 OR status_code = 403)
  AND length(login_identifier) > 0
PARTITION BY source_ip
  EXPIRE 45m
RANGE 5m;
