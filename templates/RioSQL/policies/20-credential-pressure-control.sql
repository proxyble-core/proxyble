# Policy: Credential Pressure Control
# Policy ID: credential_pressure_control
# Summary: Detects credential stuffing and password guessing against login, token, auth, and session endpoints.
# Threat: Credential stuffing and password guessing create account takeover risk and noisy auth infrastructure load.
# Detection Signals: High auth request volume; elevated 401 or 403; many failed attempts from one source; low response bytes; regular timing.
# Metrics Layer: on request-completion
# Visibility: http,https
# Severity: HIGH
# Priority: HIGH
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-auth-src-total-1m.sql
# - 10-http-auth-src-total-5m.sql
# - 10-http-auth-src-total-30m.sql
# - 10-http-auth-src-fail-1m.sql
# - 10-http-auth-src-fail-5m.sql
# - 10-http-auth-src-loginid-5m.sql
# - 10-http-auth-src-lowbytes-5m.sql

SELECT  concat('LIMIT_ENDPOINT_RATE ', h.source_ip, ' 10/second /login,/token,/auth,/session 15m')
FROM    http_log_on_request_completion h,
        http_auth_src_total_1m a1,
        http_auth_src_total_5m a5,
        http_auth_src_total_30m b30,
        http_auth_src_fail_1m f1,
        http_auth_src_fail_5m f5,
        http_auth_src_lowbytes_5m low5
WHEN    (a5.count >= 20 AND f5.count * 100 >= a5.count * 70)
     OR (a1.count >= 12 AND f1.count >= 8)
     OR (b30.is_full
         AND a5.count > ((b30.count / 6) * 5)
         AND f5.count * 100 >= a5.count * 60)
     OR (a5.count >= 20
         AND f5.count * 100 >= a5.count * 50
         AND low5.count * 100 >= a5.count * 70)
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   15m ON PARTITION a5;

SELECT  concat('REJECT ', h.source_ip, ' 30m')
FROM    http_log_on_request_completion h,
        http_auth_src_fail_5m f5,
        http_auth_src_loginid_5m ids
WHEN    f5.count >= 30
AND     ids.count_distinct >= 10
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   30m ON PARTITION f5;
