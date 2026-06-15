# Policy: Legitimate Burst Protection
# Policy ID: legitimate_burst_protection
# Summary: Detects sharp but clean traffic bursts so Proxyble can apply short pressure relief instead of long bans.
# Threat: Marketing events, deploys, integrations, or customer jobs create short-lived spikes that should not trigger long bans.
# Detection Signals: Sharp temporary spike; high success rate; known event window; clean response mix; quick return toward baseline.
# Metrics Layer: on request-completion
# Visibility: tcp,http,https
# Severity: LOW
# Priority: MEDIUM
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-src-req-2m.sql
# - 10-http-src-req-30m.sql
# - 10-http-global-req-2m.sql
# - 10-http-global-req-30m.sql
# - 10-http-src-success-2m.sql
# - 10-http-src-client-server-error-2m.sql
# - 10-http-src-total-time-15m.sql

SELECT  concat('BUSY_DEFLECTION ', h.source_ip, ' 5m')
FROM    http_log_on_request_completion h,
        http_src_req_2m r2,
        http_src_req_30m b30,
        http_global_req_2m g2,
        http_global_req_30m gb30,
        http_src_success_2m ok2,
        http_src_client_server_error_2m err2,
        http_src_total_time_15m t15
WHEN    b30.is_full
AND     gb30.is_full
AND     r2.count >= ((b30.count / 15) * 3)
AND     g2.count >= ((gb30.count / 15) * 3)
AND     ok2.count * 100 >= r2.count * 90
AND     err2.count * 100 <= r2.count * 10
AND     t15.avg <= 3000
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   5m ON PARTITION r2;
