# Policy: Expensive Endpoint Cost Control
# Policy ID: expensive_endpoint_cost_control
# Summary: Detects normal-looking request volumes that create excessive latency, compute cost, timeouts, or heavy response cost.
# Threat: Normal-looking request volume triggers expensive compute, database, third-party, or AI-provider costs.
# Detection Signals: Normal RPS with high latency; repeated heavy handlers; large responses; high error or timeout rate; expensive endpoint concentration.
# Metrics Layer: on request-completion
# Visibility: http,https
# Severity: MEDIUM
# Priority: HIGH
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-expensive-src-time-1m.sql
# - 10-http-expensive-src-time-5m.sql
# - 10-http-expensive-src-timeout-5m.sql
# - 10-http-expensive-src-error-5m.sql

SELECT  concat('LIMIT_ENDPOINT_RATE ', h.source_ip, ' 5/second /search,/report,/export,/mcp,/ai,/aggregate,/batch 15m')
FROM    http_log_on_request_completion h,
        http_expensive_src_time_1m e1,
        http_expensive_src_time_5m e5,
        http_expensive_src_timeout_5m to5,
        http_expensive_src_error_5m err5
WHEN    e1.sum > 120000
     OR (e5.count >= 20 AND e5.avg > 3000)
     OR to5.count >= 5
     OR (e5.count >= 10 AND err5.count * 100 >= e5.count * 30)
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   15m ON PARTITION e5;
