# Policy: Endpoint Discovery Control
# Policy ID: endpoint_discovery_control
# Summary: Detects route scanning, hidden endpoint probing, uncommon methods, and high 400/404/405 ratios.
# Threat: Scanners map hidden endpoints, deprecated routes, methods, and admin paths before deeper abuse.
# Detection Signals: Many unique paths; high 404 or 405; uncommon methods; low bytes returned; fast route variation.
# Metrics Layer: on request-completion
# Visibility: http,https
# Severity: HIGH
# Priority: HIGH
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-discovery-src-path-60s.sql
# - 10-http-discovery-src-path-5m.sql
# - 10-http-discovery-src-miss-60s.sql
# - 10-http-discovery-src-miss-5m.sql
# - 10-http-discovery-src-sensitive-5m.sql
# - 10-http-discovery-src-bad-method-5m.sql

SELECT  concat('LIMIT_ENDPOINT_RATE ', h.source_ip, ' 5/second / 15m')
FROM    http_log_on_request_completion h,
        http_discovery_src_path_60s p60,
        http_discovery_src_miss_60s m60,
        http_discovery_src_bad_method_5m bm5
WHEN    (p60.count >= 30
         AND p60.count_distinct >= 30
         AND m60.count * 100 >= p60.count * 50)
     OR bm5.count >= 5
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   15m ON PARTITION p60;

SELECT  concat('REJECT ', h.source_ip, ' 30m')
FROM    http_log_on_request_completion h,
        http_discovery_src_path_5m p5,
        http_discovery_src_miss_5m m5,
        http_discovery_src_sensitive_5m s5
WHEN    s5.count_distinct >= 3
     OR (s5.count >= 12 AND m5.count * 100 >= p5.count * 50)
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   30m ON PARTITION s5;
