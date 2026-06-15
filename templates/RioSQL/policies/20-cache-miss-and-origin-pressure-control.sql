# Policy: Cache Miss And Origin Pressure Control
# Policy ID: cache_miss_and_origin_pressure_control
# Summary: Detects cache-miss-heavy variant generation, query-string churn, and origin pressure from cacheable traffic.
# Threat: Automated variants force origin work and reduce cache efficiency.
# Detection Signals: High backend latency; repeated uncacheable variants; cache-miss-heavy paths; query-string churn; elevated origin request ratio.
# Metrics Layer: on request-completion
# Visibility: http,https
# Severity: MEDIUM
# Priority: MEDIUM
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-cache-src-fullurl-5m.sql
# - 10-http-cache-src-fullurl-15m.sql
# - 10-http-cache-src-query-5m.sql
# - 10-http-cache-src-query-15m.sql
# - 10-http-cache-src-miss-5m.sql
# - 10-http-cache-src-miss-15m.sql
# - 10-http-src-total-time-5m.sql

SELECT  concat('LIMIT_ENDPOINT_RATE ', h.source_ip, ' 10/second / 15m')
FROM    http_log_on_request_completion h,
        http_cache_src_fullurl_5m u5,
        http_cache_src_query_5m q5,
        http_cache_src_miss_5m m5,
        http_src_total_time_5m t5
WHEN    u5.count >= 50
AND     ((m5.count * 100 >= u5.count * 70 AND q5.count_distinct >= 25)
      OR (u5.count_distinct * 100 >= u5.count * 80 AND t5.avg > 2000))
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   15m ON PARTITION u5;

SELECT  concat('BUSY_DEFLECTION ', h.source_ip, ' 10m')
FROM    http_log_on_request_completion h,
        http_cache_src_fullurl_15m u15,
        http_cache_src_query_15m q15,
        http_cache_src_miss_15m m15
WHEN    u15.count >= 200
AND     m15.count * 100 >= u15.count * 70
AND     q15.count_distinct >= 75
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   10m ON PARTITION u15;
