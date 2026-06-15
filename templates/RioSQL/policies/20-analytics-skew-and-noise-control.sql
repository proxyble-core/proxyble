# Policy: Analytics Skew And Noise Control
# Policy ID: analytics_skew_and_noise_control
# Summary: Detects repetitive synthetic traffic that pollutes page views, forms, counters, metrics, and ranking signals.
# Threat: Automation pollutes metrics, search ranking signals, counters, or lead forms without always causing outages.
# Detection Signals: High repeated page views or submissions; low response diversity; repetitive timing; source dominates event volume.
# Metrics Layer: on request-completion
# Visibility: http,https
# Severity: LOW
# Priority: LOW
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-analytics-src-path-10m.sql
# - 10-http-analytics-src-status-10m.sql
# - 10-http-analytics-global-10m.sql
# - 10-http-src-ts-10m.sql

SELECT  concat('LIMIT_RATE_SLOW ', h.source_ip, ' 20m')
FROM    http_log_on_request_completion h,
        http_analytics_src_path_10m p10,
        http_analytics_src_status_10m s10,
        http_analytics_global_10m g10,
        http_src_ts_10m ts10
WHEN    p10.count >= 500
AND     p10.count * 100 >= g10.count * 5
AND     p10.count_distinct <= 3
AND     s10.count_distinct <= 3
AND     ts10.count > 1
AND     ((ts10.last - ts10.first) / (ts10.count - 1)) < 1000
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   20m ON PARTITION p10;
