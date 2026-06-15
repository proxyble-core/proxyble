# Policy: Large Download And Export Control
# Policy ID: large_download_and_export_control
# Summary: Detects repeated exports, archive/report downloads, very large responses, and high byte-to-request ratios.
# Threat: Automated downloads create bandwidth cost and increase data-exfiltration exposure.
# Detection Signals: Very high response bytes; repeated exports; archive or report endpoints; sequential downloads; high byte-to-request ratio.
# Metrics Layer: on request-completion
# Visibility: http,https
# Severity: MEDIUM
# Priority: MEDIUM
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-export-src-bytes-15m.sql
# - 10-http-export-src-bytes-1h.sql
# - 10-http-export-src-bytes-24h.sql
# - 10-http-export-src-query-1h.sql

SELECT  concat('LIMIT_BANDWIDTH ', h.source_ip, ' 5mb 30m')
FROM    http_log_on_request_completion h,
        http_export_src_bytes_15m e15,
        http_export_src_bytes_1h e1h,
        http_export_src_query_1h q1h
WHEN    e15.sum > 1000000000
     OR e1h.count >= 100
     OR e1h.max > 250000000
     OR q1h.count_distinct >= 50
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   30m ON PARTITION e15;

SELECT  concat('LIMIT_RATE_SLOW ', h.source_ip, ' 1h')
FROM    http_log_on_request_completion h,
        http_export_src_bytes_24h e24
WHEN    e24.sum > 10000000000
     OR e24.count >= 1000
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   1h ON PARTITION e24;
