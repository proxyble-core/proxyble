# Policy: Gray-Zone Automation Shaping
# Policy ID: gray_zone_automation_shaping
# Summary: Detects clients that persistently stay near static thresholds with little idle time and accumulating bytes or cost.
# Threat: Clients stay just below static thresholds, consuming unfair capacity over long windows.
# Detection Signals: Sustained near-threshold RPS; no quiet periods; predictable timing; steady byte or cost accumulation; repeated policy-edge behavior.
# Metrics Layer: on request-completion
# Visibility: http,https
# Severity: LOW
# Priority: MEDIUM
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-src-req-5m.sql
# - 10-http-src-req-30m.sql
# - 10-http-src-req-2h.sql
# - 10-http-src-bytes-2h.sql
# - 10-http-src-total-time-15m.sql
# - 10-http-gray-src-rate-usage-5m.sql

SELECT  concat('LIMIT_RATE_SLOW ', h.source_ip, ' 30m')
FROM    http_log_on_request_completion h,
        http_src_req_5m r5,
        http_src_req_30m r30,
        http_src_req_2h r2h,
        http_src_bytes_2h b2h,
        http_src_total_time_15m t15,
        http_gray_src_rate_usage_5m usage5
WHEN    (usage5.count >= 20
         AND usage5.avg >= 70
         AND usage5.avg <= 95
         AND r30.is_full
         AND r2h.is_full)
     OR (r30.is_full
         AND r2h.is_full
         AND r5.count >= 70
         AND r5.count <= 95
         AND r30.count >= 420
         AND r2h.count >= 1680)
     OR b2h.sum > 5000000000
     OR t15.sum > 900000
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   30m ON PARTITION r5;
