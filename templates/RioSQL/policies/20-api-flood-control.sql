# Policy: API Flood Control
# Policy ID: api_flood_control
# Summary: Detects sudden request floods, broad endpoint spread, high error pressure, and TCP connection bursts.
# Threat: Automation consumes backend capacity and degrades real customer traffic.
# Detection Signals: Sudden request-rate spike; rising backend latency; rising 5xx or 429; broad endpoint spread; short inter-request intervals.
# Metrics Layer: on request-arrival
# Visibility: tcp,http,https
# Severity: HIGH
# Priority: HIGH
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-arrival-src-req-10s.sql
# - 10-http-arrival-src-req-20s.sql
# - 10-http-arrival-src-req-60s.sql
# - 10-http-arrival-src-req-30m.sql
# - 10-http-arrival-src-path-5m.sql
# - 10-http-arrival-src-ts-60s.sql
# - 10-http-arrival-src-rate-usage-10s.sql
# - 10-http-src-req-30s.sql
# - 10-http-src-flood-error-30s.sql
# - 10-http-src-total-time-30s.sql
# - 10-http-global-req-30s.sql
# - 10-http-global-flood-error-30s.sql
# - 10-tcp-arrival-src-conn-10s.sql

SELECT  concat('BUSY_DEFLECTION ', h.source_ip, ' 5m')
FROM    http_log_on_request_arrival h,
        http_arrival_src_req_10s r10,
        http_arrival_src_req_20s r20,
        http_arrival_src_req_60s r60,
        http_arrival_src_req_30m b30,
        http_arrival_src_path_5m paths,
        http_arrival_src_ts_60s ts60,
        http_arrival_src_rate_usage_10s usage10
WHEN    r10.count >= 150
     OR r60.count >= 600
     OR usage10.max >= 120
     OR (b30.is_full
         AND r20.count >= 50
         AND r20.count > ((b30.count / 90) * 10))
     OR (r60.count >= 120 AND paths.count_distinct >= 20)
     OR (ts60.count > 1
         AND r60.count >= 50
         AND ((ts60.last - ts60.first) / (ts60.count - 1)) < 100)
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   5m ON PARTITION r10;

SELECT  concat('LIMIT_RATE_SLOW ', h.source_ip, ' 10m')
FROM    http_log_on_request_completion h,
        http_src_req_30s r30,
        http_src_flood_error_30s err30,
        http_src_total_time_30s t30,
        http_global_req_30s g30,
        http_global_flood_error_30s gerr30
WHEN    r30.count >= 100
AND     (err30.count * 100 >= r30.count * 20
      OR t30.avg > 5000
      OR (g30.count >= 1000 AND gerr30.count * 100 >= g30.count * 10))
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   10m ON PARTITION r30;

SELECT  concat('LIMIT_CONN_RATE ', t.source_ip, ' 25/second 10m')
FROM    tcp_log_on_request_arrival t,
        tcp_arrival_src_conn_10s c10
WHEN    c10.count >= 250
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   10m ON PARTITION c10;
