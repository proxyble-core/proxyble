# Policy: Retry Storm Control
# Policy ID: retry_storm_control
# Summary: Detects broken clients that rapidly retry after 429, 5xx, or 503 responses and amplify partial outages.
# Threat: Broken clients and scripts amplify outages by retrying too quickly after failures.
# Detection Signals: Repeated identical requests; short retry intervals; rising 5xx, 429, or 503; no natural backoff; bursty new connections.
# Metrics Layer: on request-completion
# Visibility: tcp,http,https
# Severity: MEDIUM
# Priority: HIGH
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-src-req-30s.sql
# - 10-http-src-req-60s.sql
# - 10-http-src-req-30m.sql
# - 10-http-src-flood-error-30s.sql
# - 10-http-src-ts-30s.sql
# - 10-http-retry-src-failed-signature-30s.sql
# - 10-http-global-req-30s.sql
# - 10-http-global-flood-error-30s.sql
# - 10-tcp-arrival-src-conn-10s.sql

SELECT  concat('LIMIT_RATE_SLOW ', h.source_ip, ' 10m')
FROM    http_log_on_request_completion h,
        http_src_req_30s r30,
        http_src_req_60s r60,
        http_src_req_30m b30,
        http_src_flood_error_30s f30,
        http_src_ts_30s ts30,
        http_retry_src_failed_signature_30s sig30
WHEN    sig30.count >= 3
AND     sig30.count_distinct <= 2
AND     ((r30.count >= 3
          AND ts30.count > 1
          AND ((ts30.last - ts30.first) / (ts30.count - 1)) < 2000)
      OR (b30.is_full
          AND r60.count > ((b30.count / 30) * 5)
          AND f30.count * 100 >= r30.count * 30))
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   10m ON PARTITION r30;

SELECT  concat('TIMEOUT ', h.source_ip, ' 5s 10m')
FROM    http_log_on_request_completion h,
        http_src_req_30s r30,
        http_src_flood_error_30s f30,
        http_global_req_30s g30,
        http_global_flood_error_30s gerr30
WHEN    g30.count >= 100
AND     gerr30.count * 100 >= g30.count * 20
AND     r30.count >= 30
AND     f30.count * 100 >= r30.count * 50
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   10m ON PARTITION r30;

SELECT  concat('LIMIT_CONN_RATE ', t.source_ip, ' 20/second 10m')
FROM    tcp_log_on_request_arrival t,
        tcp_arrival_src_conn_10s c10
WHEN    c10.count >= 200
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   10m ON PARTITION c10;
