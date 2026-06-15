# Policy: Slow Client And Connection Hoarding Control
# Policy ID: slow_client_and_connection_hoarding_control
# Summary: Detects sources holding sockets or requests open with low throughput, long duration, or high connection occupancy.
# Threat: Sources hold connections open cheaply and exhaust proxy or backend capacity.
# Detection Signals: Long request duration; slow headers or body; low throughput; high active connections; long-lived streams from one source.
# Metrics Layer: on request-completion
# Visibility: tcp,http,https
# Severity: HIGH
# Priority: HIGH
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-src-total-time-5m.sql
# - 10-http-src-bytes-5m.sql
# - 10-http-slow-src-lowbytes-5m.sql
# - 10-http-slow-src-timeout-5m.sql
# - 10-tcp-arrival-src-current-1m.sql
# - 10-tcp-completion-src-session-5m.sql
# - 10-tcp-completion-src-lowbytes-5m.sql

SELECT  concat('TIMEOUT ', h.source_ip, ' 5s 15m')
FROM    http_log_on_request_completion h,
        http_src_total_time_5m t5,
        http_src_bytes_5m b5,
        http_slow_src_lowbytes_5m slow5,
        http_slow_src_timeout_5m timeout5
WHEN    slow5.count >= 5
     OR timeout5.count >= 8
     OR (t5.avg > 30000 AND b5.sum < 10240 AND t5.count >= 5)
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   15m ON PARTITION t5;

SELECT  concat('LIMIT_CONCURRENT ', t.source_ip, ' 25 30m')
FROM    tcp_log_on_request_arrival t,
        tcp_arrival_src_current_1m cur1
WHEN    cur1.max >= 50
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   30m ON PARTITION cur1;

SELECT  concat('DROP ', t.source_ip, ' 30m')
FROM    tcp_log_on_request_completion t,
        tcp_completion_src_session_5m sess5,
        tcp_completion_src_lowbytes_5m low5
WHEN    sess5.max > 60000
AND     low5.count >= 10
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   30m ON PARTITION sess5;
