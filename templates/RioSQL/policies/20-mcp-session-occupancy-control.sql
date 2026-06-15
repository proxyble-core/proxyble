# Policy: MCP Session Occupancy Control
# Policy ID: mcp_session_occupancy_control
# Summary: Detects long-lived or over-abundant MCP streaming sessions, reconnect churn, and scarce session occupancy.
# Threat: Long-lived agent sessions can occupy scarce server capacity and starve interactive users.
# Detection Signals: Long session duration; high concurrent connections; slow streaming reads; repeated reconnects; low useful throughput.
# Metrics Layer: on request-completion
# Visibility: tcp,http,https
# Severity: MEDIUM
# Priority: HIGH
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-mcp-src-session-15m.sql
# - 10-http-mcp-src-long-15m.sql
# - 10-http-mcp-src-time-5m.sql
# - 10-tcp-arrival-src-current-1m.sql

SELECT  concat('TIMEOUT ', h.source_ip, ' 10s 20m')
FROM    http_log_on_request_completion h,
        http_mcp_src_session_15m s15,
        http_mcp_src_long_15m l15,
        http_mcp_src_time_5m t5
WHEN    s15.count_distinct >= 10
     OR l15.count >= 5
     OR t5.sum > 600000
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   20m ON PARTITION s15;

SELECT  concat('LIMIT_CONCURRENT ', t.source_ip, ' 20 30m')
FROM    tcp_log_on_request_arrival t,
        tcp_arrival_src_current_1m cur1
WHEN    cur1.max >= 40
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   30m ON PARTITION cur1;
