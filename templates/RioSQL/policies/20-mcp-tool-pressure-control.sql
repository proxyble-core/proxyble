# Policy: MCP Tool Pressure Control
# Policy ID: mcp_tool_pressure_control
# Summary: Detects agentic MCP tool or resource calls at machine speed, with high latency, cost, byte output, or route spread.
# Threat: Agents or tools call MCP endpoints at machine speed, causing cost, latency, and downstream risk even when requests are well formed.
# Detection Signals: High MCP endpoint RPS; repeated tool/resource routes; long tool latency; high response bytes; clustered calls from one source.
# Metrics Layer: on request-completion
# Visibility: http,https
# Severity: HIGH
# Priority: HIGH
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-mcp-src-tool-1m.sql
# - 10-http-mcp-src-tool-5m.sql
# - 10-http-mcp-src-time-5m.sql
# - 10-http-mcp-src-error-5m.sql

SELECT  concat('LIMIT_ENDPOINT_RATE ', h.source_ip, ' 5/second /mcp 15m')
FROM    http_log_on_request_completion h,
        http_mcp_src_tool_1m m1,
        http_mcp_src_tool_5m m5,
        http_mcp_src_time_5m mt5,
        http_mcp_src_error_5m err5
WHEN    m1.count >= 60
     OR m5.count >= 200
     OR mt5.sum > 300000
     OR (mt5.count >= 20 AND mt5.avg > 5000)
     OR (m5.count >= 20 AND err5.count * 100 >= m5.count * 25)
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   15m ON PARTITION m5;

SELECT  concat('BUSY_DEFLECTION ', h.source_ip, ' 10m')
FROM    http_log_on_request_completion h,
        http_mcp_src_tool_5m m5,
        http_mcp_src_time_5m mt5
WHEN    m5.count_distinct >= 20
AND     mt5.sum > 180000
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   10m ON PARTITION m5;
