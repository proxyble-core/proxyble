# Policy: Known Bad Source Ejection
# Policy ID: known_bad_source_ejection
# Summary: Detects high-confidence hostile sources, severe repeated violations, scanner patterns, and obvious attack probes.
# Threat: Some sources are clearly hostile and should not consume proxy, application, or analyst time.
# Detection Signals: Repeated severe policy violations; obvious scanner or attack-tool pattern; continuing abuse after softer controls; hostile source intelligence.
# Metrics Layer: on request-completion
# Visibility: tcp,http,https
# Severity: HIGH
# Priority: HIGH
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-hostile-src-pattern-15m.sql
# - 10-http-hostile-src-pattern-1h.sql
# - 10-http-hostile-src-forbidden-15m.sql
# - 10-http-hostile-src-malformed-15m.sql
# - 10-http-discovery-src-sensitive-5m.sql
# - 10-http-discovery-src-bad-method-5m.sql
# - 10-http-auth-src-fail-5m.sql
# - 10-http-src-flood-error-30s.sql
# - 10-tcp-arrival-src-conn-10s.sql

SELECT  concat('REJECT ', h.source_ip, ' 1h')
FROM    http_log_on_request_completion h,
        http_hostile_src_pattern_15m p15,
        http_hostile_src_forbidden_15m forb15,
        http_hostile_src_malformed_15m mal15,
        http_discovery_src_sensitive_5m sens5,
        http_discovery_src_bad_method_5m badmethod5,
        http_auth_src_fail_5m auth5,
        http_src_flood_error_30s flood30
WHEN    p15.count_distinct >= 3
     OR (p15.count >= 10 AND forb15.count >= 10)
     OR (badmethod5.count >= 5 AND forb15.count >= 5)
     OR ((sens5.count >= 5 OR auth5.count >= 20)
         AND flood30.count >= 5)
     OR mal15.count >= 10
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   1h ON PARTITION p15;

SELECT  concat('DROP ', h.source_ip, ' 24h')
FROM    http_log_on_request_completion h,
        http_hostile_src_pattern_1h p1h,
        http_hostile_src_forbidden_15m forb15,
        http_hostile_src_malformed_15m mal15
WHEN    p1h.count_distinct >= 5
     OR (p1h.count >= 30 AND forb15.count >= 20)
     OR mal15.count >= 25
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   24h ON PARTITION p1h;

SELECT  concat('DROP ', t.source_ip, ' 1h')
FROM    tcp_log_on_request_arrival t,
        tcp_arrival_src_conn_10s c10
WHEN    c10.count >= 500
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   1h ON PARTITION c10;
