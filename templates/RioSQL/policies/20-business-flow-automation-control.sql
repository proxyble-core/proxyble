# Policy: Business Flow Automation Control
# Policy ID: business_flow_automation_control
# Summary: Detects automation performing legitimate business actions too quickly or persistently.
# Threat: Automation performs valid actions too quickly or too persistently, such as reservation abuse, inventory holding, vote skewing, or form submission.
# Detection Signals: High action frequency; repetitive workflow order; abnormal conversion ratios; fast repeated POSTs; source dominates a flow.
# Metrics Layer: on request-arrival
# Visibility: http,https
# Severity: MEDIUM
# Priority: MEDIUM
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-arrival-src-business-action-5m.sql
# - 10-http-arrival-src-business-action-15m.sql
# - 10-http-arrival-src-post-5m.sql
# - 10-http-arrival-src-ts-60s.sql
# - 10-http-arrival-business-global-5m.sql

SELECT  concat('LIMIT_ENDPOINT_RATE ', h.source_ip, ' 10/second /search,/select,/reserve,/hold,/checkout,/vote,/submit,/create 15m')
FROM    http_log_on_request_arrival h,
        http_arrival_src_business_action_5m a5,
        http_arrival_src_business_action_15m a15,
        http_arrival_src_post_5m p5,
        http_arrival_src_ts_60s ts60,
        http_arrival_business_global_5m g5
WHEN    a5.count >= 120
     OR p5.count >= 60
     OR (a15.count >= 300 AND a15.count_distinct <= 4)
     OR (g5.count >= 100
         AND a5.count >= 25
         AND a5.count * 100 >= g5.count * 25)
     OR (ts60.count > 1
         AND a5.count >= 50
         AND ((ts60.last - ts60.first) / (ts60.count - 1)) < 300)
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   15m ON PARTITION a5;
