# Policy: Scraping And AI Crawler Cost Control
# Policy ID: scraping_and_ai_crawler_cost_control
# Summary: Detects excessive successful reads, high bandwidth use, broad URL traversal, and crawler-like content extraction.
# Threat: Automated clients extract content or data while creating bandwidth cost and business-model risk.
# Detection Signals: High bytes_sent; repeated GETs; pagination walking; sequential IDs; low write activity; crawler-like timing.
# Metrics Layer: on request-completion
# Visibility: http,https
# Severity: MEDIUM
# Priority: HIGH
# Catalog: ../policies.json
#
# Dependencies:
# - 10-http-read-src-get-15m.sql
# - 10-http-read-src-write-15m.sql
# - 10-http-read-src-url-15m.sql
# - 10-http-read-src-query-15m.sql
# - 10-http-src-bytes-15m.sql

SELECT  concat('LIMIT_BANDWIDTH ', h.source_ip, ' 5mb 30m')
FROM    http_log_on_request_completion h,
        http_read_src_get_15m get15,
        http_read_src_write_15m write15,
        http_read_src_url_15m url15,
        http_read_src_query_15m query15,
        http_src_bytes_15m bytes15
WHEN    bytes15.sum > 500000000
     OR (get15.count >= 1000
         AND get15.count > (write15.count * 25)
         AND url15.count_distinct >= 100)
     OR (query15.count_distinct >= 100 AND get15.count >= 300)
OUTPUT  local(
        target_stream 'rule_queue'
)
SLEEP   30m ON PARTITION get15;
