# rule_queue is a local stream that accepts one line of text from other upstream queries.

CREATE STREAM rule_queue (
        line string
)
INPUT local;



# a query to get any messages sent to rule_queue and write them to a file
# use a cooldownof 3 seconds to batch too frequent activity

SELECT  line
FROM    rule_queue
OUTPUT  file(
        directory '/var/spool/proxyble/rules'
        file_name 'inbox.tmp'
        cooldown_ms 3000
);