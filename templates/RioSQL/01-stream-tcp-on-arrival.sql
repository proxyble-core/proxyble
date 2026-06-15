# A stream that listens on UDP port 5241 for TCP logs from HAproxy as client requests arrive.

CREATE STREAM tcp_log_on_request_arrival (
        schema                  string,
        event_stage		string,
        traffic_mode		string,
        request_id		string,
        accept_ts_ms		number,
        source_ip		string,
        source_port		number,
        frontend_ip		string,
        frontend_port		number,
        frontend_name		string,
        active_conn		number,
        frontend_conn		number,
        source_conn_cur		number,
        policy_action		string,
        policy_param		string
)
INPUT UDP(port 5241)
PARSER log(
        pattern '* * * * * * * * * * * * * * *
'
);

