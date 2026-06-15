# A stream that listens on UDP port 5242 for TCP logs from HAproxy after request response completes.

CREATE STREAM tcp_log_on_request_completion (
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
        policy_param		string,
        backend_name		string,
        server_name		string,
        server_ip		string,
        server_port		string,
        bytes_uploaded		number,
        bytes_sent		number,
        queue_time_ms		number,
        connect_time_ms		number,
        total_time_ms		number,
        session_duration_ms	number,
        termination_state	string,
        backend_conn		number,
        server_conn		number,
        backend_queue		number,
        server_queue		number
)
INPUT UDP(port 5242)
PARSER log(
        pattern '* * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
'
);

