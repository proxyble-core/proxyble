# A stream that listens on UDP port 5243 for HTTP logs from HAproxy as client requests arrive.

CREATE STREAM http_log_on_request_arrival (
        schema	        	string,
        event_stage		string,
        traffic_mode		string,
        request_id		string,
        accept_ts_ms		number,
        request_ts_ms		number,
        source_ip		string,
        source_port		number,
        real_client_ip		string,
        frontend_ip		string,
        frontend_port		number,
        frontend_name		string,
        tls		        string,
        sni	        	string,
        tls_protocol		string,
        tls_cipher		string,
        alpn	        	string,
        host	        	string,
        method		        string,
        path	        	string,
        query_string		string,
        full_url		string,
        http_version		string,
        user_agent		string,
        referer	        	string,
        user_header		string,
        client_key		string,
        tenant_id		string,
        session_id		string,
        login_identifier	string,
        mcp_client_id		string,
        mcp_session_id		string,
        mcp_tool_name		string,
        active_conn		number,
        frontend_conn		number,
        policy_action		string,
        policy_param		string,
        endpoint_rate_limit	number,
        endpoint_rate_current	number
)
INPUT UDP(port 5243)
PARSER log(
        pattern '* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
'
);

