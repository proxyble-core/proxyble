# Manual Rules

Rules control what happens to traffic from a source IP address or CIDR block.
CIDR means an IP range written like `203.0.113.0/24`. In plain terms,
`203.0.113.0/24` covers the IPs from `203.0.113.0` through `203.0.113.255`.

When you add a rule, Proxyble determines if the rule type is best enforced
by HAproxy or by NFTables, and deploys the rule where it belongs.

## Rule Scope

Most rule types accept one IPv4 address or one CIDR block. A single IP address
is treated like a `/32`, which means exactly one host.

CIDR targets are rule scopes. If you add a rule for `198.51.100.0/24`, the rule
applies to every source IP in that range. For nftables-backed connection limits
such as `LIMIT_CONN_RATE` and `LIMIT_CONCURRENT`, Proxyble uses the CIDR only to
decide which clients are covered. The actual counter is per source IP, so one
abusive client inside the CIDR does not consume the limit for every other client
in the same range.

For example, `LIMIT_CONN_RATE 198.51.100.0/24 25/second` gives each individual
IP in `198.51.100.0/24` its own `25/second` connection-rate bucket. It is not a
single shared `25/second` bucket for the whole `/24`.

If you type a host address inside a CIDR, Proxyble normalizes it to the network
address before storing the rule. For example, `10.10.10.10/24` becomes
`10.10.10.0/24`.

For HAProxy-backed parameter rules such as `LIMIT_BANDWIDTH` or `TIMEOUT`, the
same bandwidth or timeout value is assigned to every matching source in the CIDR.
Those rules are still scoped to the CIDR target, but they are not per-IP policy
objects.

`LIMIT_ENDPOINT_RATE` is different: it accepts one individual IPv4 address only.
It does not accept CIDR blocks because endpoint rate tracking is intentionally
per source IP and per HTTP path prefix.

`0.0.0.0/0` means every IPv4 address in the world. For `LIMIT_CONN_RATE` and
`LIMIT_CONCURRENT`, that still means per-IP counters: every IPv4 client is in
scope, but each client gets its own counter. Use it carefully. The manual rule
flow refuses `DROP` and `REJECT` with `0.0.0.0/0` so you do not accidentally
block all clients. Other rule types can use it when a global limit or slowdown
is intentional.

## Rule Workflow

List rules:

```sh
sudo proxyble --rules-list
```

Add a rule:

```sh
sudo proxyble --yes --rules-add --rule DROP --target 203.0.113.25 --expiration 10m
```

Check whether an IP is affected by active rules:

```sh
sudo proxyble --rules-check --ip 203.0.113.25
```

Remove one matching rule from the check result:

```sh
sudo proxyble --yes --rules-check --ip 203.0.113.25 --remove --rule DROP --target 203.0.113.25
```

Reset all rules or all rules of one type:

```sh
sudo proxyble --yes --rules-reset --type ALL
sudo proxyble --yes --rules-reset --type LIMIT_CONN_RATE
```

Expiration values can be temporary, such as `10s`, `30m`, `1h`, or `1d`.
Leaving the interactive expiration blank creates a permanent rule. In CLI mode,
use `--expiration none` for a permanent rule.

## Rule Types

### `BUSY_DEFLECTION`

`BUSY_DEFLECTION` is an HAProxy-backed HTTP/HTTPS rule that returns a temporary
busy response. In plain terms, Proxyble tells the client "try again later"
instead of forwarding the request to your backend. It is softer than a block
because it signals overload rather than hostility.

This rule is useful when a source may be legitimate but is adding pressure at a
bad time, such as a partner integration, a large customer job, a crawler, or a
burst during an incident. It is a good first response before using stricter
rules.

CLI hint:

```sh
sudo proxyble --yes --rules-add --rule BUSY_DEFLECTION --target 203.0.113.25 --expiration 5m
```

### `DROP`

`DROP` is an nftables-backed rule that silently discards matching traffic. In
plain terms, the client gets no useful answer. This is low-cost for the server
because the traffic is stopped at the firewall layer.

Use `DROP` for clearly hostile sources, abusive scanners, or sources you do not
want to spend proxy or application resources on. Avoid using it for uncertain
clients because silent failure can make troubleshooting harder.

CLI hint:

```sh
sudo proxyble --yes --rules-add --rule DROP --target 203.0.113.25 --expiration 30m
```

### `LIMIT_BANDWIDTH`

`LIMIT_BANDWIDTH` is an HAProxy-backed HTTP/HTTPS rule that limits response
bandwidth for a source. Bandwidth means how much data per second the client can
receive. Proxyble accepts values such as `500kb`, `10mb`, or `1gb`.

Use this when a client is expensive because it downloads large responses, export
files, generated reports, or model output, but you do not want to block it
completely. It is often better for cost control than a hard ban.

CLI hint:

```sh
sudo proxyble --yes --rules-add --rule LIMIT_BANDWIDTH --target 203.0.113.25 --bandwidth 10mb --expiration 15m
```

### `LIMIT_CONCURRENT`

`LIMIT_CONCURRENT` is an nftables-backed rule that caps active connections from
a source. Concurrent connections are connections open at the same time. If the
source exceeds the cap, new or excess connection attempts are blocked.

When the target is a CIDR block, the cap is measured per individual source IP.
For example, a `/24` target with limit `50` allows each client IP in that range
up to `50` active connections; it does not create one shared pool of `50`
connections for the entire CIDR.

Use this for clients that hold too many connections open, long-running streams,
slow clients, or connection-hoarding behavior. It helps protect connection slots
without necessarily blocking every request from the source.

CLI hint:

```sh
sudo proxyble --yes --rules-add --rule LIMIT_CONCURRENT --target 203.0.113.0/24 --limit 50 --expiration 10m
```

### `LIMIT_CONN_RATE`

`LIMIT_CONN_RATE` is an nftables-backed rule that caps how quickly a source can
create new connections. Connection rate is written as `25/second` or
`100/minute`. It works before HTTP details matter, so it is available in TCP,
HTTP, and HTTPS modes.

When the target is a CIDR block, the rate is measured per individual source IP.
For example, a `/24` target with rate `25/second` gives each client IP in that
range its own `25/second` bucket; it does not make the whole CIDR share one
bucket.

Use this for floods, scanners, aggressive retry loops, and clients that rapidly
open new sockets. It is especially useful in TCP mode because Proxyble does not
need to inspect HTTP paths to enforce it.

CLI hint:

```sh
sudo proxyble --yes --rules-add --rule LIMIT_CONN_RATE --target 203.0.113.0/24 --rate 25/second --expiration 10m
```

### `LIMIT_ENDPOINT_RATE`

`LIMIT_ENDPOINT_RATE` is an HAProxy-backed HTTP/HTTPS rule that rate-limits one
source IP on selected HTTP path prefixes. A path prefix is the beginning of a
URL path, such as `/login`, `/search`, or `/api/export`.

Use this when abuse is focused on specific endpoints. It is well suited for
login pressure, search scraping, export abuse, MCP tool routes, or expensive API
handlers. It requires HTTP visibility, so use HTTP mode or HTTPS mode with TLS
termination.

CLI hint:

```sh
sudo proxyble --yes --rules-add --rule LIMIT_ENDPOINT_RATE --target 203.0.113.25 --rate 10/second --endpoints /login,/api/export --expiration 15m
```

### `LIMIT_RATE_SLOW`

`LIMIT_RATE_SLOW` is an HAProxy-backed HTTP/HTTPS rule that returns HTTP `429`
responses. HTTP `429` means "too many requests." In plain terms, the client is
told to slow down.

Use this for clients that may be legitimate but are overactive, such as scripts,
integrations, crawlers, or retrying SDKs. It is a good middle step before using
`BUSY_DEFLECTION`, `REJECT`, or `DROP`.

CLI hint:

```sh
sudo proxyble --yes --rules-add --rule LIMIT_RATE_SLOW --target 203.0.113.25 --expiration 10m
```

### `REJECT`

`REJECT` is an nftables-backed rule that blocks traffic and fails it quickly.
Unlike `DROP`, the client receives a fast failure instead of waiting for a
timeout.

Use `REJECT` when you want unwanted traffic to stop quickly and you are not
trying to hide that the source is blocked. It is often easier to diagnose than
`DROP`, but it still prevents the source from reaching HAProxy or your backend.

CLI hint:

```sh
sudo proxyble --yes --rules-add --rule REJECT --target 203.0.113.25 --expiration 30m
```

### `TIMEOUT`

`TIMEOUT` is an HAProxy-backed HTTP/HTTPS rule that shortens the backend server
timeout for a source. Backend timeout means how long HAProxy waits for your app
to respond. Values can be `5`, `5s`, `500ms`, or `1m`; a plain number means
seconds.

Use this when a source triggers slow database work, expensive AI calls, large
reports, or long-running handlers. It limits how long one source can tie up
backend work before Proxyble gives up on that request.

CLI hint:

```sh
sudo proxyble --yes --rules-add --rule TIMEOUT --target 203.0.113.25 --timeout-value 5s --expiration 10m
```

Previous: [Listener and backend setup](03-listener-and-backend.md)  
Next: [Running Proxyble](05-running-proxyble.md)
