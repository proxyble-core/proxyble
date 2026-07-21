# RioDB Analytics And Policies

RioDB analytics lets Proxyble detect behavior that static rules can miss.
Static rules are exact instructions: one source, one action, one expiration.
Analytics policies watch traffic over time and react when the pattern becomes
risky.

This helps with threats such as:

- Credential stuffing and password guessing.
- API floods that build over seconds or minutes.
- Clients staying just below manual thresholds for long periods.
- Endpoint discovery and route scanning.
- Scraping, export abuse, and large downloads.
- Retry storms after errors or rate limits.
- Expensive endpoints that create high backend, database, or AI-provider cost.
- Slow clients and connection hoarding.
- MCP session or tool pressure from agentic clients.

RioDB is not free and open source. Proxyble, HAProxy, and nftables are open
source, but RioDB is governed by the RioDB EULA. RioDB provides a Free Tier that
allows one instance per customer. Review the EULA shown by Proxyble before
enabling it.

For expert RioDB and RioSQL details, see the RioDB documentation:

```text
https://www.riodb.co/docs/
```

## Resource Planning

RioDB runs in memory. In plain terms, its analytics windows and stream state are
kept in RAM, so you do not need to add database storage just for traffic
analytics. You still need ordinary disk space for the RioDB application files,
SQL files, and logs.

If the host has very little available RAM, add memory before enabling busy
policies. For high-throughput APIs, additional CPU processors are strongly
recommended because RioDB has to parse and evaluate live event streams as
traffic arrives.

RioDB requires Java. The license screen shows a Java JDK notice for OpenJDK or
Amazon Corretto whenever RioDB is selected. The exact Java version and package
are configured in `bin/riodb-settings.json`; current release settings use Java
17 headless packages. If a working `java` command already exists, Proxyble
skips Java installation.

## Add RioDB From The Start

Interactive path:

```sh
sudo ./proxyble
```

Choose `Automated protection`.

CLI hint:

```sh
sudo ./proxyble --yes --install --with-riodb --accept-license
```

The install adds RioDB configuration, installs Java if needed, installs RioDB,
copies the required RioSQL bootstrap template, and enables the Policies menu.

## Add RioDB Later

Interactive path:

```sh
sudo proxyble
```

Choose `Installation` and `Add RioDB`.

CLI hint:

```sh
sudo proxyble --yes --installation-add-riodb --accept-license
```

Adding RioDB later keeps the existing Proxyble Core, HAProxy, and nftables setup.
It enables RioDB in `/etc/proxyble/config.ini`, installs the RioDB-dependent
pieces, refreshes HAProxy so traffic logs can be sent to RioDB, and starts
services if the listener and backend are complete.

## Deploy Policies

A policy is a RioSQL file that reads live HAProxy traffic events and writes rule
decisions to the local rule queue. The rule queue then feeds
`proxyble-rule-agent`, which applies the rule through HAProxy or nftables.

Interactive path:

```sh
sudo proxyble
```

Choose `Policies` and `Deploy`, then select a compatible policy. Compatibility
depends on listener mode. HTTP-visible policies require HTTP mode or HTTPS mode
with TLS termination.

CLI hint:

```sh
sudo proxyble --policies-deploy --policy api_flood_control --restart-riodb
```

Policy changes take effect after RioDB restarts. In CLI mode, add
`--restart-riodb` when you want Proxyble to restart RioDB immediately.

## View, Edit, And Remove Policies

List deployed managed policies:

```sh
sudo proxyble --policies-list
sudo proxyble --policies-view
```

`--policies-view` is currently an alias for `--policies-list`.

Remove a deployed policy:

```sh
sudo proxyble --yes --policies-remove --policy api_flood_control --restart-riodb
```

Edit an installed policy SQL file:

```sh
sudo proxyble --policies-edit --policy api_flood_control --editor vi
```

Editing policy SQL is an advanced action. Restart RioDB after edits so RioDB
reloads the SQL.

## Default Policy Templates

Proxyble does not hardcode the policy list. It dynamically reads RioSQL templates
from:

```text
/opt/proxyble/templates/RioSQL/policies
```

In the source tree, the same templates live under:

```text
templates/RioSQL/policies
```

The templates are ordinary RioSQL files with comment headers. Users can modify
templates, create new ones, or obtain different policies as RioSQL files. Shared
streams and windows live in `templates/RioSQL`, and policy dependencies are
copied into RioDB's flat SQL directory when a policy is deployed.

Default policy templates include:

| Policy ID | What it watches for |
| --- | --- |
| `analytics_skew_and_noise_control` | Repetitive synthetic traffic that pollutes metrics, counters, forms, or ranking signals. |
| `api_flood_control` | Sudden request floods, broad endpoint spread, error pressure, and connection bursts. |
| `business_flow_automation_control` | Automation performing valid business actions too quickly or too persistently. |
| `cache_miss_and_origin_pressure_control` | Cache-miss-heavy variants, query-string churn, and origin pressure. |
| `credential_pressure_control` | Credential stuffing and password guessing against login, token, auth, and session endpoints. |
| `endpoint_discovery_control` | Route scanning, hidden endpoint probing, uncommon methods, and high 400/404/405 ratios. |
| `expensive_endpoint_cost_control` | Normal-looking traffic that creates excessive latency, compute cost, or timeout pressure. |
| `gray_zone_automation_shaping` | Clients that stay near static thresholds with little idle time. |
| `known_bad_source_ejection` | High-confidence hostile sources and repeated severe violations. |
| `large_download_and_export_control` | Repeated exports, archive/report downloads, and very large responses. |
| `legitimate_burst_protection` | Sharp but clean traffic bursts that need short pressure relief instead of long bans. |
| `mcp_session_occupancy_control` | Long-lived or over-abundant MCP streaming sessions and reconnect churn. |
| `mcp_tool_pressure_control` | Agentic MCP tool or resource calls at machine speed. |
| `retry_storm_control` | Broken clients that rapidly retry after 429, 5xx, or 503 responses. |
| `scraping_and_ai_crawler_cost_control` | Successful reads, broad URL traversal, and crawler-like extraction. |
| `slow_client_and_connection_hoarding_control` | Slow connections, long request duration, low throughput, or high connection occupancy. |


## Build Policies With AI
A separate GitHub repository contains a Codex-ready project for leveraging AI to
generate advanced Proxyble protection policies. See [Proxyble AI Policy Maker](https://github.com/proxyble-core/proxyble-ai-policy-maker).


Previous: [Running Proxyble](05-running-proxyble.md)  
Next: [Removing Proxyble](07-remove-proxyble.md)
