# Logs

Logs are the first place to look when a service does not start, a rule does not
apply, or a policy does not seem to trigger.

CLI hints:

```sh
sudo proxyble --config-status
sudo proxyble --config-view
sudo proxyble --verbose --config-start
```

`--verbose` prints detailed action output to the terminal while also writing the
action log.

## Log Locations

| Component | Where to look | Notes |
| --- | --- | --- |
| Proxyble wizard and CLI | `/var/log/proxyble/*.log` | Each action opens a timestamped log such as `config-start-YYYYMMDD-HHMMSS.log`. The directory comes from `[proxyble] log_dir` in `/etc/proxyble/config.ini`. |
| `proxyble-rule-agent` | `/var/log/proxyble-rule-agent/YYYY-MM-DD.log` | Daily rule-agent logs and rule audit events. Rule state is under `/var/lib/proxyble-rule-agent`, but that is state, not log output. |
| `proxyble-rule-agent` systemd service | `journalctl -u proxyble-rule-agent.service` | The service is oneshot. The path and timer units can also be checked with `journalctl -u proxyble-rule-agent.path` and `journalctl -u proxyble-rule-agent.timer`. |
| HAProxy | `journalctl -u haproxy.service` | Proxyble does not configure a default HAProxy file access log. When RioDB is enabled, HAProxy sends structured traffic events to RioDB over local UDP. |
| HAProxy RioDB traffic events | `127.0.0.1:5241`, `127.0.0.1:5242`, `127.0.0.1:5243`, `127.0.0.1:5244` | TCP arrival/completion defaults are `5241` and `5242`. HTTP/HTTPS arrival/completion defaults are `5243` and `5244`. These ports are configured in `[riodb]`. |
| nftables | `journalctl -u nftables.service` | Proxyble does not create a default nftables file log. To inspect live rules, use `nft list table inet pmgr`. |
| RioDB | `/var/log/riodb` | RioDB application logs. The directory comes from `[riodb] log_dir` in `/etc/proxyble/config.ini`. |
| RioDB systemd service | `journalctl -u riodb.service` | Useful when RioDB does not start or fails while loading SQL. |

Depending on the Linux distribution, systemd journal files usually live under
`/var/log/journal` for persistent logs or `/run/log/journal` for runtime-only
logs. Use `journalctl` rather than reading those files directly.

## RioDB Log Level

RioDB logging is controlled by:

```text
/opt/riodb/conf/logback_service.xml
```

You can change the RioDB log level there. Common levels are:

- `ERROR`: only serious failures.
- `WARN`: warnings and errors.
- `INFO`: normal service activity plus warnings and errors.

After changing RioDB logging, restart RioDB or start the Proxyble runtime stack
again.

CLI hint:

```sh
sudo proxyble --yes --config-start
```

## Quick Checks

Proxyble action logs:

```sh
sudo ls -lt /var/log/proxyble
```

Rule-agent activity:

```sh
sudo ls -lt /var/log/proxyble-rule-agent
sudo journalctl -u proxyble-rule-agent.service -n 50 --no-pager
```

HAProxy and nftables:

```sh
sudo journalctl -u haproxy.service -n 50 --no-pager
sudo journalctl -u nftables.service -n 50 --no-pager
sudo nft list table inet pmgr
```

RioDB:

```sh
sudo journalctl -u riodb.service -n 50 --no-pager
sudo ls -lt /var/log/riodb
```

Previous: [Removing Proxyble](07-remove-proxyble.md)  
Back to: [Guide index](README.md)
