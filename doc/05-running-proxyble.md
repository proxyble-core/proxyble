# Running Proxyble

The `Config` menu controls runtime services after the listener and backend are
configured.

Interactive path:

```sh
sudo proxyble
```

Then choose `Config`.

## Start

`Start` starts the runtime stack in the required order. Runtime stack means the
system services that actually handle traffic and rules:

- `nftables`: Linux packet filtering.
- `riodb.service`: RioDB analytics, only when RioDB is enabled.
- `haproxy.service`: the listener and reverse proxy.
- `proxyble-rule-agent.path` and `proxyble-rule-agent.timer`: rule processing
  triggers.

CLI hint:

```sh
sudo proxyble --yes --config-start
```

`--config-restart` is an alias for `--config-start`. Start uses stop/start
internally so freshly rendered HAProxy configuration is applied.

CLI hint:

```sh
sudo proxyble --yes --config-restart
```

## Status

`Status` shows systemd health for the required services, host resource usage,
and recent rule activity. Systemd is the Linux service manager Proxyble uses to
start and monitor HAProxy, nftables, RioDB, and the rule agent.

CLI hint:

```sh
sudo proxyble --config-status
```

Status also counts rules applied today and during the past week from
`/var/log/proxyble-rule-agent`.

## Stop

`Stop` stops Proxyble runtime services. It stops the rule-agent path, timer, and
service first, then RioDB if enabled, then HAProxy and nftables.

CLI hint:

```sh
sudo proxyble --yes --config-stop
```

Stopping services pauses protection. It does not remove Proxyble and does not
delete rules from the saved rule-agent state.

## View

`View` shows the current Proxyble configuration file. The canonical file is:

```text
/etc/proxyble/config.ini
```

CLI hint:

```sh
sudo proxyble --config-view
```

The file contains listener, backend, RioDB, HAProxy, nftables, and rule-agent
paths. Proxyble writes individual values while preserving unrelated keys.

Previous: [Manual rules](04-manual-rules.md)  
Next: [RioDB analytics and policies](06-riodb-analytics-and-policies.md)
