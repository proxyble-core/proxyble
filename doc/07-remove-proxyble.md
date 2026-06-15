# Removing Proxyble

Proxyble removal is destructive. It removes Proxyble services, configuration,
logs, runtime state, installed packages, systemd units, and the RioDB system
user/group when present.

Interactive path:

```sh
sudo proxyble
```

Choose `Installation` and `Remove`.

CLI hint:

```sh
sudo proxyble --installation-remove
```

## Java Removal Choice

If RioDB is installed, the remover asks whether to also remove Java JDK or keep
it for other applications. Keep Java if any other software on the host might
use it. If Java removal is selected but no supported Java package is detected,
Proxyble logs a notice and skips Java package removal.

CLI hints:

```sh
# Remove Proxyble but keep Java.
sudo proxyble --yes --installation-remove --keep-java

# Remove Proxyble and remove the supported Java package when detected.
sudo proxyble --yes --installation-remove --remove-java
```

## What Removal Stops

Removal stops and disables:

- `proxyble-rule-agent.path`
- `proxyble-rule-agent.timer`
- `proxyble-rule-agent.service`
- `riodb.service`, when RioDB is enabled
- `haproxy.service`
- `nftables.service`

Removal also kills leftover `proxyble-rule-agent`, `riodb`, and `haproxy`
processes if they are still running.

## What Removal Deletes

Removal deletes the default installed paths, including:

- `/etc/proxyble`
- `/opt/proxyble`
- `/usr/local/bin/proxyble`
- `/usr/local/bin/proxyble-rule-agent`
- `/var/spool/proxyble/rules`
- `/var/lib/proxyble-rule-agent`
- `/var/log/proxyble-rule-agent`
- `/opt/riodb`, when RioDB is installed in the default location
- `/var/log/riodb`
- `/etc/haproxy`
- `/run/haproxy`
- `/var/lib/haproxy`
- Proxyble systemd units and service overrides

Proxyble writes a removal action log under `/var/log/proxyble` while the
teardown is running. Because removal deletes many log directories, keep any
audit material you need before confirming removal.

Previous: [RioDB analytics and policies](06-riodb-analytics-and-policies.md)  
Next: [Logs](08-logs.md)
