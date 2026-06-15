# Rules Only vs. Automated Policies

Proxyble can run as Core only, or as Core plus RioDB analytics. You can start
with rules only and add RioDB later.

## Manual Rules

A manual rule is an explicit instruction you create. For example: "drop this
IP for 10 minutes" or "rate-limit this source on `/login`." Proxyble passes the
rule to `proxyble-rule-agent`, which validates it and applies it through
nftables or HAProxy.

Manual rules are good when you already know the source, the action, and how long
the action should last. They are also good for small deployments, known testing
traffic, emergency blocks, or teams that want to keep protection simple and fully
manual.

CLI hint:

```sh
sudo proxyble --rules-list
sudo proxyble --yes --rules-add --rule DROP --target 203.0.113.25 --expiration 10m
```

## Automated Policies

An automated policy is a RioSQL file that watches live traffic and creates rules
when a pattern is detected. RioSQL is RioDB's stream query language. In plain
terms, it lets Proxyble ask questions like "is this source suddenly making too
many login attempts?" while traffic is happening.

Automated policies are useful when the threat is behavioral instead of obvious.
A single request may look normal, but the pattern over 30 seconds, 5 minutes, or
an hour may reveal scraping, credential stuffing, endpoint discovery, retry
storms, or expensive endpoint abuse.

CLI hint:

```sh
sudo proxyble --yes --installation-add-riodb --accept-license
sudo proxyble --policies-deploy --policy api_flood_control --restart-riodb
```

## Which Should You Choose?

| Choose | When it fits |
| --- | --- |
| Core only | You want open source manual rule management, know the sources to control, or want the smallest setup first. |
| Core plus RioDB | You want Proxyble to detect patterns in real time and trigger temporary rules automatically. |
| Start Core, add RioDB later | You want to get protected quickly, then add analytics when you are ready. |

Core only still installs and manages HAProxy and nftables. It just does not
install Java or RioDB, and the Policies menu stays hidden. This option is completely free and open source.

Adding RioDB later leaves the existing Proxyble, HAProxy, and nftables setup in
place. Proxyble enables RioDB in `/etc/proxyble/config.ini`, installs Java only
when no working Java runtime is already present, installs RioDB, refreshes
HAProxy logging to RioDB, and enables the Policies workflow.

Previous: [First run](01-first-run.md)  
Next: [Listener and backend setup](03-listener-and-backend.md)
