# First Run

Thank you for choosing Proxyble. Proxyble helps protect an API, web app, or
TCP service by putting a managed traffic-control layer in front of it.

Proxyble installs and manages two battle-tested open source components:

- `HAProxy`: a reverse proxy and load balancer. In plain terms, it receives
  client traffic and forwards allowed traffic to your app.
- `nftables`: the modern Linux packet-filtering framework. In plain terms, it
  is the firewall layer Proxyble uses for low-level IP and connection controls.

Proxyble Core, the part used for basic manual rule management, is free and open
source. With Core, you can add, view, check, and remove rules yourself.

Proxyble can also be enhanced with RioDB analytics. RioDB is an in-memory
stream-processing engine, which means it reads live traffic metadata and 
evaluates them immediately instead of storing them in a database first. 
RioDB is not free and open source, but it provides a Free Tier that allows 
one instance per customer. Review the RioDB EULA before enabling it.


Simplest way to install and run:

```sh
curl -fsSL https://www.proxyble.com/sdc_download/275/?key=0yp8fqn2eb8yl69h4ov2s6jhbl6kl2 | sudo bash
```


## Start The Wizard

From the release directory, start Proxyble:

```sh
sudo ./proxyble
```

**WE HIGHLY RECOMMEND YOU USE THE INTERACTIVE TERMINAL UI.**  
For automated deployments, this document includes hints for CLI alternative.


The first run asks which protection profile to install:

- `Automated protection`: installs Proxyble Core plus RioDB analytics.
- `Core only`: installs Proxyble Core for manual rules without RioDB.

CLI hint:

```sh
sudo ./proxyble --install --core-only
sudo ./proxyble --install --with-riodb
```

For unattended installs (no UI), add `--yes`. When installing RioDB, also add
`--accept-license` because RioDB requires EULA acceptance:

```sh
sudo ./proxyble --yes --install --core-only
sudo ./proxyble --yes --install --with-riodb --accept-license
```

## After Installation

After installation, Proxyble can be run from anywhere as:

```sh
sudo proxyble
```

That command opens the interactive wizard. Proxyble also has command-line mode,
which is useful for automation, repeatable setup, or scripts:

```sh
proxyble --help
proxyble --install --help
proxyble --config-listener --help
```

You can also review component notices, the RioDB EULA when available, and
installed component versions from the CLI:

```sh
sudo proxyble --installation-license
sudo proxyble --installation-list
```

Administrators can also use `systemd` directly. Systemd is the Linux service
manager that starts, stops, and reports status for long-running services. This
is useful when you want to inspect or control one Proxyble component instead of
using the full Proxyble wizard.

Core components include:

- `haproxy.service`: receives client traffic and forwards allowed traffic to the backend.
- `nftables.service`: applies Linux firewall rules.
- `proxyble-rule-agent.service`: processes rule changes on demand.
- `proxyble-rule-agent.path`: watches the rule inbox for changes.
- `proxyble-rule-agent.timer`: runs the rule agent once per minute so expired rules are cleaned up.

RioDB installs `riodb.service` when analytics are enabled.

All services can be easily managed from the interactive terminal UI.  
But systemctl commands are another option for starting and stopping services.

Examples:

```sh
# View status for core services.
sudo systemctl status haproxy.service
sudo systemctl status nftables.service
sudo systemctl status proxyble-rule-agent.service
sudo systemctl status proxyble-rule-agent.path
sudo systemctl status proxyble-rule-agent.timer
```

For normal Proxyble operation, prefer `sudo proxyble --config-start`,
`sudo proxyble --config-stop`, and `sudo proxyble --config-status` because those
commands handle the expected Proxyble service set together.

Previous: [Guide index](README.md)  
Next: [Rules only or automated policies](02-rules-only-vs-automated-policies.md)
