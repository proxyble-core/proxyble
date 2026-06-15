# First Run

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

From that point on, you can always bring up the proxyble terminal UI by running:

```sh
sudo proxyble
```


## Proxyble Terminal UI


The UI first asks which protection profile to install:

- Automated protection: detect anomalies and automate rule workflows with
  Proxyble Core plus RioDB analytics. An always-free RioDB tier is available.
  Recommended for most users.
- Core only: control rules manually with open-source (GPLv2) Proxyble Core.
  RioDB automation can be added later.


If undecided, start with "Core only". RioDB option can be added later.

The next pages in this User Guide cover different steps of the configuration.

## Command-Line Mode

Proxyble also supports command-line flags for repeatable installs, automation,
and troubleshooting. Instead of executing the donwloaded file, you can extract
and run:

```sh
./proxyble --help
```

For example, an unattended core install can be started with:

```sh
sudo ./proxyble --install --core-only --yes
```

An unattended install with RioDB analytics can be started with:

```sh
sudo ./proxyble --install --with-riodb --yes --accept-license
```

When RioDB analytics is selected, Proxyble looks for the configured RioDB
archive in `bin/`. If it is not present, Proxyble downloads it from the servers
listed in `bin/riodb-settings.json` before continuing.


Previous: [Guide index](README.md)  
Next: [Rules only or automated policies](02-rules-only-vs-automated-policies.md)
