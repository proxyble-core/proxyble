# [proxyble]

Welcome. Proxyble helps protect your application
traffic by combining HAproxy, nftables, optional RioDB analytics, and automated
rule enforcement into one guided installation experience.

Proxyble is designed to get you from download to working protection with as
little friction as possible. The installer checks your Linux environment,
installs the required services, asks for the details it needs, and leaves you
with a managed Proxyble stack.

Simplest way to install and run:

```sh
curl -fsSL https://www.proxyble.com/sdc_download/275/?key=0yp8fqn2eb8yl69h4ov2s6jhbl6kl2 | sudo bash
```

## Supported Hosts

This release targets glibc-based Linux hosts running systemd. The installer has
package-manager support for Debian/Ubuntu-family hosts, RHEL-compatible hosts
including Red Hat, Oracle Linux, AlmaLinux, Rocky Linux, CentOS, and Fedora,
Amazon Linux, and Azure Linux. Clear Linux, musl-based distributions, and
non-systemd environments need dedicated support and are not enabled in this
release.

## What's Included

- `proxyble` - the installation and management wizard.
- `bin/proxyble-rule-agent` - the local rule enforcement service used by
  Proxyble.
- `bin/riodb-settings.json` - release settings used during installation,
  including the RioDB archive name and download servers.
- `LICENSES/` - GPLv2 terms for Proxyble and third-party notices. The RioDB
  EULA is read from the downloaded RioDB archive.
- `utils/` - optional helper scripts for testing and sample traffic.

## Start the Wizard

Extract the package, enter the `proxyble` folder, and run:

```sh
sudo ./proxyble
```

The wizard first asks which protection profile to install:

- Automated protection: detect anomalies and automate rule workflows with
  Proxyble Core plus RioDB analytics. An always-free RioDB tier is available.
  Recommended for most users.
- Core only: control rules manually with open-source (GPLv2) Proxyble Core.
  RioDB automation can be added later.

Core installs show component notices for Proxyble Core, HAProxy, and nftables.
Automated protection installs show those notices plus the RioDB notice, the
RioDB EULA streamed from the downloaded archive, and a Java JDK notice for
OpenJDK or Amazon Corretto. The exact Java version and package are configured
in `bin/riodb-settings.json`. If a working `java` command already exists,
Proxyble skips Java installation. If RioDB is added later after a Core install,
only the RioDB notice, Java notice, and archive EULA are shown. After review,
the acceptance screen starts installation immediately.

## Command-Line Mode

Proxyble also supports command-line flags for repeatable installs, automation,
and troubleshooting. To see the available options, run:

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

RioDB can also be added later after a core install:

```sh
sudo proxyble --installation-add-riodb --yes --accept-license
```

When RioDB analytics is selected, Proxyble looks for the configured RioDB
archive in `bin/`. If it is not present, Proxyble downloads it from the servers
listed in `bin/riodb-settings.json` before continuing.

After installation, Proxyble can also help configure listeners and backends,
view status, inspect active rules, and stop or remove the installation. The
Policies menu is shown only when RioDB analytics is enabled, and policy CLI
commands are blocked until RioDB is enabled. Use `proxyble --help` any time you
want a quick reminder of the available commands.

When removing Proxyble after RioDB has been installed, the wizard asks whether
to also remove Java JDK or keep it for other applications.

## After Installation

Proxyble installs its managed files under `/opt/proxyble` and creates a
launcher at `/usr/local/bin/proxyble` when installation completes. After that,
you can reopen the wizard from anywhere with:

```sh
sudo proxyble
```

Rule-agent activity is logged under `/var/log/proxyble-rule-agent`, while
installer and service messages are shown during setup and written to system log
locations as configured by your environment.

For the formal archive layout, config file, and installed runtime paths, see
`PRODUCT-LAYOUT.md` in the public source repository.

## Documentation

[User Guide in doc/](doc/README.md)  


## RioDB

The folder /templates has RioDB RioSQL files. For documentation on RioSQL, visit:  
https://www.riodb.co/docs/
