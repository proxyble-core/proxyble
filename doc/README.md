# Proxyble User Guide

Proxyble helps site and network administrators put a managed protection layer
in front of an API, web application, or TCP service. It can also use real-time
analytics and automated policy workflows for threat detection and mitigation as
traffic conditions change.

Proxyble is a complex traffic-control product made simple. This guide walks
through the main setup and operation steps in plain language while still using
the real terms you will see on your server.

Start with [First run](01-first-run.md) if you are installing Proxyble for the
first time. After installation, use the other pages as task-focused references.

## Pages

1. [First run](01-first-run.md): install Proxyble and open the interactive
   terminal UI.
2. [Rules only or automated policies](02-rules-only-vs-automated-policies.md):
   choose manual rule control or analytics-assisted automation.
3. [Listener and backend setup](03-listener-and-backend.md): tell Proxyble
   where traffic enters and where allowed traffic should go.
4. [Manual rules](04-manual-rules.md): add, check, and remove traffic rules
   yourself.
5. [Running Proxyble](05-running-proxyble.md): start, stop, inspect, and view
   the running service set.
6. [RioDB analytics and policies](06-riodb-analytics-and-policies.md): enable
   live analytics and automated policy workflows.
7. [Removing Proxyble](07-remove-proxyble.md): remove Proxyble cleanly when you
   no longer need it.
8. [Logs](08-logs.md): find logs and run quick checks when troubleshooting.

## Running Proxyble

After installation, Proxyble creates a launcher at `/usr/local/bin/proxyble`.
Most actions change system services or traffic rules, so run Proxyble with root
privileges:

```sh
sudo proxyble
```

For command-line mode, use `proxyble --help` to see available actions:

```sh
proxyble --help
proxyble --config-listener --help
proxyble --config-status --help
```

## Supported Hosts

This release targets glibc-based Linux hosts running systemd. The installer has
package-manager support for Debian/Ubuntu-family hosts, RHEL-compatible hosts
including Red Hat, Oracle Linux, AlmaLinux, Rocky Linux, CentOS, and Fedora,
Amazon Linux, and Azure Linux. Clear Linux, musl-based distributions, and
non-systemd environments need dedicated support and are not enabled in this
release.

Next: [First run](01-first-run.md)
