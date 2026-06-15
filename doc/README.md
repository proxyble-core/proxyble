# Proxyble User Guide

This guide starts after you already have Proxyble available on the server. It
does not cover downloading or unpacking the release.

Proxyble is for software developers who build APIs and services, including
people who do not normally administer firewalls. The guide keeps the real
network terms, then explains each one in plain language.

## Pages

1. [First run](01-first-run.md)
2. [Rules only or automated policies](02-rules-only-vs-automated-policies.md)
3. [Listener and backend setup](03-listener-and-backend.md)
4. [Manual rules](04-manual-rules.md)
5. [Running Proxyble](05-running-proxyble.md)
6. [RioDB analytics and policies](06-riodb-analytics-and-policies.md)
7. [Removing Proxyble](07-remove-proxyble.md)
8. [Logs](08-logs.md)

## CLI Reminder

After installation, Proxyble creates a launcher at `/usr/local/bin/proxyble`.
Most actions change system services or firewall state, so run them with root
privileges:

```sh
sudo proxyble
```

For command-line mode, put global flags such as `--yes`, `--silent`, and
`--verbose` before the action:

```sh
sudo proxyble --yes --config-status
proxyble --help
proxyble --config-listener --help
```

Next: [First run](01-first-run.md)
