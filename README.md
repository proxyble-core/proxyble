# Proxyble

Proxyble protects APIs, web applications, and TCP services.

It simplifies rule management, and enables powerful real-time analytics with 
automated policy workflows to detect and mitigate threats as traffic changes.

Proxyble is built for professionals who want practical control without building
every proxy and firewall workflow by hand. Download it, run the guided setup,
answer a few questions, and enable protection.

A separate GitHub repository contains a Codex-ready project to help you build
Proxyble protection policies with AI. See [Proxyble AI Policy Maker](https://github.com/proxyble-core/proxyble-ai-policy-maker).

## What Proxyble Is For

Use Proxyble when you want to:

- Place a controlled protection point in front of an application or service.
- Use real-time analytics to help detect and mitigate changing traffic threats.
- Add, view, and remove traffic rules without hand-editing firewall files.
- Start with manual rule control and add automated policy workflows when you
  need them.
- Keep the product on a server you choose, under your operational control.

Proxyble is not a hosted service. It runs on the server you choose, manages the
local components it installs, and can be operated through an interactive
terminal UI.

## What Gets Installed

Proxyble brings together a small set of well-known tools and manages them as
one stack:

- `Proxyble Core`: the command-line tool and rule manager.
- `HAProxy`: receives client traffic and forwards allowed traffic to your app.
- `nftables`: applies the Linux traffic rules used by Proxyble.
- `RioDB analytics`: optional live analytics for automated protection workflows.

Proxyble Core, HAProxy, and nftables are open source. RioDB analytics is
optional and has a free tier for one instance per customer.

## Supported Hosts

This release targets glibc-based Linux hosts running systemd. x86, amd64, and
ARM64 hosts are supported.

## Download and Run Proxyble

Simplest way to install and run:

```sh
curl -fsSL https://www.proxyble.com/sdc_download/275/?key=0yp8fqn2eb8yl69h4ov2s6jhbl6kl2 | sudo bash
```

The installer checks your environment, explains what it needs, and walks you
through the setup.

## Documentation

[User Guide in doc/](doc/README.md)

## Community Support

[Proxyble on Reddit](https://www.reddit.com/r/proxyble/)


## RioDB Documentation

The `templates/` folder includes RioDB RioSQL files. For advanced RioDB
documentation, visit:

https://www.riodb.co/docs/
