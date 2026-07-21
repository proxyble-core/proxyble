# Proxyble Product Layout

This document defines the customer release layout and the installed filesystem
layout for Proxyble. Treat these paths as compatibility boundaries for
installers, package scripts, support runbooks, and deployment automation.

## Release Archive Layout

A customer release archive is a single top-level `proxyble/` directory.

```text
proxyble/
  proxyble
  README.md
  LICENSES/
    GPL-2.0.txt
    THIRD-PARTY-NOTICES.txt
  bin/
    proxyble-rule-agent
    riodb-settings.json
  utils/
    *.sh
```

The archive intentionally does not include source code or source-maintainer
documentation such as `PRODUCT-LAYOUT.md` and `DESIGN.md`. Those files remain
in the public source repository.

## Source Repository Layout

The public source repository keeps both Proxyble Go modules under the
`proxyble/` project directory:

```text
proxyble/
  src/                  installer and management CLI Go module
  proxyble-rule-agent/  rule enforcement agent Go module
```

Package and staging scripts build `proxyble/src/` into the `proxyble` binary
and `proxyble/proxyble-rule-agent/` into `bin/proxyble-rule-agent`.
Source-maintainer helper scripts live under `proxyble/bin/` but are excluded
from staged installs and customer release archives.

## `LICENSES/`

`LICENSES/` is the Proxyble license bundle for the release. These file names are
stable and must not be changed without updating the installer, package script,
documentation, and tests.

| Path | Purpose |
| --- | --- |
| `LICENSES/GPL-2.0.txt` | GPLv2 text for Proxyble Core and GPLv2 component notices. |
| `LICENSES/THIRD-PARTY-NOTICES.txt` | Third-party component and library notices. |

The installer displays component notices with purpose, license, local notice
path, and official website. Core installs show Proxyble Core, HAProxy, and
nftables notices. Full installs show those notices plus the RioDB notice, the
RioDB EULA streamed from the configured RioDB archive member
`riodb/LICENSES/RIODB-EULA.txt`, and a Java JDK dependency notice. Adding RioDB
analytics later from the Installation menu or CLI shows only the RioDB notice,
Java notice, and archive EULA. Proxyble skips Java package installation when a
working `java` command already exists.

## `bin/`

In release archives, `bin/` contains runtime payloads that the installer needs
but does not build during customer installation.

| Path | Purpose |
| --- | --- |
| `bin/proxyble-rule-agent` | Bundled rule enforcement binary installed to `/usr/local/bin/proxyble-rule-agent`. |
| `bin/riodb-settings.json` | Release settings for Java package selection, the RioDB archive path, and RioDB download servers. |

`riodb-settings.json` is the stable place for release-specific runtime inputs.
The `riodb.archive_path` value names the RioDB archive. Relative archive paths
are resolved from installed `/opt/proxyble/bin/`, the settings file directory,
and development `bin/`. If the archive is not present when RioDB analytics is
selected, the installer downloads `archive_path` into `bin/` from the
`riodb.download_servers` list and then extracts it.

Do not rename `proxyble-rule-agent`, `riodb-settings.json`, the configured RioDB
archive path, or the RioDB download server schema without updating installer
code, package validation, and release tests.

## `templates/`

`templates/RioSQL/` contains deployable RioSQL policy templates and shared
window/query dependencies used by the Policies UI and policy CLI actions.
The installer copies this tree to `/opt/proxyble/templates/` so installed
systems can deploy policies without the source tree.

## Configuration

The canonical installed configuration file is:

```text
/etc/proxyble/config.ini
```

Default ownership and mode:

```text
/etc/proxyble             root:root 0700
/etc/proxyble/config.ini  root:root 0600
```

The installer creates the file on first run and preserves unrelated keys when
updating individual values. These sections are part of the supported
configuration contract:

| Section | Key paths and purpose |
| --- | --- |
| `[proxyble]` | `install_dir`, `launcher_path`, `log_dir`. |
| `[java]` | Java major version expected by the release, plus whether the current Proxyble install installed Java itself. |
| `[traffic]` | Listener mode: `tcp`, `http`, or `https`. |
| `[riodb]` | `enabled=false` for core installs, plus HAProxy-to-RioDB UDP listener defaults: TCP request-arrival `udp_tcp_request_arrival_log_port=5241`, TCP request-completion `udp_tcp_request_completion_log_port=5242`, HTTP/HTTPS request-arrival `udp_http_request_arrival_log_port=5243`, and HTTP/HTTPS request-completion `udp_http_request_completion_log_port=5244`. When RioDB analytics is enabled, the installer adds RioDB user, group, install root, app subdir, log dir, service name, logger config, and generated keystore settings. |
| `[haproxy]` | Listener/backend values plus map, runtime, and chroot directories. |
| `[nftables]` | Managed nftables family, table, chain, and set names. |
| `[rule_agent]` | Rule-agent binary, inbox, state, and log paths. |

The defaults are intentionally conservative. Operators may edit supported
values, but security-sensitive paths should remain root-owned and should not
be moved to shared temporary directories.

## Installed Application Paths

| Path | Purpose |
| --- | --- |
| `/opt/proxyble` | Installed Proxyble application tree. |
| `/opt/proxyble/proxyble` | Root-owned installer/management binary. |
| `/opt/proxyble/README.md` | Installed customer readme. |
| `/opt/proxyble/LICENSES/` | Installed license bundle. |
| `/opt/proxyble/bin/` | Installed runtime payloads and release settings. |
| `/opt/proxyble/templates/` | Installed RioSQL policy templates and dependencies. |
| `/usr/local/bin/proxyble` | User-facing launcher. |
| `/usr/local/bin/proxyble-rule-agent` | Installed rule-agent binary. |
| `/var/log/proxyble` | Proxyble installer and management action logs. |

`/opt/proxyble/LICENSE` and `/opt/proxyble/NOTICE` are legacy paths. Current
releases install `LICENSES/` instead.

## RioDB Runtime Paths

Default RioDB paths come from `[riodb]` in `config.ini`. They are populated
and used only when `riodb.enabled=true`.

| Path | Purpose |
| --- | --- |
| `/opt` | RioDB archive extraction root. |
| `/opt/riodb` | RioDB application home. |
| `/opt/riodb/sql` | RioDB SQL directory writable by the RioDB service account. |
| `/opt/riodb/conf` | RioDB configuration directory. |
| `/opt/riodb/.ssl/keystore.jks` | Generated self-signed keystore path by default. |
| `/var/log/riodb` | RioDB logs. |
| `/etc/systemd/system/riodb.service` | RioDB systemd unit by default. |

Runtime code, libraries, scripts, and generated installation configuration
should be readable/executable by the RioDB service account but not writable by
that account. Writable RioDB areas are limited to SQL, logs, and runtime data
the engine needs.

## Rule-Agent Runtime Paths

| Path | Purpose |
| --- | --- |
| `/var/spool/proxyble/rules` | Rule-agent handoff directory. Root-only for core installs; writable by the RioDB group when RioDB analytics is enabled. |
| `/var/spool/proxyble/rules/inbox.tmp` | Rule request inbox watched by systemd path unit. |
| `/var/lib/proxyble-rule-agent` | Persistent enforcement state. |
| `/var/lib/proxyble-rule-agent/rule_state_nft.json` | nftables desired-state file. |
| `/var/lib/proxyble-rule-agent/rule_state_haproxy.json` | HAProxy desired-state file. |
| `/var/lib/proxyble-rule-agent/last_reload` | Reload marker. |
| `/var/log/proxyble-rule-agent` | Daily rule-agent logs. |
| `/run/proxyble-rule-agent/rule_agent.lock` | Runtime lock used to serialize rule-agent runs. |
| `/etc/systemd/system/proxyble-rule-agent.service` | One-shot rule-agent service. |
| `/etc/systemd/system/proxyble-rule-agent.path` | Watches the inbox for low-latency rule application. |
| `/etc/systemd/system/proxyble-rule-agent.timer` | Runs once per minute for expiration handling. |

Do not move the handoff back to `/tmp` or `/var/tmp`. The default spool path is
part of the security model.

## Allow-List Runtime Paths

Allow-list state is stored separately from rule-agent state because it is managed
by the Proxyble management binary, not by `proxyble-rule-agent`.

| Path | Purpose |
| --- | --- |
| `/etc/proxyble/allow-list` | Root-only allow-list directory. |
| `/etc/proxyble/allow-list/basic.sources` | Basic allow-list source file, one IPv4 address or CIDR per line. |
| `/etc/proxyble/allow-list/basic.nft` | Rendered Basic nftables batch applied with `nft -f`. |
| `/etc/proxyble/allow-list/endpoint.sources` | Endpoint allow-list source file, one IPv4 address/CIDR and endpoint path per line. |

Default ownership and mode:

```text
/etc/proxyble/allow-list                root:root 0700
/etc/proxyble/allow-list/basic.sources  root:root 0600
/etc/proxyble/allow-list/basic.nft      root:root 0600
/etc/proxyble/allow-list/endpoint.sources root:root 0600
```

When `basic.sources` has entries, Proxyble applies a dedicated
`inet proxyble_allowlist` nftables table that rejects traffic to the configured
Proxyble listening port unless the source is listed. Emptying `basic.sources`
removes that table and disables Basic default-deny behavior.

When `endpoint.sources` has entries, Proxyble renders HAProxy endpoint ACLs for
HTTP/HTTPS modes and reloads HAProxy under the shared HAProxy lock. Requests
matching a listed endpoint path prefix are denied unless the source matches one
of that endpoint's allowed IPv4 addresses or CIDR blocks. Emptying
`endpoint.sources` removes those ACLs and disables endpoint default-deny
behavior.

Core installs keep `riodb.enabled=false`, do not install Java/RioDB, do not
start `riodb.service`, and hide the Policies menu. Adding RioDB later sets
`riodb.enabled=true`, installs RioDB, installs Java only when no working Java
runtime is already present, refreshes the rule-agent handoff ownership,
refreshes HAProxy so the RioDB UDP access-log sink is enabled, and enables the
Policies menu.

Uninstall asks whether to also remove Java JDK whenever RioDB is installed. If
Java removal is selected but no supported Java package is detected, Proxyble
logs a notice and skips Java package removal.

## HAProxy Runtime Paths

| Path | Purpose |
| --- | --- |
| `/etc/haproxy/haproxy.cfg` | Rendered HAProxy configuration. Existing files are backed up before replacement. |
| `/etc/haproxy/maps` | Runtime map directory. |
| `/etc/haproxy/maps/rules.map` | Source-to-action map. |
| `/etc/haproxy/maps/params.map` | Source-to-parameter map. |
| `/etc/haproxy/maps/endpoint-rates.map` | Endpoint-rate map. |
| `/etc/proxyble/allow-list/endpoint.sources` | Source data used to render HAProxy endpoint allow-list ACLs. |
| `/run/haproxy` | HAProxy runtime directory. |
| `/run/haproxy/admin.sock` | HAProxy Runtime API socket. |
| `/var/lib/haproxy` | HAProxy chroot directory. |
| `/etc/tmpfiles.d/haproxy.conf` | Recreates `/run/haproxy` after boot. |
| `/etc/systemd/system/haproxy.service.d/` | Proxyble HAProxy systemd override directory. |

The rule agent updates HAProxy through the Runtime API and map files. Rule
changes should not require HAProxy restarts.

## nftables Runtime Contract

Proxyble manages an nftables table using values from `[nftables]` in
`config.ini`. Defaults:

```text
family:        inet
table_name:    pmgr
managed_chain: managed_rules
input_chain:   input
blacklist_set: blacklist
```

The installer writes a systemd override at:

```text
/etc/systemd/system/nftables.service.d/
```

The override runs:

```text
ExecStartPre=+/usr/local/bin/proxyble --internal-nft-init
```

The bootstrap is idempotent and ensures the Proxyble-managed table and input
hook exist when nftables starts.

## Compatibility Rules

- Keep the release archive as one top-level `proxyble/` directory.
- Keep the install profiles explicit: Proxyble Core must work without RioDB,
  Proxyble + RioDB must require the RioDB EULA before RioDB is installed, and
  adding RioDB later must show only the RioDB notice, Java dependency notice,
  and EULA.
- Keep `LICENSES/`, `bin/`, and `README.md` in the release archive.
- Keep source-maintainer documentation such as `PRODUCT-LAYOUT.md` and
  `DESIGN.md` out of customer release archives.
- Keep `riodb/LICENSES/RIODB-EULA.txt` inside the downloaded RioDB archive as the
  EULA path used by Installation -> License.
- Keep `bin/riodb-settings.json` as the release settings file.
- Keep `/etc/proxyble/config.ini` as the canonical installed configuration.
- Keep `/var/spool/proxyble/rules/inbox.tmp` as the default rule-agent handoff.
- Keep `/etc/proxyble/allow-list/basic.sources` as the Basic allow-list source
  file.
- Keep `/etc/proxyble/allow-list/endpoint.sources` as the Endpoint allow-list
  source file.
- Do not change installed path defaults without updating this layout reference,
  `config.go` or `allowlist.go`, installer tests, `bin/stage.sh`,
  `bin/package.sh`, and deployment documentation together.
