# Proxyble Runtime Design

This document is for future maintainers, including future Codex sessions. It
records the runtime contract between HAProxy, RioDB, and the Proxyble rule
agent so feature work does not accidentally weaken the security model or break
the handoff mechanics.

## Names

The enforcement component is currently installed as `proxyble-rule-agent`.
Older notes may call the same role `policy-manager`,
`proxyble-rule-manager`, or `proxyble-rule-agent`. In this document, "rule
agent" means the root-owned Go program that reads RioDB rule decisions and
applies them to HAProxy and nftables.

The installer owns the system configuration. The bundled rule-agent binary is
expected at `bin/proxyble-rule-agent`. The installer does not fetch rule-agent
or RioDB payloads from older release directories.

## High-Level Flow

1. HAProxy accepts client traffic and forwards accepted requests to the
   configured backend server or servers.
2. When RioDB analytics is enabled, HAProxy can emit access-log data to RioDB by
   UDP only. The port is selected by traffic mode and metric layer from the four
   `[riodb]` UDP log port keys in `config.ini`.
3. RioDB receives the log stream, evaluates RioSQL stream processing queries,
   and writes rule decisions as plain text lines to the local rule-agent inbox.
4. `proxyble-rule-agent.path` starts `proxyble-rule-agent.service` when the
   inbox changes.
5. `proxyble-rule-agent.timer` also starts the same service once per minute so
   rule expiration is processed even when no new rules arrive.
6. The rule agent validates and merges the new rules into its JSON state, then
   applies the resulting desired state to nftables and HAProxy.

HAProxy and RioDB do not directly modify firewall or proxy enforcement state.
Only the rule agent is allowed to update nftables and HAProxy runtime maps.

## Trust Boundaries

Proxyble assumes RioDB is useful but not fully trusted. A future RioDB or Java
library compromise should be contained to these capabilities:

- Receive local HAProxy log traffic on RioDB's UDP input.
- Process that traffic inside the RioDB service.
- Append rule-decision lines to the configured inbox file.

RioDB must not be able to write HAProxy configuration, HAProxy maps, nftables
configuration, rule-agent state, Proxyble installer files, or systemd units.
The rule-agent side treats inbox contents as hostile input and re-validates the
rule syntax and target before applying anything.

HAProxy is also intentionally narrow. It emits logs to RioDB only when RioDB
analytics is enabled and enforces the runtime maps that the rule agent
installs. The HAProxy admin socket is used by the root rule agent, not by
RioDB.

## Filesystem Contract

Default rule handoff paths are defined in `config.go`:

```text
rule_dir=/var/spool/proxyble/rules
watch_file=/var/spool/proxyble/rules/inbox.tmp
```

The installer creates the default handoff with these permissions:

```text
/var/spool/proxyble              root:root   0755
/var/spool/proxyble/rules        root:riodb  0710
/var/spool/proxyble/rules/inbox.tmp root:riodb 0620
```

The directory mode is deliberate. RioDB's group can traverse the directory if
it knows the inbox path, but it cannot list, create, delete, or rename files in
the directory. The inbox mode is also deliberate. RioDB can open the file for
write/append through group permission, but it cannot read the file.

Do not move the handoff back to `/tmp` or `/var/tmp`. RioDB runs with
`PrivateTmp=true`, and world-writable temporary trees create avoidable symlink
and path-replacement risks. The installer migrates the old default
`/var/tmp/rules/inbox.tmp` to the spool path while preserving operator-custom
paths.

The installer rejects symlinked handoff paths before managing them. The rule
agent also rejects a symlinked inbox before rotating it. Keep both checks.

## Privileged Path Safety

The installer runs as root, so managed filesystem helpers must fail closed on
symlinks. Use the shared helpers in `system.go` instead of direct
`os.OpenFile`, `os.MkdirAll`, `os.Chown`, or `os.Chmod` calls for installer
owned paths.

Important rules:

- `atomicWriteFile`, `copyFile`, `touchFile`, and lock/log helpers reject
  symlink targets before writing.
- File creation uses `O_NOFOLLOW` where a file is opened directly.
- Managed directory creation rejects symlinked path components before creating
  or chmodding directories.
- Recursive chown/chmod refuses symlink children instead of following them.
- Uninstall removal refuses paths that traverse symlinked parents.

These checks are meant to prevent a compromised service account, stale local
artifact, or operator-customized path from turning a root install action into a
write/chmod/chown/remove operation against an unintended host file.

## RioDB Filesystem Ownership

RioDB runs as the configured `riodb` user, but it should not own every byte of
its installed application tree. The installer hardens the tree after extraction
and after generated files are created:

```text
/opt                             host-owned, not recursively managed
/opt/riodb                       root:riodb 0750
static RioDB directories           root:riodb 0750
static executable files/scripts    root:riodb 0750
static non-executable files/JARs    root:riodb 0640
/opt/riodb/sql                   riodb:riodb 0700
/var/log/riodb                     riodb:riodb 0700
```

This split is intentional. RioDB users may connect through RioDB's own session
interface and create SQL objects, so the SQL area remains writable by RioDB.
Logs are also writable by RioDB. Runtime code, Java libraries, scripts, and
configuration generated during install should be readable/executable by RioDB
but not writable by the RioDB service account.

## RioDB Rule Production

The mandatory RioDB rule queue template is
`templates/RioSQL/00-stream-rule-queue.sql`. The installer copies this template
directly; Proxyble does not generate RioSQL from Go code. It creates a local
RioDB stream named `rule_queue` and writes each selected line to the inbox:

```text
directory '/var/spool/proxyble/rules'
file_name 'inbox.tmp'
cooldown_ms 3000
```

RioDB batches file output with a 3 second cooldown. If the cooldown has already
elapsed while a decision was pending, a new rule may flush immediately. Future
code should not depend on exactly one line per wakeup or exactly one wakeup per
RioDB decision.

Bundled RioSQL inputs and policies live under `templates/RioSQL/`. Policy
deployment copies selected policy files plus declared dependencies from that
directory into RioDB's flat `sql/` directory.

## Rule-Agent Intake

The rule agent is a oneshot program, not a daemon. Its service is started by
systemd path and timer units.

When it starts, it performs these steps:

1. Opens `/run/proxyble-rule-agent/rule_agent.lock` and takes a
   non-blocking `flock`.
2. Exits with success if another rule-agent run is already active.
3. Enforces the `last_reload` backoff so rapid triggers do not create a CPU
   storm.
4. Rotates the inbox to a stable snapshot:
   `/var/spool/proxyble/rules/inbox.tmp` becomes
   `/var/spool/proxyble/rules/inbox.tmp.processing`.
5. Immediately recreates a fresh `root:riodb` inbox with mode `0620`.
6. Parses the `.processing` snapshot and removes it after parsing.

This swap is the central race-avoidance mechanism. RioDB always has an inbox to
append to, while the rule agent processes an immutable snapshot. An empty inbox
is left in place instead of being renamed, which avoids unnecessary path-unit
loops.

The rule agent limits one input batch to 10,000 lines. Extra lines in that
snapshot are skipped and logged. Invalid commands are skipped and logged.

## Rule Syntax And Routing

Each inbox line starts with an action and a source target. The target is an IPv4
address or CIDR for most actions. Single IPv4 addresses are normalized to `/32`.

nftables-only actions:

- `DROP`
- `REJECT`
- `LIMIT_CONCURRENT`
- `LIMIT_CONN_RATE`

`LIMIT_CONCURRENT` and `LIMIT_CONN_RATE` treat a CIDR target as the rule scope,
not as one shared counter. The rule agent creates a per-rule interval set for
the configured source target, then creates a bounded dynamic NFTables set keyed
by `ip saddr` so each matching client IP gets its own connection-count or
connection-rate meter. This keeps `0.0.0.0/0` and large CIDR rules compact in
the ruleset while preserving per-client enforcement.

HAProxy-only actions:

- `LIMIT_BANDWIDTH`
- `TIMEOUT`
- `LIMIT_RATE_SLOW`
- `BUSY_DEFLECTION`
- `LIMIT_ENDPOINT_RATE`

Routing is exclusive. A rule is enforced by either nftables or HAProxy, never
both. If a target moves from one backend to the other, the stale entry is
deleted from the previous backend's state.

`LIMIT_ENDPOINT_RATE` is HTTP/HTTPS-only and single-IP-only. In TCP mode it is
skipped because HAProxy cannot inspect request paths in a TCP passthrough
profile.

`0.0.0.0/0` is treated as dangerous but sometimes intentional. Permanent global
`DROP` and `REJECT` rules are refused; they must include an expiration. Other
global rules are accepted with alert logging.

## State And Logs

The rule agent persists desired enforcement state under
`/var/lib/proxyble-rule-agent`:

```text
rule_state_nft.json
rule_state_haproxy.json
last_reload
```

The directory and files are root-only. State files are the source of truth for
active rules across service restarts and timer runs. The timer is required
because expiration is driven by comparing this state with the current time.

Rule-agent logs are written under `/var/log/proxyble-rule-agent` as daily log
files. The installer and management UI also maintain Proxyble action logs
under `/var/log/proxyble`.

## HAProxy Enforcement

HAProxy configuration is rendered by `haproxy.go`. The relevant runtime pieces
are:

- Conditional UDP logging to RioDB on the configured `[riodb]` metric port:
  TCP request-arrival `5241`, TCP request-completion `5242`,
  HTTP/HTTPS request-arrival `5243`, HTTP/HTTPS request-completion `5244` by
  default.
- HAProxy Runtime API socket at `/run/haproxy/admin.sock`.
- Runtime maps under `/etc/haproxy/maps`.

Default permissions:

```text
/run/haproxy                 root:haproxy                 0750
/etc/haproxy/maps            root:haproxy                 0750
/etc/haproxy/maps/*.map      root:haproxy                 0640
/run/haproxy/admin.sock      root:proxyble-haproxy-admin 0660, level admin
```

The admin socket deliberately uses `proxyble-haproxy-admin`, not the runtime
`haproxy` group. Do not add the `haproxy` service user to
`proxyble-haproxy-admin`. The root rule agent can connect without group
membership. The separate group labels HAProxy admin authority; if a future
non-root admin helper needs to use it, update directory traversal deliberately
instead of adding the HAProxy service user to the admin group.

The rule agent updates HAProxy through the Runtime API. It does not restart
HAProxy for rule changes. It clears and repopulates these maps:

```text
/etc/haproxy/maps/rules.map
/etc/haproxy/maps/params.map
/etc/haproxy/maps/endpoint-rates.map
```

Map changes should remain zero-downtime. Avoid designs that require restarting
HAProxy when a rule is added, expired, or removed.

## nftables Enforcement

The nftables service override installs a pre-start bootstrap:

```text
ExecStartPre=+/usr/local/bin/proxyble --internal-nft-init
```

This ensures a Proxyble-managed `inet pmgr` table and input hook exist when
nftables starts. The bootstrap is idempotent and intentionally small.

When active rules change, the rule agent writes a private temporary nft batch
file and executes:

```text
nft -f <private-temp-file>
```

The batch deletes and recreates the Proxyble-owned `inet pmgr` table in a
single nft transaction, then rebuilds its sets and rules from
`rule_state_nft.json`. Do not add unrelated operator-managed firewall rules to
the `pmgr` table; it belongs to Proxyble and can be rebuilt by the rule agent.

## Basic Allow-List Enforcement

The Basic allow-list is intentionally separate from the rule agent. It applies
only to the configured Proxyble listening port and uses its own nftables table:

```text
/etc/proxyble/allow-list/basic.sources  root:root 0600
/etc/proxyble/allow-list/basic.nft      root:root 0600
inet proxyble_allowlist
```

The allow-list file contains one IPv4 address or CIDR per line. The installer
creates `/etc/proxyble/allow-list` as `root:root 0700` and the Basic source file
as `root:root 0600`. Proxyble renders `basic.nft` from `basic.sources` and
applies it with `nft -f`.

When the Basic allow-list has entries, Proxyble renders an atomic nft batch that
creates an `inet proxyble_allowlist` input hook before the rule-agent `pmgr`
hook. Sources in `basic.sources` are allowed to continue to later firewall and
rule-agent processing. Other TCP traffic to the configured HAProxy listener port
is rejected. When the Basic list is emptied, Proxyble deletes the
`proxyble_allowlist` table so the listener is no longer deny-by-default.

Do not move Basic allow-list rules into `inet pmgr`. The rule agent owns and
rebuilds `pmgr`; allow-list state must remain independent so manual
deny-by-default behavior is not removed by rule-agent reconciliation.

## Endpoint Allow-List Enforcement

Endpoint allow-lists are also separate from the rule agent, but they are enforced
in HAProxy instead of nftables because they depend on HTTP path matching:

```text
/etc/proxyble/allow-list/endpoint.sources  root:root 0600
```

Each non-comment line contains one IPv4 address or CIDR followed by one endpoint
path:

```text
203.0.113.10 /api
198.51.100.0/24 /login
```

Endpoint allow-list is only available in HTTP and HTTPS modes. When entries
exist, Proxyble regenerates `haproxy.cfg` with endpoint ACLs and reloads HAProxy
under the shared HAProxy lock. Requests matching a listed endpoint path prefix
are denied by default unless the request source matches at least one allowed
IPv4 address or CIDR for that endpoint. Emptying `endpoint.sources` removes
those HAProxy ACLs and disables endpoint default-deny behavior.

## Runtime Coordination Locks

Proxyble core and `proxyble-rule-agent` can both mutate shared enforcement
backends, so they coordinate with advisory `flock` locks under a root-only
runtime directory:

```text
/run/proxyble/locks              root:root 0700
/run/proxyble/locks/haproxy.lock root:root 0600
/run/proxyble/locks/nftables.lock root:root 0600
```

The lock directory is created without following symlinks and the lock files are
opened with no-follow semantics. This prevents an untrusted local user from
pre-placing a symlink or permissive lock path that could redirect privileged
writes.

All HAProxy config renders, HAProxy reloads/restarts, HAProxy Runtime API map
updates, and HAProxy map-file rewrites must hold `haproxy.lock`. The rule agent
writes `/etc/haproxy/maps/*.map` while holding this lock before applying the
same state through the Runtime API, so a later HAProxy reload can reconstruct
the active rule maps from disk.

All Proxyble-managed nftables transactions must hold `nftables.lock`, including
Basic allow-list `nft -f`, nftables service pre-start initialization, and
rule-agent `pmgr` batch rebuilds. This does not merge Basic allow-list state into
`inet pmgr`; it only serializes access to the nftables backend.

## systemd Units

`proxyble-rule-agent.service` is intentionally root and oneshot:

```text
Type=oneshot
ExecStart=/usr/local/bin/proxyble-rule-agent <http-or-tcp>
User=root
Group=root
UMask=0077
RuntimeDirectory=proxyble-rule-agent proxyble/locks
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
ReadWritePaths=/var/spool/proxyble/rules
ReadWritePaths=/var/lib/proxyble-rule-agent
ReadWritePaths=/var/log/proxyble-rule-agent
ReadWritePaths=/run/proxyble-rule-agent
ReadWritePaths=/run/proxyble/locks
ReadWritePaths=/etc/haproxy/maps
After=network.target nftables.service haproxy.service
Wants=nftables.service haproxy.service
```

The capability set is deliberately narrow. `CAP_NET_ADMIN` is required for
`nft -f`, `CAP_NET_RAW` is retained for nftables/netlink compatibility, and
`CAP_CHOWN` lets the root process recreate the `root:riodb` inbox after the
file swap. The service should not need general filesystem override capability,
internet sockets, home-directory access, device access, or writes outside the
listed paths. The shared locks runtime directory is created at service startup
and preserved between one-shot runs so Proxyble processes always coordinate on
the same lock files. Its write allowance permits serialized nftables and
HAProxy updates, and the HAProxy maps path is the narrow exception under `/etc`
required for HAProxy-backed rules while `ProtectSystem=strict` is active.

`proxyble-rule-agent.path` watches the inbox:

```text
PathChanged=/var/spool/proxyble/rules/inbox.tmp
Unit=proxyble-rule-agent.service
```

`proxyble-rule-agent.timer` runs once per minute:

```text
OnCalendar=*:0/1
AccuracySec=1s
Unit=proxyble-rule-agent.service
```

The `.path` unit gives low-latency rule application. The `.timer` unit handles
expiration and acts as a backup if a file event is missed. The internal flock is
still required because both triggers can occur at nearly the same time.

RioDB runs as the configured `riodb` user and group with service hardening such
as `ProtectSystem=full`, `ProtectHome=yes`, `PrivateTmp=true`,
`PrivateDevices=yes`, and `NoNewPrivileges=yes`. HAProxy has its own hardening
override in `haproxy.go`, including `PrivateTmp=true`, `ProtectSystem=full`,
capability bounding, namespace restrictions, and restricted address families.

## Change Checklist

When changing the rule handoff path, update all of these together:

- `config.go` defaults.
- `templates/RioSQL/00-stream-rule-queue.sql` RioDB SQL queue output.
- `install.go` `ensureRuleInbox` and systemd path unit rendering.
- `rules.go` manual rule append path.
- utility scripts under `utils/`.
- the rule-agent `inputTmpFile` constant and rotation tests.
- this document.

When changing rule syntax or adding an action, update all of these together:

- rule-agent parser, validation, routing, and state merge logic.
- HAProxy config rendering and map logic when the action is HAProxy-backed.
- nft batch generation when the action is nftables-backed.
- RioDB rule-decision output lines.
- installer tests and rule-agent tests.
- operator documentation and examples.

When changing systemd behavior, preserve these invariants:

- RioDB never gets write access to HAProxy, nftables, rule-agent state, or
  systemd configuration.
- The rule agent can never process two snapshots concurrently.
- Expiration still runs without requiring new RioDB output.
- HAProxy rule updates remain Runtime API map changes, not service restarts.
- nftables rule updates remain atomic batch transactions.
