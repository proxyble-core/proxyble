# Allow-List

Allow-list is a deny-by-default feature for the Proxyble listening port. It does
not protect every port on the server. For whole-server or subnet access control,
use your network firewall or cloud security lists first whenever possible.

Interactive path:

```sh
sudo proxyble
```

Then choose `Allow-list`.

## Basic Allow-List

Basic allow-list protects the listening port. When at least one source is listed,
traffic to the Proxyble listening port is rejected unless the source IPv4 address
or CIDR block is on the allow-list.

Add a source:

```sh
sudo proxyble --basic-allow-list --add 203.0.113.25
sudo proxyble --basic-allow-list --add 198.51.100.0/24
```

Remove a source:

```sh
sudo proxyble --basic-allow-list --remove 203.0.113.25 --yes
```

Remove all Basic allow-list sources:

```sh
sudo proxyble --basic-allow-list --remove-all --yes
```

Removing all sources disables Basic default-deny behavior.

## Endpoint Allow-List

Endpoint allow-list is available only in HTTP and HTTPS modes. It protects
specific HTTP path prefixes on the Proxyble listening port. When an endpoint is
listed, requests to that endpoint are rejected unless the request source matches
one of the allowed IPv4 addresses or CIDR blocks for that endpoint.

Add a source for one or more endpoints:

```sh
sudo proxyble --endpoint-allow-list --add 203.0.113.25 --endpoints /login /api
sudo proxyble --endpoint-allow-list --add 198.51.100.0/24 --endpoints /private
```

Remove a source from an endpoint:

```sh
sudo proxyble --endpoint-allow-list --remove 203.0.113.25 --endpoints /login --yes
```

Remove all Endpoint allow-list entries:

```sh
sudo proxyble --endpoint-allow-list --remove-all --yes
```

Removing all endpoint entries disables Endpoint default-deny behavior.

## Storage

Allow-list state is stored under:

```text
/etc/proxyble/allow-list/
```

These files are managed by Proxyble. Use the wizard or CLI commands instead of
editing them by hand.

Previous: [Logs](08-logs.md)
