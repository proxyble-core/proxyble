# Listener And Backend Setup

Proxyble needs two runtime settings before it can start protecting traffic:

- `Listener`: the public port Proxyble receives client traffic on.
- `Backend`: the app or service Proxyble forwards allowed traffic to.

The listener and backend must both be complete before service start, manual
rules, or policy workflows can run.

## Listener

The listener is the front door. Clients connect to this port first, then
Proxyble decides what to allow, slow down, or block.

Interactive path:

```sh
sudo proxyble
```

Then choose `Config` and `Listener`.

CLI hint:

```sh
sudo proxyble --config-listener --mode tcp --port 443 --timeout 60s --no-start
```

## Listener Prompts

`Change listener configuration?` appears when a listener already exists. Choose
yes if you want to replace the current mode, port, timeout, or certificate.

`Traffic mode` chooses what Proxyble can see:

- `TCP`: Layer 4 traffic. Use this for any raw TCP service and for HTTPS
  pass-through, where Proxyble does not terminate TLS. Proxyble can see IPs and
  connections, but not HTTP paths or headers.
- `HTTP`: unencrypted Layer 7 HTTP. Use this when clients send plain HTTP to
  Proxyble.
- `HTTPS`: encrypted HTTP where HAProxy terminates TLS. Terminating TLS means
  HAProxy decrypts the request with a certificate, so Proxyble can inspect HTTP
  paths and headers before forwarding to the backend.

Use `TCP` for pass-through SSL/TLS. If your application or another proxy behind
Proxyble owns the certificate and decrypts traffic later, Proxyble cannot see
HTTP paths, so the HTTP-only rules are not available.

Use `HTTPS` only when Proxyble should terminate TLS. In this mode, HAProxy needs
a PEM bundle containing the certificate and private key.

CLI hints:

```sh
# HTTPS pass-through. Proxyble does not decrypt TLS.
sudo proxyble --config-listener --mode tcp --port 443 --timeout 60s --no-start

# Plain HTTP.
sudo proxyble --config-listener --mode http --port 80 --timeout 60s --no-start

# HTTPS with TLS termination using an existing PEM bundle.
sudo proxyble --config-listener --mode https --port 443 --timeout 60s --certificate /etc/proxyble/api.pem --no-start
```

`Listener port` is the port clients connect to, such as `80`, `443`, or a custom
API port. Do not set a loopback backend to the same port as the listener.

`Timeout` is the HAProxy client/server timeout, such as `60s`. In plain terms,
it is how long Proxyble waits before giving up on a slow connection or backend
response.

`Listener TLS` appears only for HTTPS mode. You can:

- Provide an existing `.pem` file.
- Generate a self-signed certificate for the current IP address.
- Generate a self-signed certificate for the current hostname.
- Generate a self-signed certificate for a DNS name.

CLI hints:

```sh
# Generate a self-signed certificate for this server's current IP.
sudo proxyble --config-listener --mode https --port 443 --timeout 60s --generate-self-signed --self-signed-for ip --no-start

# Generate a self-signed certificate for a DNS name.
sudo proxyble --config-listener --mode https --port 443 --timeout 60s --generate-self-signed --self-signed-for fqdn --self-signed-fqdn api.example.com --no-start

# Write the generated PEM bundle to a specific path.
sudo proxyble --config-listener --mode https --port 443 --timeout 60s --generate-self-signed --self-signed-for fqdn --self-signed-fqdn api.example.com --self-signed-output /etc/proxyble/api-self-signed.pem --no-start
```

When changing traffic mode on an existing running configuration, Proxyble may
ask whether to reset active rules. This matters because TCP mode supports fewer
rule types than HTTP/HTTPS mode.

CLI hint:

```sh
sudo proxyble --config-listener --mode http --port 80 --timeout 60s --reset-active-rules --no-start
sudo proxyble --config-listener --mode http --port 80 --timeout 60s --keep-active-rules --no-start
```

## Backend

The backend is the protected destination. It is your application server, API
server, local process, container port, or upstream service.

Interactive path:

```sh
sudo proxyble
```

Then choose `Config` and `Backend`.

CLI hint:

```sh
sudo proxyble --config-backend --primary-host 127.0.0.1 --primary-port 8080 --no-start
```

## Backend Prompts

`Change backend configuration?` appears when a backend already exists.

`Primary backend host` is the host or IP address of the main destination. For a
local app, this is often `127.0.0.1`. For another server, use that server's IP
address or DNS name.

`Primary backend port` is the port your app listens on, such as `8080`, `3000`,
or `8443`.

`Secondary backend host` is optional. If you provide it, Proxyble also asks for
`Secondary backend port`. When a secondary backend exists, HAProxy balances
traffic across the two backend servers with round-robin load balancing.

CLI hints:

```sh
# One backend.
sudo proxyble --config-backend --primary-host 127.0.0.1 --primary-port 8080 --no-secondary --no-start

# Two backends.
sudo proxyble --config-backend --primary-host 10.0.0.10 --primary-port 8080 --secondary-host 10.0.0.11 --secondary-port 8080 --no-start

# Save backend and start services immediately if the listener is already complete.
sudo proxyble --config-backend --primary-host 127.0.0.1 --primary-port 8080 --start-services
```

Previous: [Rules only or automated policies](02-rules-only-vs-automated-policies.md)  
Next: [Manual rules](04-manual-rules.md)
