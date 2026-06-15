# Runtime Payloads And Project Tools

Release builds place runtime payloads here for standalone distribution:

- `proxyble-rule-agent`
- `riodb-settings.json`

`proxyble-rule-agent` is built from `../proxyble-rule-agent/` by the package
and staging scripts. Do not edit the binary directly.

This directory also holds source-repository helper scripts:

- `stage.sh`
- `test-cli.sh`
- `package.sh`
- `package-arm.sh`

Those scripts are excluded from staged installs and customer release archives.

The RioDB archive filename/path is configured by `riodb.archive_path` in
`riodb-settings.json`. If the archive is missing when RioDB analytics is
selected, the installer downloads it into `bin/` from `riodb.download_servers`
before extraction.

The full release payload and installed path contract is documented in
`../PRODUCT-LAYOUT.md`.
