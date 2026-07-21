# Proxyble RioSQL Templates

This directory contains shared RioSQL stream and window templates plus the policy catalog used by Proxyble.

Proxyble reads policy `.sql` headers from `policies/`, displays each policy's name, summary, visibility, and deployment details, then recursively copies declared dependencies into RioDB's SQL directory.

Policy query files live in `policies/` so Proxyble can distinguish deployable policy choices from shared stream and window dependencies. RioDB loads files from a flat SQL directory on restart, so selected files should be copied into the target SQL directory without preserving the `policies/` subdirectory.

`00-stream-rule-queue.sql` is mandatory for every RioDB-enabled Proxyble install. It creates the local `rule_queue` stream that writes decisions to the proxyble-rule-agent inbox. The installer and policy deploy actions always copy it, and policy removal never prunes it.
