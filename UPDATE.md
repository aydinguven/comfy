# Using setup v4

For a new deployment, download the full `litellm-rhel9.8-x86_64-setup-v4.tar`
and its SHA-256 sidecar, verify the checksum, and extract into a new directory.
Run `sudo python3.12 install.py setup`. Choice 3 installs three LiteLLM gateways
with managed PostgreSQL/Redis on node 1 only, or existing external services.
Review CLUSTER.md for the lack of datastore failover in this placement.

The small `litellm-rhel9.8-x86_64-setup-update-v4.tar` contains only updated
installer files, guides, reset/CA-repair helpers and their checksums. It does
not contain LiteLLM application payloads, RPMs or the optional HA payload.
Its extraction root matches the full bundle: `litellm-rhel9.8-x86_64`.

For an incomplete bootstrap on the same topology, verify its sidecar, back up
your old extracted installer files, then extract the small update over that
installer directory (from its parent). Keep the original full application
bundle and its matching sidecar in place. Run the updated `install.py setup`,
choose Resume, and keep selecting that ORIGINAL full bundle. The saved plan,
credentials, CA key and bound full-bundle checksum must remain unchanged. Do
not select the small update as the application bundle. The wizard can offer
the key-preserving CA extension repair if needed.

Replacing an attempted deployment's bound full bundle with the new full v4 tar
is deliberately refused. Use the small installer update with the original
bundle for a bootstrap retry. A working deployment does not need to be rerun
to use its UI; perform live application/infrastructure upgrades separately.
Changing an existing one-node plan into three gateways is an explicit migration,
not a Resume operation. Preserve database contents, keys and CA until that
migration has been planned and verified.
