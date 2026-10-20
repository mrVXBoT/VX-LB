# VX-LB Binary Depot

This directory contains Linux binaries used by VX-LB for remote node deployment.

## Layout

- `x86_64/`: 64-bit AMD/Intel Linux binaries.
- `aarch64/`: 64-bit ARM Linux binaries.

When a required binary is available here, VX-LB transfers it to the remote node over the configured SSH connection.

To refresh bundled binaries, run:

```bash
python3 scripts/bundle_binaries.py
```
