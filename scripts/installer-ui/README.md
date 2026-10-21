# Installer UI

The installer uses the checked-in `renderer.bundle.mjs` with a compatible Node.js
runtime (Node 18.16+). No npm install is performed on target servers. The bundle is
probed before use; missing/unsupported Node or a narrow TTY uses the Bash renderer.
The Bash loader also covers the initial curl bootstrap before any local files exist.

The animation adapts the [numbers_5 shell example](https://cliloaders.com/numbers_5)
to VX-LB branding with an 80 ms frame interval. These frames indicate activity,
not a download percentage. Layouts and stage success messages use
[@poppinss/cliui](https://github.com/poppinss/cliui), pinned to 6.4.1 for Node 18 support.
Runtime dependency license texts are in `THIRD_PARTY_LICENSES.txt`.

To rebuild from this directory (development only):

```sh
npm ci --ignore-scripts
npm run build
```

Commit the source, lockfile, bundle and license texts together. The offline kit
already includes `scripts/`, so this renderer travels with it. Do not include
`node_modules` in a release kit.
