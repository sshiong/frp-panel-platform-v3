# License policy

The release dependency policy permits the following SPDX identifiers for the
bundled web dependencies: `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`,
`ISC`, `Python-2.0`, and `BlueOak-1.0.0`. Copyleft licenses that require source
distribution of the complete product (`GPL`, `AGPL`, `SSPL`, and `BUSL`) are
blocked by `scripts/license-policy.rb`.

The check reads the committed npm lockfiles, requires every resolved package to
declare a license, and runs in local `make license` and CI. Go module licensing
must be reviewed when the dependency graph changes; the generated SPDX SBOM
keeps those module entries as `NOASSERTION` until a release owner records the
upstream license evidence.
