# Maintained downstream Headscale build

This package builds Headscale **0.29.4 at commit `8106636c7f8d0cf8c9d4fb0beae94415069b768b`**, with explicit security backports and a local diagnostic-route removal. It builds from the locked upstream source archive; it does not modify any upstream checkout, create Git commits, deploy a service or certify production security.

```sh
python3 scripts/build_headscale.py prepare
python3 scripts/build_headscale.py verify
python3 scripts/build_headscale.py build
```

`build` verifies every source/patch hash, executes required Go regressions with the race detector, compiles a static binary in a digest-pinned official Go container, builds a digest-pinned distroless image, and checks the image's non-root user and an offline `version` invocation. It never publishes container ports. Docker and Git are required on the build machine. The default target matches the Docker daemon; `--platform linux/amd64` or `--platform linux/arm64` selects an explicit target. Cross-platform tests can require Docker emulation and are slower.

Outputs:

- Disposable source: `.cache/covee/deploy/headscale-src/`.
- Local image: `covee-headscale:hardened-local`.
- Build manifest: `.cache/covee/deploy/headscale-build/manifest.json`.
- Required-test results and logs: `.cache/covee/deploy/headscale-build/test-results.json` and `security-tests.log`.
- Static binary: `.cache/covee/deploy/headscale-build/bin/headscale`.

The manifest records source/archive/patch hashes, builder/runtime image digests, platform, binary hash, local image ID and checks. This is a local artifact manifest, not a registry signature or independent security review. Upstream's source-built `version` command reports `dev`; the pinned source, downstream version and patchset are recorded in the manifest and OCI image labels.

The prepared tree is immutable to the build. Unexpected files, altered executable bits, source edits, patch drift or missing mandatory test passes stop the build. `prepare --reset-source` deliberately regenerates only this disposable source cache from the verified archive. The verified patch application is deterministic; it does not resolve conflicts or fetch a moving branch.

## Patch provenance

`source-lock.json` pins the upstream source archive, the exact preserved upstream patch bytes in `upstream/`, and the actually applied downstream patches in `patches/`.

1. [PR 3526](https://github.com/juanfont/headscale/pull/3526): reject/re-decide consumed SSH-check verdicts instead of accepting the zero value from a closed channel. The official 0.29 backport is `6f27bf8d7a527e3d0a94b8805caaa90d0959c067`.
2. [PR 3517](https://github.com/juanfont/headscale/pull/3517): send explicit empty SSH policies when rules disappear or compilation fails, and re-check the current rule and concrete login user before and after authentication. Adapted from official 0.29 backport `77b96cbf03daca3078ea7e0712cf33f3adf9a0ff`. Performance-only SSH-policy delta deduplication is omitted because it depends on unrelated newer mapper changes; security behavior and regressions are retained.
3. [PR 3522](https://github.com/juanfont/headscale/pull/3522): send the configured logtail instruction on every initial/full map and the expired-self frame. Runtime and tests derive from `cced8a0aba230c2a0e52ae4679611f079747727b` and `01db1dec884d2aee2d249569601e203265fd6aff`, adapted for the pinned Tailscale module and fixture APIs.
4. Local patch: remove `/metrics` from the inner Noise router. A regression establishes a real authenticated Noise transport using a never-enrolled machine key, performs inner HTTP/2 requests, and requires both `/metrics` and `/metrics/` to return 404 without enrolling a node.
5. Local patch `0003-covee-sign-in-pages.patch`: present Headscale's two device sign-in pages, the confirmation and the result, as Covee. It uses the Covee mark and favicon, loads no web fonts from Google, says "device" and "network" instead of "node" and "tailnet", removes the Headscale and Tailscale documentation links, and matches the broker's page style. Behavior is unchanged. Headscale's template and OIDC tests are updated to the new wording and pass with the patch; the build's required regressions do not involve these pages.

The original fixes were reviewed and merged upstream. Their official 0.29 backports are currently part of draft [PR 3544](https://github.com/juanfont/headscale/pull/3544); this package does not claim that draft is an approved release. Our adapted patchset also needs ongoing review when the source pin changes.

Required regressions cover SSH rule removal in a real control client, fail-closed empty SSH policies, login-user rule matching, post-verdict policy changes, consumed and concurrent verdict replay, initial/reconnected map logtail behavior, expired-self frames and inner Noise metrics denial. This does not replace signed Apple acceptance, Entra testing, external ingress checks, recovery testing or dependency/advisory review.

The final image runs `/headscale` as UID/GID `10001:10001`, contains CA certificates, and has no shell or package manager. The deployment must still supply properly owned persistent state, read-only configuration/secrets, verified upstream TLS, resource limits and private administration. See [the deployment requirements](../../docs/production-deployment.md).
