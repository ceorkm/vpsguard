# Releasing vpsguard

The release workflow runs on every `v*` tag. It builds the binaries, the
`.deb`/`.rpm` packages, the cosign-signed checksums, and (re)publishes the
APT repository on the `gh-pages` branch.

## One-time setup

These steps are needed once per repo for `apt install vpsguard` to work
end-to-end. Skipping them still produces a working release (raw binaries,
`.deb` / `.rpm` files, checksums) — the only thing that breaks is the
self-hosted APT repo's GPG signature.

### 1. Generate a GPG key for signing the APT Release file

```bash
gpg --full-generate-key                    # RSA 4096, "vpsguard signing key"
gpg --armor --export-secret-keys KEY-ID > vpsguard-signing.asc
```

### 2. Add the private key as a GitHub Actions secret

```bash
gh secret set VPSGUARD_GPG_KEY < vpsguard-signing.asc --repo ceorkm/vpsguard
```

Then **delete the local file**:

```bash
shred -u vpsguard-signing.asc
```

### 3. Enable GitHub Pages on the `gh-pages` branch

`Settings → Pages → Source: Deploy from a branch → gh-pages → /` (root).

The first release tag will create the branch and populate it.

## Cutting a release

```bash
git tag v0.3.0 -m "first public release"
git push origin v0.3.0
```

Wait ~3 min, then:

- Releases page shows binaries, `.deb`, `.rpm`, checksums, signature.
- `https://ceorkm.github.io/vpsguard/` shows the APT install snippet.
- `apt-get update && apt-get install vpsguard` works on Debian/Ubuntu.

## Rolling back a release

```bash
gh release delete v0.3.0 --yes --cleanup-tag
git push --delete origin v0.3.0
```

The next tag re-runs everything.
