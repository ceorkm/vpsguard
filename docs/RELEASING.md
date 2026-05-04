# Releasing vpsguard

The release workflow runs on every `v*` tag. It builds:

- Linux binaries for amd64 and arm64
- `.deb` and `.rpm` package files as GitHub Release assets
- `checksums.txt`
- a cosign bundle for the checksum file

## Cutting a release

```bash
git tag v0.3.0 -m "first public release"
git push origin v0.3.0
```

Wait for the GitHub Actions release workflow to finish, then verify:

- the GitHub Releases page has `vpsguard-linux-amd64`
- the GitHub Releases page has `vpsguard-linux-arm64`
- the GitHub Releases page has `.deb` and `.rpm` files
- `checksums.txt` includes every uploaded binary/package
- `checksums.txt.bundle` exists
- the raw installer can download and install the release on a clean Linux VPS

## Public install command

After the first release exists, the supported public install path is:

```bash
curl -fsSL https://raw.githubusercontent.com/ceorkm/vpsguard/main/packaging/install.sh | sudo bash
```

## Rolling back a release

```bash
gh release delete v0.3.0 --yes --cleanup-tag
git push --delete origin v0.3.0
```

The next tag re-runs everything.
