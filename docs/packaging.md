# Meson and Fedora RPMs

Sylva is licensed under GPL-3.0-only; see [LICENSE](../LICENSE). The Fedora
packaging builds two independent packages: `sylva` (CLI) and `sylvad` (optional
self-hosted server and systemd service). Git-backed clients need only `sylva`.

## Build locally

Use the minimum Go patch version from `go.mod`, Python 3, Meson >= 1.3 and Ninja.
For Fedora RPMs also install the RPM and systemd build macros:

```sh
sudo dnf install golang meson ninja-build python3 rpm-build redhat-rpm-config systemd-rpm-macros git-core
make build
bin/sylva version
bin/sylvad -version
```

`make build` configures Meson in `bin/` and asks it to compile both Go programs.
Go still manages dependencies and incremental compilation. The binaries use
position-independent code, trimmed source paths and an embedded version.
`make build-cli` and `make build-daemon` select one binary. Existing Go checks,
coverage and Docker E2E targets remain available.

Direct Meson use is supported too:

```sh
meson setup build --prefix=/usr
meson compile -C build
meson test -C build --print-errorlogs
DESTDIR="$PWD/stage" meson install -C build
```

Meson installs both binaries, service files, server configuration and licensing
documentation. For a system installation prefer RPMs, which also create the
service user and assign configuration ownership. An administrator using a
direct Meson installation must create the account using `systemd-sysusers`
and grant the `sylva` group read access to `/etc/sylva/sylvad.conf`.

## Create RPMs

```sh
make                         # build with Meson, verify packaging, then build RPMs
make rpm VERSION=1.2.3        # override the development / exact-tag version
make sources VERSION=1.2.3    # source archive and generated spec only
make changelog VERSION=1.2.3  # preview RPM changelog from Git history
```

An exact `vX.Y.Z` tag supplies the default version. Untagged builds use `VERSION`.
Prereleases such as `v1.2.3-rc.1` are supported and become `1.2.3~rc.1` in RPM
metadata so they sort before the final release. Binary version output keeps
`1.2.3-rc.1`. Build metadata (`+...`) is deliberately rejected.

Artifacts appear in `dist/<version>/`: CLI and daemon RPMs, a source RPM, a
vendored `.tar.gz`, the generated `sylva.spec`, `CHANGELOG.rpm.txt`, sysusers source,
and `SHA256SUMS`. Temporary RPM build files stay in its `rpmbuild/` subdirectory.
`BUILD_DIR`, `DIST_DIR`, `GO`, `MESON`, `PYTHON` and `RPMBUILD` are Make overrides.
`RPMBUILD_FLAGS` passes optional flags to rpmbuild; normal builds check all
BuildRequires. `make clean` removes binaries; release artifacts are retained.

The spec template is [sylva.spec.in](../packaging/rpm/sylva.spec.in).
Source preparation downloads the Go modules pinned by `go.mod`/`go.sum` and
vendors them into the archive. RPM compilation sets `GOPROXY=off`, `GOSUMDB=off`
and `GOTOOLCHAIN=local`, then uses Meson with `-Doffline=true`. Dependency notices,
the Go standard library license and a module inventory are included as
`THIRD_PARTY_LICENSES`. Bundled Go modules receive RPM `Provides` metadata.
These are upstream Fedora RPMs; inclusion in Fedora's own repositories would
need its separate package review and dependency/licensing review.

Changelog entries use commit subjects and hashes, grouped by reachable release
tags along the first-parent history. Each range includes merged commits, and
headers use the release commit's UTC date and author. RPM macro characters in
Git messages are escaped. Full Git history is required during source preparation;
the source archive embeds the resulting changelog so RPM rebuilds need no Git
checkout. Only explicit source file types are copied; vaults, local `.env`,
certificates, keys and build artifacts are excluded.

## Install and operate the server

```sh
sudo dnf install ./dist/1.2.3/sylva-1.2.3-1.fc44.x86_64.rpm
# Optional: install on the host that will store the encrypted vault.
sudo dnf install ./dist/1.2.3/sylvad-1.2.3-1.fc44.x86_64.rpm
sudo systemctl enable --now sylvad.service
systemctl status sylvad.service
journalctl -u sylvad.service
```

The service runs as `sylva`, with state and SQLite files under `/var/lib/sylva`
(mode `0700`) and a restrictive umask. Its default listener is `127.0.0.1:8443`.
It reads `/etc/sylva/sylvad.conf` and optional root-only environment variables
from `/etc/sysconfig/sylvad`; it does not read the invoking user's `.env` or
client `.sylva/config`. Packaged configurations use `%config(noreplace)` so local
edits survive upgrades. State is retained on package removal.

For remote access, configure [mTLS](mtls.md) or [Tailscale](tailscale.md) before
changing the listener. Place service certificates under `/etc/sylva/certs`,
grant the `sylva` group the required read access, and restart the service after
configuration changes. For Tailscale, use the packaged state directory and put
the optional auth key in `/etc/sysconfig/sylvad`. Systemd limits writable paths
to the service state directory and hides user home directories.
