# Installation

The repository provides `install.sh` (POSIX sh) and `install.ps1` (Windows
PowerShell 5.1 / PowerShell 7). They install or upgrade the executable, verify
release SHA-256 checksums, and preserve configuration and credentials. Like the
[Hysteria 2 official installer](https://v2.hysteria.network/docs/getting-started/Server-Installation-Script/),
they create an example configuration; configure your node before starting it.

Published releases contain all platform binaries, both installers and
`SHA256SUMS`. The release workflow verifies the complete bundle before creating
a draft for publication.

## Install, upgrade, remove

On Linux / FreeBSD:

```sh
curl -fsSL https://github.com/LiuTangLei/braidpath/releases/latest/download/install.sh -o install-braidpath.sh
sudo sh install-braidpath.sh
# On OpenWrt, run sh as root; sudo is not required.
```

On macOS, use the same download, then `sh install-braidpath.sh` **without sudo**.
It installs for the login user. Rerunning the installer upgrades the executable.
An already running Unix service continues using the old executable until you
restart it; the installer never starts or restarts it automatically.

```sh
sh install-braidpath.sh --dry-run             # Plan only; no network/writes
sudo sh install-braidpath.sh --version v0.2.0 # Choose a published version
sudo sh install-braidpath.sh --check         # Compare installed/latest
sudo sh install-braidpath.sh --remove        # Keep config, keys and state

# User installation or a system without a supported service manager:
sh install-braidpath.sh --prefix "$HOME/.local" --service none
# Use the same --prefix and --service options when upgrading/removing.
```

Windows:

```powershell
Invoke-WebRequest -UseBasicParsing https://github.com/LiuTangLei/braidpath/releases/latest/download/install.ps1 -OutFile install-braidpath.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-braidpath.ps1 -AddToPath
# Optional startup at the current user's login, with limited privileges:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-braidpath.ps1 -StartupTask
# Other operations:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-braidpath.ps1 -Check
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-braidpath.ps1 -Version v0.2.0
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-braidpath.ps1 -Remove
```

Windows defaults to `%LOCALAPPDATA%\BraidPath`. `-InstallDir` changes it;
`-Architecture amd64|arm64|386` overrides detection. Stop an existing BraidPath
process from that directory before upgrading. `-AddToPath` updates only the
user PATH; open a new terminal to use it. Uninstall removes only the PATH entry
it added. The optional login task is **not** a Windows SCM service and does not
run before login. Its name is `BraidPath-<current-user-SID>`.

For an offline/local installation from a checkout:

```sh
cargo build --release --locked --bin braidpath
sh install.sh --local ./target/release/braidpath --prefix "$HOME/.local" --service none
# Optional externally supplied local-file digest:
sh install.sh --local ./target/release/braidpath --sha256 HEX_DIGEST --prefix "$HOME/.local" --service none
```

Use `-Local .\target\release\braidpath.exe` and optionally `-Sha256 HEX_DIGEST`
on Windows. A local file is explicitly trusted input; remote downloads always
require an exact checksum entry and matching executable version before replacing
the installed binary. Downloads use the canonical project release. Checksums
protect integrity under GitHub/HTTPS trust; they are not an independent signature.

## Targets and prerequisites

This is the **configured release build matrix**, not a claim that every target
has already passed native deployment acceptance. A failed/missing target blocks
the release draft. CPU selection accounts for 32-bit Linux userspace on a
64-bit kernel and selects native Apple Silicon under Rosetta.

| System | Release architectures | Packaging / installer |
| --- | --- | --- |
| Linux | amd64, 386, arm64, armv7, armv6 | Static musl binaries; POSIX sh |
| macOS | amd64, arm64 | Native Mach-O; per-user install / LaunchAgent |
| Windows | amd64, 386, arm64 | MSVC with static CRT; PowerShell |
| FreeBSD | amd64 | Native FreeBSD 14.4 VM build; POSIX sh / rc.d |

Linux builds serve both glibc and musl distributions, including Debian, Ubuntu,
Fedora, RHEL-family distributions and Alpine. ARMv6/ARMv7 builds use the
**little-endian hard-float ABI**. OpenWrt support is limited to these matching
CPU/ABI targets; MIPS, ARMv5, big-endian ARM and soft-float are not covered.
There are no Android/iOS application packages or binaries for RISC-V, LoongArch,
PowerPC, NetBSD or OpenBSD in this matrix.

Unix download requirements: POSIX sh, standard file tools, `curl` or GNU `wget`
with `--https-only`, and one of `sha256sum`, `shasum` or FreeBSD `sha256`.
BusyBox ash is supported; BusyBox wget alone is insufficient. The installer does
not run a package manager, change firewall rules, or configure NAT. Native system
requirements also follow [Rust's target support](https://doc.rust-lang.org/rustc/platform-support.html)
and the selected build environment; choosing an architecture cannot make an
obsolete OS compatible.

## Configuration and service managers

Unix `args` contains **one literal CLI argument per line**. Blank lines and lines
starting with `#` are ignored; there is no shell expansion, sourcing or `eval`.
Windows `args.json` is a JSON array of literal argument strings; embedded quotes,
empty arguments and trailing backslashes are preserved on PowerShell 5.1 and 7.
Edit `CHANGE_ME:4433`, node ID and target before starting. Both examples use
`mesh-server`, a dedicated `node` child directory and `--relay-ports 44400-44463`.
Allow UDP at the service port and that relay range, or adjust the range for your
firewall/NAT. The first start initializes keys; subsequent starts reuse them.
For joining another server or using client mode, use arguments from the
[distributed-server guide](mesh.md). Store keys in the private state directory,
and use absolute file paths readable by the service account in arguments rather
than embedding secrets. The original `--join`/`--join-key` arguments may stay in
the service configuration after enrollment; saved identity and peers allow restart
without the original server or imported key file.

| Manager | Config / state | Start after configuring |
| --- | --- | --- |
| systemd | `/etc/braidpath/args`, `/var/lib/braidpath/node` | `systemctl enable --now braidpath.service` |
| OpenRC | same Linux paths | `rc-update add braidpath default` then `rc-service braidpath start` |
| OpenWrt procd | same Linux paths | `/etc/init.d/braidpath enable` then `/etc/init.d/braidpath start` |
| FreeBSD rc.d | `/usr/local/etc/braidpath/args`, `/var/db/braidpath/node` | `sysrc braidpath_enable=YES` then `service braidpath start` |
| macOS LaunchAgent | `~/.config/braidpath/args`, `~/.local/share/braidpath/node` | `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.braidpath.plist` |
| Windows login task | `%LOCALAPPDATA%\BraidPath\args.json`, `state\node` beneath that install | Start the registered BraidPath task in Task Scheduler |
| No manager | `PREFIX/etc/braidpath/args`, `PREFIX/var/lib/braidpath/node` | `PREFIX/libexec/braidpath-run PREFIX/etc/braidpath/args` |

System services run as a dedicated `braidpath` account, created through `useradd`,
BusyBox `adduser`, or FreeBSD `pw`. OpenWrt installations without these tools
must create that account first. The account and its data are retained on
uninstall. macOS and Windows tasks use the current login user's permissions.
System service paths must contain only letters, digits, `_`, `.`, `/`, `-`;
custom binary-only prefixes and Windows paths may contain spaces/quotes.

Use `--service systemd|openrc|procd|rc|launchd|none` to select explicitly. Automatic
selection is disabled for custom prefixes. Existing services/binaries without
an installer ownership marker are not overwritten. Keep systemd local changes
in drop-ins; generated service definitions are refreshed during an upgrade.
For restarting a running installation use the manager's `restart` command, or
`launchctl kickstart -k gui/$(id -u)/org.braidpath` on macOS. Unix binary replacement
is atomic, but the upgrade is not a transaction across OS service configuration.

## Build and validation

`scripts/release-targets.json` is the asset/matrix source. The release workflow
runs the existing CI, builds 11 targets, runs their `--version` smoke checks
(natively, in a FreeBSD VM, or under cross/QEMU), verifies executable headers,
and produces `SHA256SUMS`. Builds and CI run concurrently; assembly requires
both to pass. Tag versions must match `Cargo.toml`. A manual workflow run or a
push to `codex/build-*` only uploads artifacts; a tag run creates a reviewable draft, never an
automatically published release. See the workflow logs before publishing.
A manual run may select `linux`, `native` or `freebsd` to diagnose that family;
partial runs upload individual artifacts and cannot assemble or draft a release.

Installer tests cover architecture selection, safe argument handling, verified
downloads, integrity rejection, install/upgrade/uninstall preservation, concurrent
install rejection and binary header validation. PowerShell lifecycle tests run
on Windows CI. Local container/template checks do not establish native OpenRC,
procd, FreeBSD, Windows startup-task or public-network acceptance.
