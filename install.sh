#!/bin/sh
# BraidPath installer. POSIX sh: works with dash, BusyBox ash and macOS sh.
# SPDX-License-Identifier: Apache-2.0
set -eu

REPO=https://github.com/LiuTangLei/braidpath
API=https://api.github.com/repos/LiuTangLei/braidpath/releases/latest
operation=install
version=
local_file=
expected_hash=
architecture=
prefix=
service=auto
dry_run=0
work=
staged=
lock=
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
has() { command -v "$1" >/dev/null 2>&1; }
cleanup() {
    [ -z "$staged" ] || rm -f "$staged"
    [ -z "$work" ] || rm -rf "$work"
    [ -z "$lock" ] || rmdir "$lock"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
usage() {
    cat <<'HELP'
Usage: sh install.sh [options]
  --version vX.Y.Z       Install a specific release (default: latest stable)
  --local FILE          Install a trusted local executable without downloading
  --sha256 HEX          Expected SHA-256 for --local (downloads always verify)
  --prefix DIR          Install into DIR/bin (custom prefix defaults to no service)
  --arch ARCH           amd64, arm64, 386, armv7 or armv6
  --service MODE        auto, none, systemd, openrc, procd, rc, launchd
  --check               Show installed and latest stable version; change nothing
  --remove              Remove installed program/service; retain all config/keys
  --dry-run             Print the plan without downloads or system changes
  --print-target        Print the detected release asset name and exit
  -h, --help            Show help

Initial installation creates an example argument file but does not start a server.
Upgrades preserve configuration and keys. Restart a running service after upgrading.
Windows: use install.ps1. No automatic package-manager or firewall modifications.
HELP
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version|--local|--sha256|--prefix|--arch|--service)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then fail "Missing value for $1"; fi
            case "$1" in
                --version) version=$2;; --local) local_file=$2;; --sha256) expected_hash=$2;;
                --prefix) prefix=$2;; --arch) architecture=$2;; --service) service=$2;;
            esac
            shift 2;;
        --check|--remove|--print-target)
            [ "$operation" = install ] || fail 'Choose only one operation'
            operation=${1#--}; shift;;
        --dry-run) dry_run=1; shift;;
        -h|--help) usage; exit 0;;
        *) fail "Unknown option: $1";;
    esac
done
[ -z "$version" ] || [ -z "$local_file" ] || fail '--version and --local are mutually exclusive'
[ -z "$expected_hash" ] || [ -n "$local_file" ] || fail '--sha256 requires --local'
if [ "$operation" != install ]; then
    [ -z "$version$local_file$expected_hash" ] || fail 'Install options cannot be used with this operation'
fi
validate_version() {
    case "$1" in v[0-9]*) ;; *) fail "Invalid release version: $1";; esac
    case "$1" in *[!a-zA-Z0-9._-]*) fail 'Invalid characters in release version';; esac
}
[ -z "$version" ] || validate_version "$version"
if [ -n "$expected_hash" ]; then
    [ "${#expected_hash}" -eq 64 ] || fail 'SHA-256 must contain 64 hexadecimal characters'
    case "$expected_hash" in *[!a-fA-F0-9]*) fail 'Invalid SHA-256';; esac
    expected_hash=$(printf '%s' "$expected_hash" | tr 'A-F' 'a-f')
fi
case "$(uname -s)" in
    Linux) os=linux;; Darwin) os=darwin;; FreeBSD) os=freebsd;;
    MINGW*|MSYS*|CYGWIN*) fail 'Use install.ps1 in Windows PowerShell';;
    *) fail 'Supported systems: Linux, macOS, FreeBSD; Windows uses install.ps1';;
esac
if [ -z "$architecture" ]; then
    case "$(uname -m)" in
        x86_64|amd64) architecture=amd64;;
        aarch64|arm64) architecture=arm64;;
        i386|i486|i586|i686|x86) architecture=386;;
        armv7*|armv8l) architecture=armv7;;
        armv6*) architecture=armv6;;
        *) fail "No release target for $(uname -m); see docs/install.md";;
    esac
    # Select the userspace ABI, which can differ from the running Linux kernel.
    if [ "$os" = linux ]; then
        bits=$(getconf LONG_BIT 2>/dev/null || true)
        if [ -z "$bits" ] && has od; then
            class=$(od -An -t u1 -j 4 -N 1 /bin/sh | tr -d ' ')
            [ "$class" != 1 ] || bits=32
        fi
        if [ "$bits" = 32 ]; then
            case "$architecture" in amd64) architecture=386;; arm64) architecture=armv7;; esac
        fi
    elif [ "$os" = darwin ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
        architecture=arm64
    fi
fi
case "$os/$architecture" in
    linux/amd64|linux/arm64|linux/386|linux/armv7|linux/armv6|darwin/amd64|darwin/arm64|freebsd/amd64|freebsd/arm64) ;;
    *) fail "No supported release asset for $os/$architecture";;
esac
asset=braidpath-$os-$architecture
[ "$operation" != print-target ] || { say "$asset"; exit 0; }
custom_prefix=0
if [ -n "$prefix" ]; then custom_prefix=1
elif [ "$os" = darwin ] || [ "$(id -u)" != 0 ]; then prefix=$HOME/.local
else prefix=/usr/local
fi
case "$prefix" in /*) ;; *) fail '--prefix must be an absolute path';; esac
prefix=${prefix%/}
[ -n "$prefix" ] || fail 'The filesystem root is not an installation prefix'
if [ "$service" = auto ]; then
    service=none
    if [ "$custom_prefix" = 0 ]; then
        if [ "$os" = darwin ] && [ "$(id -u)" != 0 ]; then service=launchd
        elif [ "$(id -u)" = 0 ]; then
            if [ "$os" = freebsd ]; then service=rc
            elif [ -d /run/systemd/system ] && has systemctl; then service=systemd
            elif [ -r /etc/rc.common ] && has ubus; then service=procd
            elif has rc-service; then service=openrc
            fi
        fi
    fi
fi
case "$os/$service" in
    */none|linux/systemd|linux/openrc|linux/procd|freebsd/rc|darwin/launchd) ;;
    *) fail "Service manager $service is not supported on $os";;
esac
binary=$prefix/bin/braidpath
wrapper=$prefix/libexec/braidpath-run
metadata=$prefix/lib/braidpath
if [ "$service" = launchd ]; then
    config=$HOME/.config/braidpath
    state=$HOME/.local/share/braidpath
    unit=$HOME/Library/LaunchAgents/org.braidpath.plist
elif [ "$service" = none ]; then
    config=$prefix/etc/braidpath
    state=$prefix/var/lib/braidpath
    unit=
else
    config=/etc/braidpath
    state=/var/lib/braidpath
    case "$service" in
        systemd) unit=/etc/systemd/system/braidpath.service;;
        openrc|procd) unit=/etc/init.d/braidpath;;
        rc) config=/usr/local/etc/braidpath; state=/var/db/braidpath; unit=/usr/local/etc/rc.d/braidpath;;
    esac
fi
# Service formats have different escaping rules; constrain generated service paths.
if [ "$service" != none ]; then
    case "$prefix$config$state$unit" in *[!a-zA-Z0-9_./-]*) fail 'Service paths must use letters, digits, _, ., / or -; use --service none for other paths';; esac
fi
if [ "$dry_run" = 1 ]; then
    say "operation=$operation asset=$asset version=${version:-latest} binary=$binary service=$service config=$config state=$state"
    exit 0
fi
fetch() {
    if has curl; then
        curl -q --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 "$1" -o "$2"
    elif has wget && wget --help 2>&1 | grep -q -- '--https-only'; then
        wget --https-only --timeout=30 --tries=1 -q -O "$2" "$1"
    else fail 'Install curl or GNU wget with HTTPS support first'
    fi
}
new_work() { work=$(mktemp -d "${TMPDIR:-/tmp}/braidpath-install.XXXXXX"); }
latest() {
    fetch "$API" "$work/release.json" || fail 'Cannot resolve latest release. A published release is required; use --local for a local build.'
    version=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$work/release.json")
    validate_version "$version"
}
if [ "$operation" = check ]; then
    new_work; latest
    installed=not-installed
    [ ! -x "$binary" ] || installed=$("$binary" --version)
    say "Installed: $installed"
    say "Latest: $version"
    exit 0
fi
if [ "$service" != none ] && [ "$service" != launchd ]; then
    [ "$(id -u)" = 0 ] || fail 'System service installation requires root; use --service none for a user install'
fi
[ "$service" != launchd ] || [ "$(id -u)" != 0 ] || fail 'Run the launchd installer as the login user, without sudo'
mkdir -p "$metadata"
mkdir "$metadata/install.lock" 2>/dev/null || fail 'Another installer is running (or a stale install.lock needs inspection)'
lock=$metadata/install.lock
if [ -f "$metadata/installed" ]; then
    [ "$(sed -n '1p' "$metadata/installed")" = 'BraidPath installer v1' ] || fail 'Unrecognized installation receipt'
    previous_service=$(sed -n '2p' "$metadata/installed")
    [ "$previous_service" = "$service" ] || fail "Existing install uses $previous_service; use --service $previous_service"
elif [ "$operation" = remove ]; then fail "No managed installation at $prefix"
elif [ -e "$binary" ]; then fail "Refusing to overwrite unmanaged $binary"
fi
if [ -n "$unit" ] && [ -e "$unit" ]; then
    grep -q 'Managed by BraidPath installer' "$unit" || fail "Refusing to replace unmanaged $unit"
    grep -Fq "$wrapper" "$unit" || fail "Another installation owns $unit"
fi
if [ -e "$wrapper" ]; then
    grep -q 'Managed by BraidPath installer' "$wrapper" || fail "Refusing to replace unmanaged $wrapper"
fi
stop_service() {
    case "$service" in
        systemd) systemctl stop braidpath.service; systemctl disable braidpath.service;;
        openrc) if rc-service braidpath status >/dev/null 2>&1; then rc-service braidpath stop; fi; rc-update del braidpath default >/dev/null 2>&1 || true;;
        procd) /etc/init.d/braidpath stop; /etc/init.d/braidpath disable;;
        rc) if service braidpath onestatus >/dev/null 2>&1; then service braidpath onestop; fi; sysrc -x braidpath_enable >/dev/null 2>&1 || true;;
        launchd) if launchctl print "gui/$(id -u)/org.braidpath" >/dev/null 2>&1; then launchctl bootout "gui/$(id -u)/org.braidpath"; fi;;
    esac
}
if [ "$operation" = remove ]; then
    stop_service
    rm -f "$binary" "$wrapper" "$metadata/installed"
    [ -z "$unit" ] || rm -f "$unit"
    [ "$service" != systemd ] || systemctl daemon-reload
    say "Removed BraidPath. Configuration, credentials and state retained: $config ; $state"
    exit 0
fi
new_work
if [ -n "$local_file" ]; then
    [ -f "$local_file" ] || fail "Not a file: $local_file"
    cp "$local_file" "$work/braidpath"
else
    [ -n "$version" ] || latest
    base=$REPO/releases/download/$version
    fetch "$base/SHA256SUMS" "$work/SHA256SUMS" || fail "Missing release checksums for $version"
    expected_hash=$(awk -v name="$asset" '$2 == name {print $1}' "$work/SHA256SUMS")
    [ "${#expected_hash}" -eq 64 ] || fail "Missing or duplicate checksum for $asset"
    case "$expected_hash" in *[!a-f0-9]*) fail 'Malformed release checksum';; esac
    fetch "$base/$asset" "$work/braidpath" || fail "Release does not contain $asset"
fi
if [ -n "$expected_hash" ]; then
    if has sha256sum; then actual_hash=$(sha256sum "$work/braidpath" | awk '{print $1}')
    elif has shasum; then actual_hash=$(shasum -a 256 "$work/braidpath" | awk '{print $1}')
    elif has sha256; then actual_hash=$(sha256 -q "$work/braidpath")
    else fail 'Install sha256sum, shasum or sha256 to verify the download'
    fi
    [ "$actual_hash" = "$expected_hash" ] || fail 'SHA-256 mismatch; installed binary was not changed'
fi
chmod 755 "$work/braidpath"
binary_version=$("$work/braidpath" --version) || fail 'Binary cannot run on this OS/architecture; installed binary was not changed'
case "$binary_version" in 'braidpath '*) ;; *) fail 'Not a BraidPath executable';; esac
[ -z "$version" ] || [ "$binary_version" = "braidpath ${version#v}" ] || fail 'Binary version does not match release tag'

# One argument per line: no shell evaluation of configuration or credentials.
mkdir -p "$prefix/bin" "$prefix/libexec" "$config" "$state"
chmod 700 "$state"
if [ ! -e "$config/args" ]; then
    (umask 077; cat > "$config/args" <<ARGS
# Managed example; edit before starting. One literal argument per line.
mesh-server
--dir
$state/node
--id
node-1
--listen
0.0.0.0:4433
--advertise
CHANGE_ME:4433
--relay-ports
44400-44463
--target
127.0.0.1:9000
ARGS
    )
fi
if [ "$service" = systemd ] || [ "$service" = openrc ] || [ "$service" = procd ] || [ "$service" = rc ]; then
    if ! id braidpath >/dev/null 2>&1; then
        if [ "$os" = freebsd ]; then pw useradd braidpath -d "$state" -s /usr/sbin/nologin
        elif has useradd; then useradd --system --home-dir "$state" --shell /sbin/nologin braidpath
        elif has adduser; then adduser -S -D -H -h "$state" -s /sbin/nologin braidpath
        else fail 'Create a dedicated braidpath user before installing the service'
        fi
    fi
    chown braidpath "$state" "$config/args"
fi
# Single quotes are escaped for binary-only custom prefixes.
quoted_binary=$(printf '%s' "$binary" | sed "s/'/'\\\\''/g")
cat > "$work/run" <<RUN
#!/bin/sh
# Managed by BraidPath installer
set -eu
args=\$1
set --
cr=\$(printf '\\r')
while IFS= read -r line || [ -n "\$line" ]; do
    line=\${line%"\$cr"}
    case "\$line" in ''|'#'*) continue;; esac
    set -- "\$@" "\$line"
done < "\$args"
[ "\$#" -gt 0 ] || { echo 'Empty BraidPath argument file' >&2; exit 1; }
exec '$quoted_binary' "\$@"
RUN
chmod 755 "$work/run"
staged=$(mktemp "$prefix/libexec/.braidpath-run.XXXXXX")
cp "$work/run" "$staged"
chmod 755 "$staged"
mv -f "$staged" "$wrapper"
staged=
[ -z "$unit" ] || mkdir -p "$(dirname "$unit")"
case "$service" in
    systemd)
        cat > "$unit" <<UNIT
# Managed by BraidPath installer
[Unit]
Description=BraidPath distributed UDP transport
After=network-online.target
Wants=network-online.target
[Service]
User=braidpath
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
StateDirectory=braidpath
StateDirectoryMode=0700
ExecStart=$wrapper $config/args
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
        ;;
    openrc)
        cat > "$unit" <<UNIT
#!/sbin/openrc-run
# Managed by BraidPath installer
name="BraidPath"
command="$wrapper"
command_args="$config/args"
command_user="braidpath"
command_background=true
pidfile="/run/braidpath.pid"
output_log="/var/log/braidpath.log"
error_log="/var/log/braidpath.log"
depend() { need net; }
UNIT
        chmod 755 "$unit";;
    procd)
        cat > "$unit" <<UNIT
#!/bin/sh /etc/rc.common
# Managed by BraidPath installer
START=95
STOP=10
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command "$wrapper" "$config/args"
    procd_set_param user braidpath
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
UNIT
        chmod 755 "$unit";;
    rc)
        cat > "$unit" <<UNIT
#!/bin/sh
# Managed by BraidPath installer
# PROVIDE: braidpath
# REQUIRE: NETWORKING
# KEYWORD: shutdown
. /etc/rc.subr
name=braidpath
rcvar=braidpath_enable
load_rc_config \$name
: \${braidpath_enable:=NO}
pidfile=/var/run/braidpath.pid
command=/usr/sbin/daemon
command_args="-f -r -P \$pidfile -u braidpath $wrapper $config/args"
run_rc_command "\$1"
UNIT
        chmod 755 "$unit";;
    launchd)
        mkdir -p "$(dirname "$unit")"
        cat > "$unit" <<UNIT
<?xml version="1.0" encoding="UTF-8"?>
<!-- Managed by BraidPath installer -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>org.braidpath</string>
<key>ProgramArguments</key><array><string>$wrapper</string><string>$config/args</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>5</integer>
<key>StandardOutPath</key><string>$state/service.log</string>
<key>StandardErrorPath</key><string>$state/service.log</string>
</dict></plist>
UNIT
        ;;
esac
# Replace on the destination filesystem; an in-use Unix binary keeps running.
staged=$(mktemp "$prefix/bin/.braidpath.XXXXXX")
cp "$work/braidpath" "$staged"
chmod 755 "$staged"
mv -f "$staged" "$binary"
staged=
printf 'BraidPath installer v1\n%s\n%s\n' "$service" "$binary_version" > "$metadata/installed"
[ "$service" != systemd ] || systemctl daemon-reload
say "Installed $binary_version ($asset) at $binary"
say "Configuration preserved at $config/args. No service was started or restarted."
case "$service" in
    systemd) say 'After configuring: systemctl enable --now braidpath.service';;
    openrc) say 'After configuring: rc-update add braidpath default && rc-service braidpath start';;
    procd) say 'After configuring: /etc/init.d/braidpath enable && /etc/init.d/braidpath start';;
    rc) say 'After configuring: sysrc braidpath_enable=YES && service braidpath start';;
    launchd) say "After configuring: launchctl bootstrap gui/$(id -u) $unit";;
    none) say "Run: $wrapper $config/args";;
esac
