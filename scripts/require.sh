# Checks that the tools a script is about to use are installed, so it fails
# at the start with what to install, not halfway with a cargo error.
# Sourced by scripts/ci.sh and scripts/sai.sh; docs/toolchain.md and
# docs/sai.md say what each tool is for.
#
# Each require_* call notes what is missing; require_done then lists all of
# it with the command that installs each, and exits 1 if anything was.

_missing=""

_miss() {
	_missing="$_missing
  $1
      $2"
}

# rustc at least the workspace's rust-version.  A distro's packaged rust is
# the usual cause of an older one: cargo itself only says it cannot parse
# the manifest.
require_rust() {
	_msrv=$(sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml)
	_have=$(rustc --version 2>/dev/null |
		sed -n 's/^rustc \([0-9]*\.[0-9]*\).*/\1/p')
	if [ -z "$_have" ]; then
		_miss "rustc (none found; npro needs $_msrv or later)" \
			"curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile default"
		return
	fi
	if [ "$(printf '%s\n%s\n' "$_msrv" "$_have" |
		sort -t. -k1,1n -k2,2n | head -n1)" != "$_msrv" ]; then
		_miss "rustc $_have is older than npro's rust-version $_msrv" \
			"install rustup and use its toolchain, not the distro's: see docs/toolchain.md"
	fi
}

# a cargo subcommand: fmt, clippy, hack, deny, audit...
require_cargo() {
	cargo "$1" --version >/dev/null 2>&1 || _miss "cargo $1" "$2"
}

# a rustup toolchain, eg the MSRV or nightly
require_toolchain() {
	rustup run "$1" rustc --version >/dev/null 2>&1 || _miss "toolchain $1" "$2"
}

# a rustup target installed for a toolchain (default: the active one)
require_target() {
	_t=$(rustup target list --installed ${2:+--toolchain "$2"} 2>/dev/null)
	printf '%s\n' "$_t" | grep -qx "$1" ||
		_miss "target $1${2:+ for $2}" \
			"rustup target add $1${2:+ --toolchain $2}"
}

# anything else: a description, how to install it, and a command that
# succeeds when it is there
require_run() {
	_what="$1"
	_how="$2"
	shift 2
	"$@" >/dev/null 2>&1 || _miss "$_what" "$_how"
}

# a program on PATH
require_cmd() {
	command -v "$1" >/dev/null 2>&1 || _miss "$1" "$2"
}

require_done() {
	[ -z "$_missing" ] && return 0
	echo "Missing on this machine:$_missing" >&2
	echo "See docs/toolchain.md (and docs/sai.md for a sai builder)." >&2
	exit 1
}
