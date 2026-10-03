#!/bin/sh
#
# What each sai configuration runs on a unix builder.  .sai.json's platforms
# all run "scripts/sai.sh ${cmake}", and each configuration's "cmake" names
# a profile here and its arguments: sai's step template only knows the
# variable names prep, cmake and cpack, so "cmake" carries the profile.
#
#   gate            every gate a commit must pass (scripts/ci.sh)
#   test            the workspace's tests, natively on this builder
#   features        clippy over every combination of every crate's features
#   nostd           the sans-IO crates built for targets with no std
#   miri <target>   the tests under Miri, interpreting <target>: a 32-bit or
#                   big-endian machine without needing one
#   oracle          C lws main-dev's transcripts, recorded afresh, compared
#                   with the copies in crates/npro-test/transcripts
#
# docs/sai.md says what each builder needs installed.

set -eu

cd "$(dirname "$0")/.."

# rustup installs for the user the builder runs as, in its $HOME, which sai
# sets for the job; its tools are not on the builder daemon's PATH
PATH="$HOME/.cargo/bin:$PATH"
export PATH

jobs="${SAI_PARALLEL:-4}"

# the sans-IO crates, which must build with no std at all
nostd_crates="npro-core"
nostd_targets="thumbv6m-none-eabi thumbv7em-none-eabihf riscv32imc-unknown-none-elf"

# Refuse a toolchain older than the workspace's rust-version up front: cargo
# itself only says it cannot parse the manifest.  A distro's packaged cargo
# is the usual cause, when rustup is not installed for the builder's user.
msrv=$(sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml)
have=$(rustc --version 2>/dev/null | sed -n 's/^rustc \([0-9]*\.[0-9]*\).*/\1/p')
if [ -z "$have" ] ||
   [ "$(printf '%s\n%s\n' "$msrv" "$have" | sort -t. -k1,1n -k2,2n | head -n1)" != "$msrv" ]; then
	echo "rustc ${have:-not found} on this builder; npro needs $msrv or later." >&2
	echo "Install rustup for the user sai runs jobs as, see docs/sai.md:" >&2
	echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile default" >&2
	exit 1
fi

profile="${1:-}"
[ $# -gt 0 ] && shift

case "$profile" in
gate)
	exec scripts/ci.sh
	;;

test)
	cargo --version
	exec cargo test --workspace --all-features --locked -j "$jobs"
	;;

features)
	exec cargo hack clippy --workspace --feature-powerset --all-targets \
		--locked -j "$jobs" -- -D warnings
	;;

nostd)
	for t in $nostd_targets; do
		for c in $nostd_crates; do
			echo "== $c for $t"
			cargo build -p "$c" --all-features --target "$t" --locked \
				-j "$jobs"
		done
	done
	;;

miri)
	target="${1:?miri needs a target, eg s390x-unknown-linux-gnu}"
	# npro-test reads its transcripts from disk, which Miri's isolation
	# would refuse
	MIRIFLAGS="${MIRIFLAGS:-} -Zmiri-disable-isolation" \
		exec cargo +nightly miri test --workspace --all-features --locked \
			--target "$target"
	;;

oracle)
	# A C lws checkout of main-dev kept between jobs, built with what
	# every transcript needs: fault injection for the seeded random,
	# extensions and zlib for the permessage-deflate ones
	c="${LWS_ORACLE:-$HOME/lws-oracle}"
	if [ ! -d "$c/.git" ]; then
		git clone --depth 50 -b main-dev \
			https://libwebsockets.org/repo/libwebsockets "$c"
	fi
	git -C "$c" fetch --depth 50 origin main-dev
	git -C "$c" checkout -q --detach FETCH_HEAD
	echo "== C lws $(git -C "$c" log -1 --format='%h %s')"

	cmake -S "$c" -B "$c/build-oracle" -DCMAKE_BUILD_TYPE=DEBUG \
		-DLWS_WITH_SSL=OFF -DLWS_WITH_MINIMAL_EXAMPLES=ON \
		-DLWS_WITH_SYS_FAULT_INJECTION=ON -DLWS_WITHOUT_EXTENSIONS=OFF \
		-DLWS_WITH_ZLIB=ON
	cmake --build "$c/build-oracle" --target lws-api-test-sansio -j "$jobs"

	rec="$(mktemp -d)"
	trap 'rm -rf "$rec"' EXIT
	(cd "$c/minimal-examples-lowlevel/api-tests/api-test-sansio" &&
		"$c/build-oracle/bin/lws-api-test-sansio" -d 1 --record "$rec")

	ours=crates/npro-test/transcripts
	if diff -rq "$rec" "$ours" -x 'README*' -x C-COMMIT; then
		echo "== the transcripts match C $(git -C "$c" log -1 --format=%h)"
		exit 0
	fi
	echo "C's transcripts moved since $(cut -c1-12 "$ours/C-COMMIT"):"
	echo "sync them with scripts/sync-c-oracle.sh and say why in the commit"
	exit 1
	;;

*)
	echo "usage: $0 gate | test | features | nostd | miri <target> | oracle" >&2
	exit 1
	;;
esac
