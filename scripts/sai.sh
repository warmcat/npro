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
#   fuzz [secs]     libFuzzer over every fuzz target (scripts/fuzz.sh), in
#                   CI and in sai's idle time, with the corpora in a pool
#
# Each profile first checks for the tools it uses and lists any that are
# missing with their install commands; docs/sai.md says what each builder
# needs.

set -eu

cd "$(dirname "$0")/.."

# rustup installs for the user the builder runs as, in its $HOME, which sai
# sets for the job; its tools are not on the builder daemon's PATH
PATH="$HOME/.cargo/bin:$PATH"
export PATH

jobs="${SAI_PARALLEL:-4}"

# the sans-IO crates, which must build with no std at all
nostd_crates="npro-core npro-h1 npro-ws npro-io"
nostd_targets="thumbv6m-none-eabi thumbv7em-none-eabihf riscv32imc-unknown-none-elf"

. scripts/require.sh

profile="${1:-}"
[ $# -gt 0 ] && shift

case "$profile" in
gate)
	# ci.sh checks its own tools
	exec scripts/ci.sh
	;;

test)
	require_rust
	require_done
	cargo --version
	exec cargo test --workspace --all-features --locked -j "$jobs"
	;;

features)
	require_rust
	require_cargo clippy "rustup component add clippy"
	require_cargo hack "cargo install --locked cargo-hack"
	require_done
	exec cargo hack clippy --workspace --feature-powerset --all-targets \
		--locked -j "$jobs" -- -D warnings
	;;

nostd)
	require_rust
	for t in $nostd_targets; do
		require_target "$t"
	done
	require_done
	for t in $nostd_targets; do
		for c in $nostd_crates; do
			features=--all-features
			# npro-io's rustls needs atomic compare-and-swap, for its
			# Arc, which the M0 and riscv32imc have not
			if [ "$c" = npro-io ] && [ "$t" != thumbv7em-none-eabihf ]; then
				features="--features pmd"
			fi
			echo "== $c ($features) for $t"
			cargo build -p "$c" $features --target "$t" --locked \
				-j "$jobs"
		done
	done
	;;

miri)
	target="${1:?miri needs a target, eg s390x-unknown-linux-gnu}"
	require_rust
	require_toolchain nightly \
		"rustup toolchain install nightly --profile minimal --component miri,rust-src"
	require_run "miri for nightly" \
		"rustup component add miri rust-src --toolchain nightly" \
		cargo +nightly miri --version
	require_done
	# npro-test reads its transcripts from disk, which Miri's isolation
	# would refuse
	MIRIFLAGS="${MIRIFLAGS:-} -Zmiri-disable-isolation" \
		exec cargo +nightly miri test --workspace --all-features --locked \
			--target "$target"
	;;

oracle)
	# A C lws checkout of main-dev kept between jobs, built with what
	# every transcript needs: fault injection for the seeded random,
	# extensions and zlib for the permessage-deflate ones, and a tls
	# library, whose genhash the digest auth ones need.  The tls is
	# openssl, the default; h3 would need gnutls too, and records nothing.
	c="${LWS_ORACLE:-$HOME/lws-oracle}"
	require_cmd git "dnf install git"
	require_cmd cmake "dnf install cmake"
	require_cmd make "dnf install make"
	require_cmd cc "dnf install gcc"
	require_run "zlib headers" "dnf install zlib-devel" \
		sh -c 'echo "#include <zlib.h>" | cc -E - >/dev/null'
	require_run "openssl headers" "dnf install openssl-devel" \
		sh -c 'echo "#include <openssl/ssl.h>" | cc -E - >/dev/null'
	require_done
	if [ ! -d "$c/.git" ]; then
		git clone --depth 50 -b main-dev \
			https://libwebsockets.org/repo/libwebsockets "$c"
	fi
	git -C "$c" fetch --depth 50 origin main-dev
	git -C "$c" checkout -q --detach FETCH_HEAD
	echo "== C lws $(git -C "$c" log -1 --format='%h %s')"

	cmake -S "$c" -B "$c/build-oracle" -DCMAKE_BUILD_TYPE=DEBUG \
		-DLWS_WITH_SSL=ON -DLWS_WITH_HTTP3=OFF \
		-DLWS_WITH_MINIMAL_EXAMPLES=ON \
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
	echo "C's transcripts differ from those of $(cut -c1-12 "$ours/C-COMMIT"):"
	echo "if C changed them, sync them with scripts/sync-c-oracle.sh and say"
	echo "why in the commit; if C did not, this build lacks an option they need"
	exit 1
	;;

fuzz)
	# libFuzzer's line for every new unit and its periodic status would
	# swamp the job log, as in C's fuzz job: keep its start, the final
	# stats and any report.  FUZZ_OPTS set on the builder still wins.
	FUZZ_OPTS="${FUZZ_OPTS:--verbosity=0}"
	export FUZZ_OPTS
	# fuzz.sh checks its own tools
	exec scripts/fuzz.sh "$@"
	;;

*)
	echo "usage: $0 gate | test | features | nostd | miri <target> | oracle | fuzz [secs]" >&2
	exit 1
	;;
esac
