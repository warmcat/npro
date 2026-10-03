#!/bin/sh
#
# Coverage-guided fuzzing of npro's fuzz targets with libFuzzer, by hand or
# under sai.  docs/fuzzing.md says what the targets check, and how to read
# and replay what this finds.
#
#   scripts/fuzz.sh                     # 60s per target, every target
#   scripts/fuzz.sh 600                 # 10 minutes per target
#   scripts/fuzz.sh 600 utf8 sha1       # only the named targets
#   BUILD=~/npro-fuzz scripts/fuzz.sh   # build somewhere else
#   CORPUS=~/corpus scripts/fuzz.sh     # keep the corpora somewhere lasting
#
# The targets are the bins of the fuzz/ workspace, built by cargo-fuzz with
# nightly, AddressSanitizer and debug assertions.  FUZZ_OPTS adds libFuzzer
# flags, eg, FUZZ_OPTS=-verbosity=0 to leave out its line for every new
# unit and its periodic status, as scripts/sai.sh does for sai's logs.
#
# Each target's corpus is <corpus>/corpus-<target>, grown from its seeds in
# fuzz/seeds/<target>/ (and, for transcript, the vendored transcripts).
# <corpus> is <build>/corpus unless CORPUS says otherwise.
#
# This follows the C tree's fuzz/run.sh, in how it works with sai:
#
#  - Under a sai idle task (sai's READMEs/README-idle.md), SAI_IDLE_SECS is
#    the length of the slice, build included.  The time left after the build
#    is shared by as many targets as can each have IDLE_MIN_TARGET_SECS,
#    taking turns across slices.
#
#  - Under a configuration naming a pool (README-pool.md), SAI_POOL_DIR is
#    kept synced with every builder fuzzing npro, and the corpora live there.
#    The first time, any corpora CORPUS already held are copied in.
#
#  - With the pool come SAI_POOL_KNOWN, the reproducers of the bugs found so
#    far, and SAI_POOL_FINDINGS, where findings go to sai-server
#    (README-findings.md).  A CI run (not an idle slice) first replays each
#    target's known reproducers and fails if any still crash.  Reports go
#    only to sai-server, which shows them only to admins: they can be
#    unfixed security bugs, and CI logs are public.  An idle slice reports
#    its findings that way, but does not fail.
#
# Findings (crash-*, leak-*, timeout-*, oom-*, slow-unit-*) are written into
# <build>/artifacts/ with each target's output in log-<target>.txt; those
# this run produced are listed at the end, and make it exit nonzero.

set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"

# rustup's tools, for the user the builder runs as
PATH="$HOME/.cargo/bin:$PATH"
export PATH

. scripts/require.sh
require_rust
require_toolchain nightly "rustup toolchain install nightly --profile minimal"
require_cargo fuzz "cargo install --locked cargo-fuzz"
require_cargo deny "cargo install --locked cargo-deny"
require_cmd c++ "dnf install gcc-c++ (or apt install g++): libFuzzer's runtime is C++"
require_done

BUILD="${BUILD:-${CARGO_TARGET_DIR:-$REPO/target}/fuzz}"
CORPUS="${CORPUS:-$BUILD/corpus}"
ARTIFACTS="$BUILD/artifacts"

if [ -n "${SAI_POOL_DIR:-}" ] && [ -d "$SAI_POOL_DIR" ]; then
	if [ "$CORPUS" != "$SAI_POOL_DIR" ] && [ -d "$CORPUS" ] &&
	   [ ! -e "$CORPUS/.sai-pool-copied" ]; then
		for d in "$CORPUS"/corpus-*; do
			if [ -d "$d" ]; then
				mkdir -p "$SAI_POOL_DIR/${d##*/}"
				cp -Rn "$d/." "$SAI_POOL_DIR/${d##*/}/"
			fi
		done
		touch "$CORPUS/.sai-pool-copied"
	fi
	CORPUS="$SAI_POOL_DIR"
fi

SECS="${1:-60}"
case "$SECS" in
	''|*[!0-9]*) echo "usage: $0 [seconds per target] [target...]" >&2; exit 1 ;;
esac
if [ "$#" -gt 0 ]; then
	shift
fi

START=$(date +%s)
IDLE_SECS="${SAI_IDLE_SECS:-}"
case "$IDLE_SECS" in
	''|*[!0-9]*) IDLE_SECS="" ;;
esac
# least time a target gets in an idle slice, since each run begins by
# replaying its whole corpus
IDLE_MIN_TARGET_SECS=120
# time an idle slice keeps back for runs starting and stopping, and reporting
IDLE_MARGIN_SECS=30
IDLE_PER_TARGET_OVERHEAD_SECS=5

# the fuzz workspace's dependencies are let in only by name, like the main
# workspace's (docs/dependencies.md): check before building anything
echo "== cargo deny, fuzz workspace"
cargo deny --manifest-path fuzz/Cargo.toml check
# and build only what fuzz/Cargo.lock says
cargo +nightly fetch --locked --manifest-path fuzz/Cargo.toml

echo "== build"
cargo +nightly fuzz build --fuzz-dir fuzz -O --debug-assertions \
	--target-dir "$BUILD"
host=$(rustc +nightly -vV | sed -n 's/^host: //p')
BIN="$BUILD/$host/release"

ALL=$(cargo +nightly fuzz list --fuzz-dir fuzz)
if [ "$#" -gt 0 ]; then
	TARGETS="$*"
	for t in $TARGETS; do
		case " $(echo $ALL) " in
			*" $t "*) ;;
			*) echo "no fuzz target $t; there are: $(echo $ALL)" >&2; exit 1 ;;
		esac
	done
else
	TARGETS=$(echo $ALL)
fi

# the sanitizer reports need function names, for people and for sai-server's
# grouping of findings into bugs
if [ -z "${ASAN_SYMBOLIZER_PATH:-}" ]; then
	for s in llvm-symbolizer llvm-symbolizer-21 llvm-symbolizer-20 \
		 llvm-symbolizer-19 llvm-symbolizer-18; do
		if command -v "$s" >/dev/null 2>&1; then
			ASAN_SYMBOLIZER_PATH=$(command -v "$s")
			export ASAN_SYMBOLIZER_PATH
			break
		fi
	done
fi

mkdir -p "$ARTIFACTS" "$CORPUS"

if [ -n "$IDLE_SECS" ]; then
	set -- $TARGETS
	n=$#

	left=$(( IDLE_SECS - ($(date +%s) - START) - IDLE_MARGIN_SECS ))
	count=$(( left / (IDLE_MIN_TARGET_SECS + IDLE_PER_TARGET_OVERHEAD_SECS) ))
	if [ "$count" -gt "$n" ]; then
		count=$n
	fi
	if [ "$count" -lt 1 ]; then
		echo "idle slice of ${IDLE_SECS}s has no time left after the build"
		exit 0
	fi
	SECS=$(( left / count - IDLE_PER_TARGET_OVERHEAD_SECS ))

	# whose turn it is, kept with the corpora so it lasts between slices
	next=0
	if [ -r "$CORPUS/.idle-next" ]; then
		read -r next < "$CORPUS/.idle-next" || next=0
		case "$next" in
			''|*[!0-9]*) next=0 ;;
		esac
	fi
	next=$(( next % n ))
	echo $(( (next + count) % n )) > "$CORPUS/.idle-next"

	TARGETS=""
	i=0
	while [ "$i" -lt "$count" ]; do
		k=$(( (next + i) % n + 1 ))
		eval "TARGETS=\"\$TARGETS \${$k}\""
		i=$(( i + 1 ))
	done

	echo "idle slice of ${IDLE_SECS}s: ${SECS}s each for$TARGETS"
fi

# the seed directories of target $1
seeds() {
	echo "$REPO/fuzz/seeds/$1"
	if [ "$1" = transcript ]; then
		echo "$REPO/crates/npro-test/transcripts"
	fi
}

# so this run's findings can be told from earlier ones in $ARTIFACTS
STAMP="$ARTIFACTS/.run-stamp"
touch "$STAMP"

rc=0

# send a finding to sai-server through the pool: $1 target, $2 the input,
# $3 the name to give it, $4 the report.  Each is written under a hidden name
# first, so the builder never sends one half written.
sai_finding() {
	d="$SAI_POOL_FINDINGS/$1"
	mkdir -p "$d"
	tail -c 1048576 "$4" > "$d/.$3.log" && mv "$d/.$3.log" "$d/$3.log"
	cp "$2" "$d/.$3" && mv "$d/.$3" "$d/$3"
}

# replay the known reproducers of target $1, failing for any that still
# crash, and telling sai-server about those that no longer do
replay_known() {
	kdir="$SAI_POOL_KNOWN/$1"
	[ -d "$kdir" ] || return 0

	for f in "$kdir"/*; do
		h=${f##*/}
		case "$h" in
			*[!0-9a-f]*|'') continue ;;
		esac
		[ ${#h} -eq 40 ] || continue

		rlog="$ARTIFACTS/replay-$1-$h.txt"
		if "$BIN/$1" -timeout=60 "$f" > "$rlog" 2>&1; then
			mkdir -p "$SAI_POOL_FINDINGS/$1"
			: > "$SAI_POOL_FINDINGS/$1/.ok-$h" &&
				mv "$SAI_POOL_FINDINGS/$1/.ok-$h" \
				   "$SAI_POOL_FINDINGS/$1/ok-$h"
		else
			echo "$1: known bug $h still crashes (report sent to sai)"
			sai_finding "$1" "$f" "replay-$h" "$rlog"
			rc=1
		fi
	done
}

# the first corpus dir receives new discoveries; the seed dirs are only read
run_target() {
	# shellcheck disable=SC2046,SC2086
	"$BIN/$1" "$CORPUS/corpus-$1" $(seeds "$1") \
		-max_total_time="$SECS" \
		-print_final_stats=1 \
		-artifact_prefix="$ARTIFACTS/" \
		${FUZZ_OPTS:-}
}

for t in $TARGETS; do
	echo
	echo "=== $t: ${SECS}s ==="
	mkdir -p "$CORPUS/corpus-$t"
	log="$ARTIFACTS/log-$t.txt"

	if [ -n "${SAI_POOL_KNOWN:-}" ] && [ -n "${SAI_POOL_FINDINGS:-}" ] &&
	   [ -z "$IDLE_SECS" ]; then
		replay_known "$t"
	fi

	TSTAMP="$ARTIFACTS/.target-stamp"
	touch "$TSTAMP"

	if [ -t 1 ]; then
		# interactive: live output, and a copy next to the artifacts
		{ run_target "$t"; echo $? > "$log.rc"; } 2>&1 | tee "$log"
		[ "$(cat "$log.rc")" = 0 ] || rc=1
		rm -f "$log.rc"
	else
		# not a terminal, eg, a sai log: libFuzzer writes each status line
		# in many small writes, which a log collector counting chunks
		# charges for one by one; gather the output and emit it at once
		run_target "$t" > "$log" 2>&1 || rc=1

		if [ -n "${SAI_POOL_FINDINGS:-}" ]; then
			# the reports go to sai-server; the public log only gets
			# how it went
			grep -aE '^(#[0-9]+[[:space:]]+(INITED|DONE)|Done [0-9]+ runs|stat::)' \
				"$log" || true
		else
			cat "$log"
		fi
	fi

	if [ -n "${SAI_POOL_FINDINGS:-}" ]; then
		for f in $(find "$ARTIFACTS" -maxdepth 1 -type f \
				-newer "$TSTAMP" \( -name 'crash-*' \
				-o -name 'leak-*' -o -name 'timeout-*' \
				-o -name 'oom-*' -o -name 'slow-unit-*' \)); do
			echo "$t: finding ${f##*/} (report sent to sai)"
			sai_finding "$t" "$f" "${f##*/}" "$log"
		done
	fi
done

# what this run found, by absolute path, so it can be collected from the log
# even when the run was somewhere else
FOUND=$(find "$ARTIFACTS" -maxdepth 1 -type f -newer "$STAMP" \
	\( -name 'crash-*' -o -name 'leak-*' -o -name 'timeout-*' \
	   -o -name 'oom-*' -o -name 'slow-unit-*' \) | sort)

echo
if [ -n "$FOUND" ]; then
	echo "=== FINDINGS: replay each with $BIN/<target> <file> ==="
	echo "$FOUND"
	rc=1
else
	echo "=== no findings ==="
fi

if [ -n "$IDLE_SECS" ] && [ -n "${SAI_POOL_FINDINGS:-}" ]; then
	# an idle slice has reported what it found; it carries on next slice
	rc=0
fi

exit $rc
