#!/bin/sh
#
# Copy C lws' state machine oracles from a C checkout:
#
#   scripts/sync-c-states.sh /path/to/libwebsockets [build dir]
#
# Into crates/npro-test/states/, replacing what is there:
#
#   wsi-event-edges.txt  the rows of C's event table, each line of the table
#                        prefixed by its line in wsi-state.c, which is how
#                        C's trace names a row
#   edges.txt            every distinct state edge C's ctest suite takes,
#                        sorted, without each connection's tag
#   rows-fired.txt       every row of the table the suite fires, from C's
#                        LRSROW lines
#   README.lws.md        C's README.wsi-state-machines.md, which lists the
#                        rows no test fires and why
#   C-COMMIT             the C commit
#
# The suite runs in the three builds C's README measures coverage over: the
# default, one adding the options some rows need, and one with tls accepts
# on a worker.  Each has LWS_WITH_STATE_TRACE and LWS_WITH_STATE_CHECK, so
# the suite also aborts on any edge the table does not allow.  h3 is built
# where gnutls is installed, as C's own measurement is; without it the rows
# only h3 reaches (quic to tcp among them) are never fired.
#
# The builds go to <build dir>-<name>, by default <checkout>/build-npro-
# states-<name>; they are reconfigured each time.  C's ctest-background.sh
# needs netstat or ss to see its test servers come up.  Expect most of an
# hour.  The checkout should be clean, as for sync-c-oracle.sh.
#
# Any failing test stops the sync: the edges are only an oracle from a
# suite that passes.  CTEST_ARGS is passed to every ctest, eg,
# CTEST_ARGS="-E api-test-foo" to leave out a test that fails for reasons
# outside the state machines; the commit names it, and why.

set -eu

if [ $# -lt 1 ] || [ $# -gt 2 ] || [ ! -f "$1/lib/sansio/wsi-state.c" ]; then
	echo "usage: $0 <libwebsockets checkout> [build dir]" >&2
	exit 1
fi

c="$1"
b="${2:-$c/build-npro-states}"
here="$(cd "$(dirname "$0")/.." && pwd)"
dst="$here/crates/npro-test/states"
jobs="${SAI_PARALLEL:-4}"

if [ -n "$(git -C "$c" status --porcelain -- lib include CMakeLists.txt)" ]; then
	echo "$c has uncommitted changes" >&2
	exit 1
fi
if ! command -v netstat >/dev/null 2>&1 && ! command -v ss >/dev/null 2>&1; then
	echo "C's test fixtures need netstat or ss" >&2
	exit 1
fi

if pkg-config --exists gnutls 2>/dev/null; then
	h3=ON
else
	h3=OFF
	echo "no gnutls: building without h3, so its rows will not fire" >&2
fi

raw="$(mktemp)"
trap 'rm -f "$raw"' EXIT

# run C's suite in one build: $1 its name, the rest its cmake options
suite() {
	name="$1"
	shift
	echo "== C build: $name"
	cmake -S "$c" -B "$b-$name" -DCMAKE_BUILD_TYPE=DEBUG \
		-DLWS_WITH_STATE_TRACE=ON -DLWS_WITH_STATE_CHECK=ON \
		-DLWS_WITH_HTTP3="$h3" -DLWS_WITH_MINIMAL_EXAMPLES=ON \
		-DLWS_WITHOUT_EXTENSIONS=OFF -DLWS_WITH_ZLIB=ON "$@"
	cmake --build "$b-$name" -j "$jobs"
	# shellcheck disable=SC2086
	(cd "$b-$name" && LWS_STATE_TRACE_FILE="$raw" \
		ctest -j "$jobs" --timeout 180 ${CTEST_ARGS:-})
}

suite default
suite options -DLWS_WITH_ASYNC_QUEUE=ON -DLWS_WITH_SOCKS5=ON \
	-DLWS_ROLE_MQTT=ON -DLWS_WITH_HTTP_PROXY=ON -DLWS_ROLE_RAW_PROXY=ON \
	-DLWS_WITH_SYS_FAULT_INJECTION=ON -DLWS_WITH_EMAIL=ON
suite worker -DLWS_WITH_ASYNC_QUEUE=ON -DLWS_MAX_SMP=2

# the table, each line with its line in wsi-state.c
awk '/^static const struct lws_wsi_event_edge lws_wsi_event_edges\[\] = \{/ { f = 1; next }
     f && /^\};/ { exit }
     f { printf "%d\t%s\n", NR, $0 }' "$c/lib/sansio/wsi-state.c" > "$dst/wsi-event-edges.txt"

# each edge once, without the connection's tag: "LRS from -> to how [ev=X]"
grep '^LRS ' "$raw" |
	sed -E -e 's/^(LRS [^ ]+ -> [^ ]+ [^ ]+) .*( ev=[A-Z0-9_]+)$/\1\2/' -e t \
	       -e 's/^(LRS [^ ]+ -> [^ ]+ [^ ]+) .*$/\1/' |
	LC_ALL=C sort -u > "$dst/edges.txt"

# each row fired, once: "LRSROW <line> role side from event"
grep '^LRSROW ' "$raw" | sort -u -k2,2n > "$dst/rows-fired.txt"

cp "$c/READMEs/README.wsi-state-machines.md" "$dst/README.lws.md"
git -C "$c" log -1 --format='%H %s' > "$dst/C-COMMIT"

echo "$(grep -c '	[[:space:]]*R(' "$dst/wsi-event-edges.txt") rows," \
     "$(wc -l < "$dst/rows-fired.txt") fired, and" \
     "$(wc -l < "$dst/edges.txt") edges from $(cut -c1-12 "$dst/C-COMMIT")"
