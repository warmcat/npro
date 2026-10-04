#!/bin/sh
#
# Copy C lws' state machine oracles from a C checkout:
#
#   scripts/sync-c-states.sh /path/to/libwebsockets [build dir]
#
# The rows of C's event table go to crates/npro-test/states/, verbatim, and
# the state edges C's ctest suite takes beside them, from a build with
# LWS_WITH_STATE_TRACE and LWS_WITH_STATE_CHECK (so the suite also aborts on
# any edge the table does not allow).  The C commit is recorded in C-COMMIT.
# The checkout should be clean, as for sync-c-oracle.sh.
#
# The build goes to <checkout>/build-npro-states unless a build dir is
# given; it is reconfigured each time.  It is a default build without h3,
# which needs gnutls; C's ctest-background.sh needs netstat or ss to see its
# test servers come up.  The suite takes some minutes.

set -eu

if [ $# -lt 1 ] || [ $# -gt 2 ] || [ ! -f "$1/lib/sansio/wsi-state.c" ]; then
	echo "usage: $0 <libwebsockets checkout> [build dir]" >&2
	exit 1
fi

c="$1"
b="${2:-$c/build-npro-states}"
here="$(cd "$(dirname "$0")/.." && pwd)"
dst="$here/crates/npro-test/states"

if [ -n "$(git -C "$c" status --porcelain -- lib include CMakeLists.txt)" ]; then
	echo "$c has uncommitted changes" >&2
	exit 1
fi
if ! command -v netstat >/dev/null 2>&1 && ! command -v ss >/dev/null 2>&1; then
	echo "C's test fixtures need netstat or ss" >&2
	exit 1
fi

cmake -S "$c" -B "$b" -DCMAKE_BUILD_TYPE=DEBUG \
	-DLWS_WITH_STATE_TRACE=ON -DLWS_WITH_STATE_CHECK=ON \
	-DLWS_WITH_HTTP3=OFF -DLWS_WITH_MINIMAL_EXAMPLES=ON \
	-DLWS_WITHOUT_EXTENSIONS=OFF -DLWS_WITH_ZLIB=ON \
	-DLWS_WITH_SYS_FAULT_INJECTION=ON
cmake --build "$b" -j "${SAI_PARALLEL:-4}"

raw="$(mktemp)"
trap 'rm -f "$raw"' EXIT
(cd "$b" && LWS_STATE_TRACE_FILE="$raw" ctest -j "${SAI_PARALLEL:-4}" --timeout 180)

# the table's rows, between its opening and its closing brace
awk '/^static const struct lws_wsi_event_edge lws_wsi_event_edges\[\] = \{/ { f = 1; next }
     f && /^\};/ { exit }
     f' "$c/lib/sansio/wsi-state.c" > "$dst/wsi-event-edges.txt"

# each edge once, without the connection's tag: "LRS from -> to how [ev=X]"
sed -E -e 's/^(LRS [^ ]+ -> [^ ]+ [^ ]+) .*( ev=[A-Z0-9_]+)$/\1\2/' -e t \
       -e 's/^(LRS [^ ]+ -> [^ ]+ [^ ]+) .*$/\1/' "$raw" |
	LC_ALL=C sort -u > "$dst/edges.txt"

git -C "$c" log -1 --format='%H %s' > "$dst/C-COMMIT"

echo "$(grep -c '^[[:space:]]*{' "$dst/wsi-event-edges.txt") rows and" \
     "$(wc -l < "$dst/edges.txt") edges from $(cut -c1-12 "$dst/C-COMMIT")"
