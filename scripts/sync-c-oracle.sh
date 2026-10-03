#!/bin/sh
#
# Copy what npro is checked against from a C lws checkout:
#
#   scripts/sync-c-oracle.sh /path/to/libwebsockets
#
# The api-test-sansio transcripts and their README go to
# crates/npro-test/transcripts/, replacing what is there, and the C commit
# they came from is recorded in C-COMMIT beside them.  The checkout should be
# clean: a transcript is behaviour, and the commit that changes one here
# names the C commit that changed it there.

set -eu

if [ $# -ne 1 ] || [ ! -d "$1/minimal-examples-lowlevel/api-tests/api-test-sansio" ]; then
	echo "usage: $0 <libwebsockets checkout>" >&2
	exit 1
fi

c="$1"
here="$(cd "$(dirname "$0")/.." && pwd)"
src="$c/minimal-examples-lowlevel/api-tests/api-test-sansio/transcripts"
dst="$here/crates/npro-test/transcripts"

if [ -n "$(git -C "$c" status --porcelain -- "$src")" ]; then
	echo "$src has uncommitted changes" >&2
	exit 1
fi

rm -f "$dst"/*.json
cp "$src"/*.json "$dst/"
cp "$src/README.md" "$dst/README.lws.md"
git -C "$c" log -1 --format='%H %s' > "$dst/C-COMMIT"

echo "$(ls "$dst"/*.json | wc -l) transcripts from $(cut -c1-12 "$dst/C-COMMIT")"
