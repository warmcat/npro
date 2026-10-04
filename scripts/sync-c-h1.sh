#!/bin/sh
#
# Measure what C lws' h1 parser makes of npro's head corpus, and its
# dechunker of npro's chunked bodies:
#
#   scripts/sync-c-h1.sh /path/to/libwebsockets [build dir]
#
# Builds the C library static, without tls (its parser has nothing to do
# with tls), and with the header options npro's token set is C's with,
# then compiles crates/npro-test/h1/c-heads.c against its private headers,
# which calls lws_parse() itself.  It runs every head in
# crates/npro-test/h1/requests/ and responses/ through it, as a server and
# as a client, and every body in chunked/ through the dechunker, with
# variations of each, in two configurations:
#
#   default  C's defaults: a 4096 byte ah, no token limits
#   tight    a 512 byte ah, limits on a GET's target (33), User-Agent (16),
#            Host (24) and Cookie (48), and unknown methods given to the
#            fallback role
#
# the bodies only in the first, since the configuration is only a head's.
# It replaces crates/npro-test/h1/c-heads.txt and C-COMMIT with what C made
# of them, which npro-test's h1_c test holds npro's parser to.
#
# The build goes to <build dir>, by default <checkout>/build-npro-h1, and is
# reconfigured each time.  The checkout should be clean, as for
# sync-c-oracle.sh.

set -eu

if [ $# -lt 1 ] || [ $# -gt 2 ] || [ ! -f "$1/lib/sansio/http/parsers.c" ]; then
	echo "usage: $0 <libwebsockets checkout> [build dir]" >&2
	exit 1
fi

c="$1"
b="${2:-$c/build-npro-h1}"
here="$(cd "$(dirname "$0")/.." && pwd)"
dst="$here/crates/npro-test/h1"
jobs="${SAI_PARALLEL:-4}"
cc="${CC:-cc}"

if [ -n "$(git -C "$c" status --porcelain -- lib include CMakeLists.txt)" ]; then
	echo "$c has uncommitted changes" >&2
	exit 1
fi

cmake -S "$c" -B "$b" -DCMAKE_BUILD_TYPE=DEBUG \
	-DLWS_WITH_STATIC=ON -DLWS_WITH_SHARED=OFF \
	-DLWS_WITH_SSL=OFF -DLWS_WITH_HTTP3=OFF -DLWS_WITH_ZLIB=OFF \
	-DLWS_WITH_MINIMAL_EXAMPLES=OFF \
	-DLWS_ROLE_WS=ON -DLWS_ROLE_H2=ON \
	-DLWS_WITH_HTTP_UNCOMMON_HEADERS=ON -DLWS_WITH_CUSTOM_HEADERS=ON \
	-DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build "$b" --target websockets -j "$jobs"

# the private headers' paths and defines, as the library's own parsers.c
# was compiled with them
flags="$(grep '"command".*sansio/http/parsers\.c' "$b/compile_commands.json" |
	tr ' ' '\n' | grep -E '^-[ID]' | tr '\n' ' ')"
if [ -z "$flags" ]; then
	echo "no compile command for parsers.c in $b" >&2
	exit 1
fi

# shellcheck disable=SC2086
"$cc" -g -Wall -Wextra -Wno-unused-parameter $flags \
	-o "$b/c-heads" "$dst/c-heads.c" "$b/lib/libwebsockets.a" -lpthread -lm

heads=""
for f in "$dst"/requests/*.http "$dst"/responses/*.http; do
	heads="$heads server:$f client:$f"
done
bodies=""
for f in "$dst"/chunked/*.txt; do
	bodies="$bodies chunked:$f"
done

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

# shellcheck disable=SC2086
"$b/c-heads" --config default --mutations 12 $heads $bodies > "$out"
# token indices: 0 GET's target, 69 User-Agent, 3 Host, 26 Cookie
# shellcheck disable=SC2086
"$b/c-heads" --config tight --max 512 --limit 0=33 --limit 69=16 \
	--limit 3=24 --limit 26=48 --fallback --mutations 12 $heads >> "$out"

chmod 644 "$out"
mv "$out" "$dst/c-heads.txt"
trap - EXIT
git -C "$c" log -1 --format='%H %s' > "$dst/C-COMMIT"

echo "$(wc -l < "$dst/c-heads.txt") heads from $(cut -c1-12 "$dst/C-COMMIT")"
