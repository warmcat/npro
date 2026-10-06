#!/usr/bin/env bash
#
# Autobahn|Testsuite against a ws echo server or client, both ways, with
# upstream's Docker image: wstest is Python 2 only, and the image is how
# upstream runs it.  docs/sai.md says how to set up the builder it runs
# on; docs/port-plan.md (phase 1g) why it is a gate.
#
#   scripts/autobahn.sh server <command starting an echo server on 9001>
#   scripts/autobahn.sh client <command running one echo client connection>
#
# In "server" mode, the command is started in the background, and wstest's
# fuzzingclient runs every case against ws://127.0.0.1:9001.  In "client"
# mode, wstest's fuzzingserver listens on 9001, and the command is run
# once a case, with the path to ask for appended as its last argument
# (/runCase?case=N&agent=AGENT), until it fails, the cases being over; then
# once with /updateReports?agent=AGENT.  The echo examples of C, for a
# baseline, built with -DLWS_WITH_MINIMAL_EXAMPLES=1:
#
#   scripts/autobahn.sh server bin/lws-minimal-ws-server-echo -p 9001
#   scripts/autobahn.sh client bin/lws-minimal-ws-client-echo \
#	-s 127.0.0.1 -p 9001 -u
#
# Reports go to ./autobahn/reports/{servers,clients}, index.html among
# them.  The exit code is 0 only if every case not excluded below is OK,
# NON-STRICT or INFORMATIONAL, as C's scripts judge it.
#
# AUTOBAHN_IMAGE overrides the image; AUTOBAHN_AGENT the agent name.

set -euo pipefail

# Upstream's image, pinned: a digest, not a tag, so what runs is what was
# checked.  Pin it on the builder's first run: docker pull
# crossbario/autobahn-testsuite, then docker inspect --format
# '{{index .RepoDigests 0}}' crossbario/autobahn-testsuite, and put that
# here.
image="${AUTOBAHN_IMAGE:-crossbario/autobahn-testsuite@sha256:PIN-ME}"
agent="${AUTOBAHN_AGENT:-npro}"
port=9001

# Cases excluded, and why.  C's, until npro's own reasons replace them:
#  2.10, 2.11: several pings in flight; RFC 6455 does not require it, and
#              C and npro keep one pending pong.
#  12.3.1, 12.3.2, 12.4.*, 12.5.*: excluded by C's client script for
#              permessage-deflate with its client; the reason is not
#              written down there, and is to be found before npro keeps
#              them out.
exclude_server='"2.10", "2.11"'
exclude_client='"2.10", "2.11", "12.3.1", "12.3.2", "12.4.*", "12.5.*"'

mode="${1:?usage: $0 server|client <command...>}"
shift
[ $# -gt 0 ] || { echo "$0: no command given" >&2; exit 2; }

case "$image" in
*PIN-ME*)
	echo "$0: pin the image's digest first: see the top of $0" >&2
	exit 2
	;;
esac

work="$PWD/autobahn"
mkdir -p "$work/config" "$work/reports"

# wstest in the container, on the host's network so 127.0.0.1 is shared,
# as this user so the reports are ours
name="npro-autobahn-$$"
wstest() {
	docker run --rm --name "$name" --network host --user "$(id -u):$(id -g)" \
		-v "$work/config:/config:ro" -v "$work/reports:/reports" \
		"$image" wstest "$@"
}

# the cases that are not OK, NON-STRICT or INFORMATIONAL, from an index;
# "behavior": exactly, not "behaviorClose":
failures() {
	grep '"behavior":' "$1" | grep -v -e '"OK"' -e '"NON-STRICT"' \
		-e '"INFORMATIONAL"' || true
}

judge() {
	local index="$1" what="$2" total bad
	[ -s "$index" ] || { echo "$what: no report" >&2; return 1; }
	total=$(grep -c '"behavior":' "$index" || true)
	bad=$(failures "$index" | wc -l)
	echo "$what: $total cases, $bad failed"
	[ "$bad" -eq 0 ]
}

case "$mode" in
server)
	cat >"$work/config/fuzzingclient.json" <<EOF
{
	"outdir": "/reports/servers",
	"servers": [ { "agent": "$agent", "url": "ws://127.0.0.1:$port" } ],
	"cases": [ "*" ],
	"exclude-cases": [ $exclude_server ],
	"exclude-agent-cases": {}
}
EOF
	"$@" &
	server=$!
	trap 'kill $server 2>/dev/null || true' EXIT
	sleep 1
	kill -0 "$server" || { echo "$0: the server did not start" >&2; exit 3; }
	wstest -m fuzzingclient -s /config/fuzzingclient.json
	judge "$work/reports/servers/index.json" "autobahn's client, $agent's server"
	;;
client)
	cat >"$work/config/fuzzingserver.json" <<EOF
{
	"url": "ws://127.0.0.1:$port",
	"outdir": "/reports/clients",
	"cases": [ "*" ],
	"exclude-cases": [ $exclude_client ],
	"exclude-agent-cases": {}
}
EOF
	wstest -m fuzzingserver -s /config/fuzzingserver.json &
	fuzzer=$!
	# stopping the docker client need not stop its container
	trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
	sleep 3
	kill -0 "$fuzzer" || { echo "$0: wstest did not start" >&2; exit 3; }
	n=1
	while "$@" "/runCase?case=$n&agent=$agent"; do
		n=$((n + 1))
	done
	"$@" "/updateReports?agent=$agent" || true
	sleep 2
	docker rm -f "$name" >/dev/null 2>&1 || true
	judge "$work/reports/clients/index.json" "autobahn's server, $agent's client"
	;;
*)
	echo "usage: $0 server|client <command...>" >&2
	exit 2
	;;
esac
