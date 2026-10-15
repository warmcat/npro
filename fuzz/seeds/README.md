# Fuzz seeds

One directory per fuzz target, named as the target is (`npro_fuzz::Target`).
Every file in it is one input libFuzzer starts its corpus from, and one the
smoke tests in `crates/npro-fuzz/tests/smoke.rs` run on every `cargo test`.
Files named `*.md` are left out of both.

Where a target splits its input to feed it in pieces, as `utf8` and `sha1`
do, the **first byte chooses the split** and the bytes under test follow it.
A seed for those targets starts with that byte; any value will do.

The `transcript` target also starts from every transcript in
`crates/npro-test/transcripts/`.

Seeds are small and readable on purpose: each is a case worth starting from,
named for what it is.  What the fuzzer finds goes in its corpus, which is
kept between runs, not here ([docs/fuzzing.md](../../docs/fuzzing.md)).
The protocol crates' targets start from the C library's corpora
(`fuzz/fuzz-*/seeds` in the C tree), copied with where they came from:

- `h1-request`: C's `fuzz/fuzz-h1/seeds`, each behind a control byte of
  0, named as there (`absuri.http`, `get.http`...), and some of
  `crates/npro-test/h1/requests/`, named as there;
- `h1-response` and `chunked`: some of `crates/npro-test/h1/responses/`
  and `chunked/`;
- `uri`: written for it, a control byte first, its top bit set for a
  reference resolved rather than a URL parsed: RFC 3986's examples, an
  IPv6 literal with a port, and some it refuses;
- `json`: C's `fuzz/fuzz-lejp/seeds`, each behind a control byte of 0,
  named as there, and some written for it: names twice, surrogates,
  noncharacters, numbers and escapes RFC 8259 has and has not, a lone
  number, a policy like npro.rs', and `tight-*` ones reaching the small
  storage's limits;
- `ws-server`: C's `fuzz/fuzz-ws/seeds`, each behind a control byte of 0,
  named as there;
- `ws-pmd`: C's `fuzz/fuzz-ws-pmd/seeds`, each behind a control byte of
  0, named as there, `bomb-2mb-zeros.ws` among them;
- `ws-client`: C has no client corpus, so what the server sent after the
  101 in each of the `ws-client-*` transcripts but the pmd ones, behind a
  control byte of 0, named for the transcript.
- `ss-server`: written for it, a control byte first, then the operations
  `crates/npro-fuzz/src/ss.rs` reads: a GET answered, two pipelined and a
  hangup, a POST's body, a stream destroyed, a head that times out, a ws
  echo and close, ws with permessage-deflate, an upgrade refused, the
  slots running out, a stream connecting out with a GET and with a
  POST's body, a connect that fails, and a GET with a referrer and a
  user agent holding what the access log line must sanitize;
  `regress-pipelined-end` is two POSTs whose bodies arrive together,
  so the bytes that end the first transaction bring the second
  request, which the harness once saw told before the first's end.
- `files`: written for it, a control byte then the request: a file, a
  directory's default document, a route asked for without its `/`, a
  HEAD with a matching `if-none-match`, a large file, a path reaching
  outside the mount, a request for what is not there followed by one
  for the 404 document, and a request for the application's route.
- `proxy`: written for it, a control byte (the split between the
  client's bytes and the origin's, in sixteenths; whether the connect
  fails; the client's write pace) then both: a GET with arguments and a
  cookie answered with a length, a POST's body passed on, an answer
  with no length, a connect that fails, an origin gone mid-head, a
  chunked upload refused, and a HEAD answered with cookies and a
  location; `regress-http10` is an HTTP/1.0 request, whose answer the
  harness once expected in HTTP/1.1.
- `cgi-head`: written for it, a control byte then what a script wrote:
  git's `info/refs` head, a `Location` alone, LF-only lines with a
  length, a head saying `chunked`, and an NPH script's status line,
  which is no header; `regress-crlf-count` is a head of CRLF lines
  near the limit, which takes more input than it keeps, as the
  harness once did not allow for.

A `tight-*` seed's control byte has its top bit set, choosing the small
table with token limits.  A seed named `regress-*` is an input the fuzzer
once failed on, kept so it is tried every run, as in C.
