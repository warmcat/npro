# C's h1 parser, as an oracle

npro's h1 head parser and dechunker (`npro_h1::head`, `npro_h1::chunked`)
are C lws' `lws_parse()` and `lws_http_dechunk_framing()`
(`lib/sansio/http/parsers.c`).  These files say what C's make of a corpus of
heads and bodies, and `tests/h1_c.rs` holds npro's to them.

| file | what it is |
|---|---|
| `requests/` | request heads: `fuzz-h1-*` are C's `fuzz/fuzz-h1/seeds`, the rest are written to reach each branch of C's parser |
| `responses/` | response heads, the same for a client |
| `chunked/` | chunked bodies, to reach each branch of C's dechunker and its two bounds |
| `c-heads.c` | the C program that measures them, built against a C checkout's private headers and static library; not part of npro's build |
| `c-heads.txt` | what it measured: every head as a server's and as a client's in two configurations, and every body, each with twelve variations |
| `C-COMMIT` | the C commit it measured |

Each line of `c-heads.txt` is a configuration, a side, a name, the bytes
in hex, and C's verdict: where a head parsed, its whole table, down to how
many bytes of it were used, so that npro's fills at the same byte as C's.
`c-heads.c` says the format.

The variations, a few bytes changed, inserted, deleted, repeated or cut
off, come from a generator seeded by each file's name, so a new file does
not change any other's.

## What it found

Measuring it found three bugs in C, fixed there first (lws 3c8459075 and
the two before it): C lost nine bytes of every request's ah, and took a LF
as a request's second byte as a bare LF; a strict server took a header
line starting with a bare CR into an unknown header's name; and a repeated
header's value kept its leading spaces.  npro and C now agree on every
case, with nothing allowed for.

## Refreshing

```sh
scripts/sync-c-h1.sh ~/libwebsockets
```

builds C static (no tls, which its parser has nothing to do with), builds
and runs `c-heads.c`, and replaces `c-heads.txt` and `C-COMMIT`.  It takes
a minute or two.  Say in the commit what moved, and why npro follows it.
A head added to the corpus needs a sync before its test sees it.
