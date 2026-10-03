# npro: plan for the sansIO port

Status: agreed, 2026-10-03.  Phases 0 and 1a are done.  npro is the Rust port of
libwebsockets' sansIO half (https://npro.rs).

This plan puts into practice the C tree's porting guide
(`READMEs/README.sans-io-port.md`), the split it rests on
(`README.sans-io-split.md`, `README.wsi-state-machines.md`), `AGENTS.md`
and `docs/agent-context.md`.  Where this plan and those documents disagree,
they win and this plan is wrong.  Each C reference below is to the C tree's
`main-dev` branch as of 2026-10-03 (`75b415f4`).

The work is split into phases.  Each phase is a series of commits, and each
commit builds, passes its tests and has one purpose.  A phase ends when its
exit check passes, not when its code has been written.

## 0. Decisions needed before any code

These are Andy's calls.  Each one has a recommendation and the reason for
it.

1. **Names (decided).**  The project is npro, at https://npro.rs.  The
   repository is https://libwebsockets.org/git/npro.  `lws-core` had been
   taken on crates.io by an unrelated project.  Andy has reserved these
   names: `npro`, `npro-core`, `npro-h1`, `npro-ws`, `npro-h2`, `npro-h3`,
   `npro-quic`, `npro-wt`, `npro-io`, `npro-mqtt` and `npro-http`.
2. **Random, for replay (agreed).**  The port draws lws' random exactly as
   C does.  Random is an injected source (a trait).  The
   test source is xoshiro256** seeded by C's splitmix64, each `get_random(len)`
   drawing `ceil(len/8)` u64s little-endian and discarding the leftover bytes
   of the last one (`lib/misc/prng.c`, `lws_fi_random()`).  Then the seeded
   `ws-client` transcript replays byte for byte: seed 1 gives the key
   `OvomtQpKCWUnZW7tMR6Gqw==` from two u64s and the mask `16739876` from the
   low half of the third, which has been checked by hand against the
   transcript.  This costs almost nothing: the ws client already draws
   16 bytes for the key and then 4 bytes per frame, in call order.

   C's `splitmix64()` (`lib/misc/prng.c`) mixes the state *before* adding
   the increment, where the reference splitmix64 mixes it after.  A port
   using the textbook version draws a different stream.  The phase 1a
   test pins it with the `api-test-random-prng` vector and the `ws-client`
   key.
3. **C behaviours that looked wrong (fixed in C).**  The port follows C as
   fixed on `main-dev`, whose transcripts pin the fixed behaviour:
   - **permessage-deflate** now uses the peer's RFC 7692 parameters for
     the inflater and its own for the deflater, chosen by role (`c85cd0c`).
     The server's extension response takes on only options it can carry
     (`2a90be2`).
   - **A ws upgrade not for version 13 is refused** (`9ede9b1`): 426 with
     `Sec-WebSocket-Version: 13`, or 400 when there is no version.  The
     other upgrade refusals answer 400 (`24ec5a6`), and `Connection: up`
     no longer passes as the upgrade token.
   - **RSV**: one rule for both roles.  RSV1 is allowed only on the first
     frame of a data message with pmd, and never RSV2 or RSV3.  The
     256 MiB frame cap applies on the client too (`16a68d7`).  Refused
     frames close with 1002 or 1009 and a reason (`e9a9f77`).
   - **h1**: a value past its token limit fails the request rather than
     being truncated, answered 414 in the request line and 431 elsewhere
     (`ff19d16`, `c701e9c`).  `/..?` and `/.?` decode correctly, and `+`
     is a space only in the args.

   Two items from the earlier list remain for the port to settle itself.
   Each gets a test in the port:
   - **Fragment-order violations on tx** are still only `assert()`s in C.
     In Rust they are unrepresentable: the message-in-progress state is an
     enum the write API consumes.
   - **Two request-line quirks** were not covered by the fixes: HTTP/0.9
     gets a 403 through the control-character check, and a block with no
     method is refused later with no status.  Both need checking against
     `main-dev` first.
4. **Dependencies (agreed).**  [dependencies.md](dependencies.md) is the
   register, and `deny.toml` admits crates only by name.
   - **SHA-1 and base64** (the ws accept): write them in-tree in the core
     crate, as C does in `lib/misc`, checked against the RFC 3174 and
     RFC 4648 vectors.  They are about 150 lines together and not worth a
     dependency.
   - **permessage-deflate** needs deflate and inflate.  The proposal is
     `miniz_oxide` (pure Rust, `no_std` + `alloc`), behind an opt-in `pmd`
     feature.  The commit adding it justifies it, including its unsafe
     posture and its MSRV.  Writing an inflater ourselves is the
     alternative; it is not recommended for a first pass.
   - **The transcript and test harness** reads the fixed
     `lws-transcript/1` format with a small in-tree reader in a
     `publish = false` test crate, not serde.
   - **No `rand`**: random is injected.
5. **Where buffers come from without `alloc`.**  This is the main API
   decision of phase 1, detailed in section 2.  The proposal: storage is
   the caller's, sized by config, and the connection is generic over it.

## 1. What the C tree gives us to check against

What exists today on `main-dev`:

- **23 transcripts**
  (`minimal-examples-lowlevel/api-tests/api-test-sansio/transcripts/`).
  22 are stage 1 and `h2-oversized-headers` is stage 2.  They cover:
  - an h1 GET with Content-Length, from either side;
  - a ws upgrade, and one masked frame each way;
  - the ws upgrade refusals: version 8, no version, `Connection: up`,
    and an unknown subprotocol;
  - the RSV and huge-frame refusals, on each side, with and without pmd;
  - h1 URI decoding at and past its limits, and a header past its limit.

  They still include no request or response body framing, no ws close
  started by the application, no ping, and no timers.
- **Fuzz seeds**: `fuzz-h1` (9), `fuzz-ws` (8) and `fuzz-ws-pmd` (11).
  None of these three has `regress-*` seeds.
- **The state tables in `lib/sansio/wsi-state.c`**: about 200 rows,
  recorded in `README.wsi-state-machines.md`.
- **`LWS_WITH_STATE_TRACE`**: an edge-set oracle over the whole ctest
  suite.

The port cannot be checked beyond what those cover.  So phase 1 includes
**adding transcripts in C first**, each a case in `api-test-sansio` with
its application written down in the transcripts README.  They are:

- POST with Content-Length;
- POST chunked, with extensions and trailers;
- `Expect: 100-continue` and a 417;
- a pipelined pair of requests;
- a keep-alive idle timeout, which exercises `deadline`;
- a 1xx before 200 on the client;
- a chunked response to the client;
- a ws close, initiated by each side;
- ping and pong;
- a fragmented ws message with a control frame interleaved;
- a ws message larger than one tx buffer, which exercises the pull state
  machine;
- the h1 403, 400, 413, 417 and 501 refusals.  The ws upgrade and URI
  refusals are already covered.

That is C work, committed to the C tree, and it lands before the Rust
equivalent is claimed done.

## 1a. C work before the C tree is a clean basis

First taken stock of on `main-dev` at `02a2f41`.  Re-checked at `7b01adf`,
2026-09-30, by reading the code and by building C lws (no tls; with and
without extensions; with `LWS_WITH_STATE_CHECK`) and running
`api-test-sansio` against its 39 transcripts.

### Resolved since the first look

Each item below is fixed on `main-dev` and pinned by a transcript or an
api-test:

- **The client reset kept the wrong state.**  The reset now keeps the
  pipelining guards, clears the multipart state, and clears
  `seen_zero_length_recv` in every build (`0cc229d`, `api-test-http-transfer`).
- **Stale `handling_404`** (`57f80c5`, `h1-404-keepalive`).
- **`did_stream_close`** is cleared per transaction, and a pipelined
  request waits for a relayed one (`f4198c4`).
- **The close's own bits became states.**  The CLOSE answer no longer
  shares the pong slot; RETURNED_CLOSE is its only marker (`3b25b79`).
  TXN_COMPLETING and CLOSE_STARTED are states, not bits in the word
  (`3ce1f08`, `781023c`, with new close phases CLOSING and
  CLOSE_WHEN_FLUSHED).
- **`sent_response_headers` during a deferred completion** (`c137d69`).
- **ws `inside_frame` is no longer written by IO.**  IO now tells the role
  its output has drained through a new `tx_drained` op (`98e06bd`).
- **A peer CLOSE during a partial send is answered** once the partial has
  gone, and neither role reads after answering
  (`ws-server-close-partial`, `ws-server-ping-close`, `ws-client-ping-close`).
- **`app_rx` boundaries are not behaviour.**  Only each message's or
  body's concatenation, and where it ends, is (transcripts README).
- **The tail of the read is parked before anything acts on the request**
  (`16c7339`).
- **rx results tell "freed" from "lives on in its close"**, as
  `LWS_HPI_RET_CLOSING` (`d3c2136`).
- **The request line is method, target and `HTTP/` digit `.` digit**
  (`8c8d260`, `7b01adf`).
  - A request line with no version (HTTP/0.9) or no method line gets 400.
  - An unknown method gets 501 and HTTP/2.0 gets 505.
  - HTTP/1.2 is served as 1.1.
  - Up to 8 leading empty lines are skipped (the `h1-reqline-*`
    transcripts).
- **The client's body framing is exact.**  Content-Length must be digits,
  and exactly one; Transfer-Encoding must be `chunked` alone (`f70a5be`,
  `h1-client-*`).
- **Changed on purpose:** `rx_policy` may apply the policy as it answers,
  including delivering what the ws extension holds.  This is now
  documented rather than removed.  The port keeps its query pure anyway.

### Resolved at `222ccba`

Re-checked on 2026-09-30, again by reading and by running
`api-test-sansio`.  With `LWS_WITH_STATE_CHECK` on:
- the build without extensions matches all 37 transcripts it runs;
- the build with extensions matches all 41.

The earlier open items are resolved as follows:

- **The seeded transcripts are self-contained.**  Each seeded connection
  reseeds (`a8c6450`).  All 8 draw their key from u64 index 0 of the
  seed-1 stream, checked against C's PRNG.
- **`lws_read_h1()` handles `LRS_TXN_COMPLETING`**, so an h2 or h3 stream
  answered early discards the rest of its body (`eb7f382`).
- **h2 streams hear `tx_drained`**, through `rops_tx_drained_h2`
  (`eb7f382`).
- **The mount redirect raises `REQ_HDRS_COMPLETE` first**, so its
  completion has a row (`70aacb1`).
- **The close phase only goes forwards**, enforced in one place, in
  `lws_wsi_event_x()` (`837431f`).
- **Neither ws role acts on anything after the peer's CLOSE** (`a492da6`).
- **User agents on the reject list are turned away before CONNECT**
  (`60f6e56`).
- **A leading bare LF gets a 400 on purpose.**  The h1 server takes only
  CRLF line ends (`parsers.c:1316`).
- **`multipart_issue_boundary` is removed** (`222ccba`).

### After the security audit, at `258ca9d`

Re-checked on 2026-09-30.  The audit added about 300 commits, of which 57
touch stage-1 paths.  With `LWS_WITH_STATE_CHECK` on:
- the build with extensions matches all 47 transcripts;
- the build without extensions matches the 43 it runs.

Run with `--log-spew-tail 2000`, or the log-spew limiter hides some of the
"matches" lines.  ctest goes by the exit code, so it is not affected.

**Resolved:**
- Ordered comparisons on the close phase are gone.  What remains are the
  `>= LCS_DEAD_SOCKET` tail guards and the forwards-only rule.
- A ws-over-h2 CLOSE answer waits for its window
  (`b430f7d`, `h2-ws-peer-close-skint`).
- `lws_read_h1()` handles the file states.  Body that arrives while the
  answer is going is discarded (`8660de5`).
- Roles, not IO, turn reading back on after a partial send (`f07fe32`).
- STARTTLS refuses buffered plaintext (`4382394`).
- `parent_pending_cb_on_writable` is removed.

**Behaviour the port must copy** (from the audit):
- **Close phases:**
  - ws stops reading while a close phase waits on our own tx.  Reading
    resumes for the ack once our CLOSE has gone (`727d921`).
  - It also stops reading while a pmd tx drain holds (`37b0f0a`).
  - A peer CLOSE is answered only in NONE, CLOSING or
    WAITING_TO_SEND_CLOSE.  In AWAITING_CLOSE_ACK it is the ack; later
    phases end the connection unanswered (`ccddd84`,
    `ws-server-close-when-flushed`).
  - No validity PING once a close has begun (`a9c1009`).
  - A close drops any pending rx inflate drain (`2bcc18c`, `258ca9d`).
- **h1 client:**
  - It reads nothing while sending its request (`41567ac`).
  - HEAD, 204 and 304 responses have no body, whatever CL and TE say
    (`97b0fec`, `h1-client-head-*`, `h1-client-304-cl`).
  - A 1xx before the 101 is skipped (`ce715a9`, `ws-client-interim`).
  - A chunked response that also has a CL is not empty (`aa4c119`).
- **h1 server:**
  - Body framing is decided as soon as the head completes.  An upgrade
    with a body gets 400 (`4e03b7e`).
  - BODY goes to DOING_TRANSACTION exactly once (`5081666`).
  - Every dispatch raises ACTION_BEGIN (`fd7bd0c`).
  - The request head has a hard deadline (`a4a785f`).
  - Only real h1 field names are taken from the lextable (`87b92aa`).
  - Urlargs out of fragments get 414 (`5fbb131`).
  - Known header names match whatever their case (`0cc4423`).

**Design rules the audit's bug classes add:**
- **Drain membership is one piece of state.**  It is never a flag kept
  beside a list (`df0fd03`).
- **A "hold" answer from the rx policy carries "stop reading" in its
  type.**  Only the role resumes reading, at the edge that ends the
  phase.
- **"This state parks rx" is an exhaustive `match`.**  C's list is
  `lws_wsi_state_parks_rx()`.
- **A parked segment's cursor is an offset into it** (`546eb3e`).
- **Walks over children snapshot ids and re-look each one up.**  A
  callback may close a sibling (`693a86a`).
- **Cross-owner references are ids, never borrowed pointers**
  (`fe3fc47`).
- **Close phases are tested with named predicates.**  Where forwards-only
  needs order, it is an explicit rank.

**Resolved by `75b415f4`** (re-checked on 2026-10-02):
- **An h1 request with neither CL nor TE has no body.**  lws clients send
  such a body chunked (`b851fb39`, `2d98d835`, `h1-post-no-length`).
- **Completing from `AWAITING_FILE_READ` has its rows** (`4c68c756`).
- **A raw completion on a closing connection keeps the close's deadline**
  (`5b5d5484`).
- **A partial dropped at a hangup goes to the role's `tx_drained`**, not
  IO's read re-arm (`48c7dc0f`).
- **The server's ws rx drain stops in WAITING_TO_SEND_CLOSE**, as the
  client's does (`b1840724`).
- **`README.sans-io-split.md` now says roles own their read interest**,
  and a hold never leaves reading armed (`0d99cc79`).
- **pmd**: Z_STREAM_END ends a message (`da17ce63`), and an empty message
  after a whole one is the single octet `00` (`462aaf55`).

With `LWS_WITH_STATE_CHECK` on:
- the build with extensions matches all 48 transcripts;
- the build without extensions matches the 44 it runs.

## 1b. Verdict at `75b415f4`: start the port

`main-dev` is a clean enough basis to start.  The parser and framing
rules are consistent, follow RFC 9112, and are pinned by transcripts.
The state table has no `ANY` rows left where the order matters.

Two small items should be fixed in C before phase 1b translates the
state tables.  Neither blocks phases 0, 1a or 1c:

1. **No `BODY_DISCARD` row from `AWAITING_FILE_READ`**, for any role.
   - ISSUING_FILE has one, but AWAITING_FILE_READ does not
     (`wsi-state.c:390-408`).
   - Scenario: a POST with a body is answered with a file.  The app
     completes the transaction while a worker read is out.  After the
     reap (`server.c:3563`), the discard event finds no row, and the
     connection stays in AWAITING_FILE_READ until a timeout.
   - `4c68c756` made this reachable.  Now that the harness can drive a
     worker read (`9130e5af`), it deserves an api-test.
2. **The response watchdog fix (`207455a9`) does not reach h1.**
   `sent_response_headers` is only set by `lws_http_response_started()`,
   which only h2 and h3 call (`ops-h2.c:556`, `ops-h3.c:2448`).  An h1
   answer started during the body still has its timeout cleared at body
   completion, and nothing re-arms it.  Either call it from the h1 write
   path, or record the difference on purpose.

Known divergences, tracked rather than blocked on.  Most are moot in
the port's shape:
- **A bare POLLHUP on an fd asking for nothing closes without reading
  what is pending.**  This is deliberate, and pinned by case 29.  It is
  IO's concern.
- **`tx_drained` does not say whether the output was delivered or
  dropped at a hangup** (`48c7dc0f`).  An h1 TXN_COMPLETING connection
  whose tail was dropped completes as a success.  In the port, the drain
  carries `Delivered` or `Dropped`.
- **Protocol-owned bytes are still pushed** ("Open before it is done"
  item 4).  The port pulls them.
- **Flags beside state**: `client_http_body_pending`, `sending_chunked`
  and the new `client_body_chunked`, `interpreting`, `http_carries_sse`
  and `pong_pending_flag`.  There are also two write-only fields.  The
  port makes them variants.
- **From the review, not re-checked here**:
  - the ws upgrade does not check that the method is GET (RFC 6455 4.1);
  - the reap in `4c68c756` waits on a running worker read on the service
    thread.

### What the port redesigns regardless

These do not need C changes first:
- callbacks become events, applied at event boundaries;
- the parse loops become resumable cursors;
- the port owns a bounded output FIFO for committed bytes, plus the
  POLLOUT slots in C's priority order: CLOSE, then PONG or the CLOSE
  echo, then PING, then the extension drain, then the application;
- rx payloads are owned or connection-buffered where C aliases
  `serv_buf`.

The web-server layer in `http/server/server.c` (4581 lines: mounts, file
serving, ranges, zip fops, interceptor, access log, basic auth,
rewrites) is an application over the h1 protocol.  It becomes a separate
crate, after stage 1.  The only parts of it stage 1 keeps are the status
page and the refusals the transcripts pin.

## 2. Shape of the Rust side

### Workspace

- **Layout**: one workspace, members under `crates/`.  A crate is added
  when the phase that gives it content starts, not before.
  - `npro-core`: time, random, ids, the connection machines, the
    substrate (sha1, base64, utf8).
  - `npro-h1`: the h1 parser, chunked coding, and the h1 client and server
    transaction.
  - `npro-ws`: framing, handshake, close, and optional pmd.
  - `npro-io`: std, sockets, the loop.  It comes later, and tls later
    still.
  - `npro`: the facade.
  - `crates/npro-test` (`publish = false`): the transcript reader, the
    in-memory two-sided transport, the replay driver and the property-test
    helpers.
- **Crate roots**:
  - every one carries `#![forbid(unsafe_code)]` and `#![no_std]`,
    except `npro-io` and `npro-test`;
  - `alloc` only behind a feature;
  - `unexpected_cfgs` is denied in `[workspace.lints]`, along with
    `missing_docs` and the clippy set from AGENTS.md.
- **Toolchain**: MSRV 1.85, as the placeholder has, which is the edition
  2024 floor.  CI builds at 1.85 and at stable.
- **CI gates** from AGENTS.md, committed before any protocol code:
  - `cargo fmt --check`;
  - `clippy -D warnings` with the core lint set;
  - `cargo doc` with `missing_docs` denied;
  - `cargo deny` with a committed `deny.toml`;
  - `cargo audit`;
  - the MSRV build.

  `scripts/ci.sh` runs them all.  Cloud sessions install cargo-deny,
  cargo-audit, cargo-fuzz and cargo-semver-checks themselves.

### The interface, following the C contract

The C contract (`lws_io_ops_t`, ABI 1) becomes the following, in the
quinn-proto style: IO calls in, and sansIO returns what it wants done.

| C | Rust |
|---|---|
| `rx(bytes) -> consumed`, empty = peer closed | `conn.rx(now, &mut [u8]) -> Result<Rx<'_>, Error>`, with `rx.consumed` and `rx.event: Option<Event<'_>>`.  It takes `&mut` so that ws unmasks in place, and it returns at the first event, borrowing its payload from the input.  The caller loops while progress is made ("a parse that consumed less is a held byte").  `conn.rx_closed(now)` is the peer closing |
| `tx(buf, max) -> n, more` | `conn.tx(now, &mut [u8], &mut impl TxSource) -> Tx`, with `written` and `more`.  The connection's own frames (status lines, 101, CLOSE, PONG) come from its state.  The application's payload is pulled from `TxSource` into the buffer *behind* the frame header the connection has reserved.  That is C's `LWS_PRE` framing in place turned into a pull, with no copy and no parking.  This is "Open before it is done" item 4 |
| `deadline()` | `conn.deadline_passed(now)`.  `conn.next_deadline() -> Option<Instant>` is a query, not a request |
| `want_write`, `want_read(on/off)`, `close(phase)` | `conn.poll_request() -> Option<Request>`: `WantWrite`, `WantRead(bool)`, `Close(Phase)`.  Only the phases that exist for stage 1: quiesce, shutdown, stage, release |
| `transport(up/failed/gone)` | `conn.transport_up(now, TransportInfo)`, carrying alpn and tls-ness, which IO sets before up; `conn.transport_failed(now)` |
| callbacks (125 reasons) | `Event` variants returned from `rx` / `poll_event()`, and the application's calls made between them.  Stage 1 needs about 15: request headers, body chunk, body done, response headers, response body, ws established, ws message fragment, pong, peer close, closed, writeable |
| `lws_service_set_now()` | `now: Instant` is an argument of every entry point.  `Instant` is a newtype of µs `u64` and `WallTime` one of seconds.  Monotonicity is enforced (debug assert plus saturating) |
| `lws_get_random()` | a `Random` trait, handed in where drawn (`&mut dyn` or generic: to be settled in phase 1a) |

Buffers without `alloc`:

- **The header table.**  C's `ah` is a pool of `max_http_header_data`-byte
  tables with a fragment index.  The Rust `HeaderTable<S: AsMut<[u8]>>`
  has its capacity fixed by `S`: `[u8; 4096]` on a device, or
  `Box<[u8]>` with `alloc`.  The fragment index is a fixed array of
  `(offset, len)` newtypes per known token.  Header presence is explicit,
  as a `Present` variant, not a length.  Unknown headers are records in
  the same storage.
- **Rx.**  The ws rx buffer does not exist as such: payload is delivered
  from the input slice, in fragments, with `rx_buffer_size` as the
  fragment cap.
- **Tx.**  The tx side owns nothing but its position.

The **connection** is one struct holding four machines, each its own enum
whose variants carry the data of that state:

- `Transport`: phase 1 needs only `Up` / `Failed`, but all of C's variants
  are declared so that the trace maps.
- `Carrier`, per role.
- `Transaction`, per role.
- `Close`.
- The role is an enum of role states (`H1Server`, `H1Client`, `Ws`, ...),
  and a role change is a transition.
- **Events**: C's `LWS_WSIEV_*` become a `WsiEvent` enum.  The transition
  function is one `match (role, side, state, event)` per machine, with no
  `_ =>` arm, so an unlisted edge does not compile rather than being
  checked.  Rows where C accepts `ANY` source state are spelled out.  The
  plan is to list them from the C table, and question each one in review:
  `RESTART`, `CONN_FAILED`, `RETARGET`, `CLOSE_FLUSH`, `CLOSE_STAGED` and
  `SOCKET_GONE`.
- **Trace**: behind a `trace` feature, the port writes the same line as C's
  `LWS_WITH_STATE_TRACE`, `LRS h1/S:HEADERS -> h1/S:ESTABLISHED set_state ev=...`.
  That makes the C edge set over the same transcripts diffable against
  the port's: README.sans-io-split.md rule 3, "the trace is the oracle".
- **Close invariants** are types, not checks.  Examples: the ws close
  states exist only inside the `Ws` role, so `RETURNED_CLOSE` on a
  non-ws role cannot be written.  `Shutdown` exists only on the server
  side.

## 3. Phases

### Phase 0: scaffold and gates (done, 2026-10-03)

Three commits:
- **The workspace** (`crates/*`, with the `npro` facade), its
  `[workspace.lints]`, `clippy.toml`, `deny.toml`, the README, and
  `scripts/ci.sh`.  CI runs fmt, clippy (with all features and with the
  defaults), test, doc, the MSRV 1.85 check, the no_std build, cargo deny
  and cargo audit.
- **`npro-test`**: a strict reader for `lws-transcript/1`, and copies of
  the C transcripts with `C-COMMIT` and the C README beside them.
  `scripts/sync-c-oracle.sh` refreshes them from a C checkout.  C's fuzz
  seeds join `fuzz/seeds/` with the targets that use them.

**Exit check, met**: every gate passes at 1.85 and at stable, and the
reader takes all 48 transcripts.

### Phase 1a: substrate in the core crate (done, 2026-10-03)

- **Random**: the `Random` trait, one draw per `fill()`, failing as
  `Unavailable`.  `SeededRandom`, behind the additive `replay` feature, is
  C's stream; it is pinned by the `api-test-random-prng` vector and by the
  ws-client transcript's key and first mask.
- **`sha1` and `base64`** (encode only), with their RFC vectors and
  RFC 6455's accept value.
- **The incremental UTF-8 validator.**  It is checked exhaustively
  against `core::str::from_utf8`, and once, outside the tree, against C's
  own `lws_check_utf8()`: 134M cases, none differing.
- **`time::Instant`**, in microseconds, with `core::time::Duration` for
  intervals.  Wall time and deadlines come with their first users.
- **Ids and size newtypes** move to the crates that define them: a
  `StreamId` belongs to h2.

**Property tests** need no dependency.  The generators are written over
`SeededRandom`, so a failing case is reproduced from its seed.  Every
parser gets the one-shot vs fragmented oracle.

**Exit check, met**: the vectors pass, and clippy passes with
`indexing_slicing`, `arithmetic_side_effects` and `as_conversions`
denied.

### Fuzzing (done, 2026-10-03)

Ahead of the parsers, so that each is fuzzed from its first commit:
`crates/npro-fuzz` holds a harness per target with an oracle, smoke-tested
in `cargo test`; `fuzz/` holds the libFuzzer targets in a workspace of its
own; `scripts/fuzz.sh` runs them by hand and under sai, in CI and idle
time, with the corpora in a sai pool.  The first targets are the
substrate's: `utf8`, `sha1`, `base64`, and the transcript reader.
[fuzzing.md](fuzzing.md) has the details.

### Phase 1b: the connection machines

- The four machines and the `WsiEvent` transition function, for the roles
  in stage 1: h1 client and server, ws, and raw if cheap.
- Property tests:
  - no event sequence reaches a state the C table does not;
  - the invariants of section 2 hold.
- A test that checks the port's full edge set against a vendored
  `sort -u` of C's trace over its ctest suite, restricted to stage-1
  roles, in both directions.  An edge C has and the port lacks, or the
  reverse, fails with the edge named.

**Exit check**: the edge-set comparison is clean, or every difference is
listed and agreed.

### Phase 1c: h1 parsing

- **The request and response header parser.**  It is byte-restartable,
  with no recursion.  Its limits come from config:
  - `max_http_header_data`, 4096 by default and capped at 32768;
  - the per-token limits;
  - `WSI_TOKEN_COUNT` fragments.
- **Name matching.**  This is a `match` on the lowercased name, not C's
  generated lextable trie.  The trie is an implementation detail; the
  token set, the colon handling, and the method and version strings are
  the behaviour.
- **URI decoding and normalisation.**  `%XX`, then the control-character
  refusal, then `//`, `/./` and `/../`, never above root, plus the
  urlargs splitting.  The refusals are the same as C's `LPR_REFUSED`: 403,
  or 414 / 431 past a limit, pinned by the `h1-uri-*` and
  `h1-header-past-limit` transcripts.
- **The chunked decoder**, shared by client and server.  It requires at
  least one hex digit, and extensions plus trailers are bounded at 4096
  bytes per body, as C does.
- **Tests**:
  - the one-shot vs randomly fragmented oracle, as a property test;
  - fuzz targets `h1-request`, `h1-response` and `chunked`, seeded from
    C's `fuzz/fuzz-h1/seeds`, added as [fuzzing.md](fuzzing.md) says;
  - a differential test against C on the same inputs, comparing the
    parsed token table and the verdict.  This needs a small C harness
    built from the reference tree outside this repository; it is
    optional in CI.

### Phase 1d: the h1 transaction, server and client

- **Server** (`lws_http_action` rules, in C's order): CL with TE gives
  400; more than one Host gives 400; Expect gives 417 or a 100; TE other
  than a lone `chunked` gives 501; CL is parsed strictly with overflow
  checked, and over the maximum gives 413; plus Connection keep-alive
  rules by version, the body states, `DISCARD_BODY`, the pipelining limit
  of 64, and the TXN_COMPLETED / drained handling.
- **A request with neither CL nor TE has no body**, per RFC 9112 6.3
  rule 7.  C's server still reads a POST, PUT or PATCH body to the close,
  while its proxy path already treats it as zero-length.  See section 1a,
  open item 3: C decides, and a transcript pins it, before the port
  claims it.
- **Client**:
  - request composition in C's exact header order (the transcript pins
    it);
  - 1xx swallowed up to 8, with the header table rewound;
  - CL and chunked bodies, and read-to-EOF when there is neither;
  - the body pulled at the application's pace, never buffered;
  - the kept-warm `IDLING` state with its deadline.
- **Body bytes that arrived with the headers** are kept.  With the
  borrow-from-input rx this is structural: the rx simply does not consume
  them until the body event.

**Exit check**: `h1-client-get` and the first exchange of `h1-ws-server`
replay byte for byte, plus the new C transcripts of section 1 that cover
h1.

### Phase 1e: ws

- **The handshake.**
  - **Server upgrade**:
    - the Connection token must include `upgrade`;
    - Sec-WebSocket-Key must be present and under 128 bytes;
    - the subprotocol is the first known one, or the default;
    - the 101 is written in C's order, with `Upgrade: WebSocket`
      capitalised as the transcript has it.
  - **Client**: 16 random bytes for the key, then the response is
    checked: status 101, Accept, Upgrade and Connection, and the offered
    protocol.
- **The frame parser.**
  - Server and client are one parser parameterised by side, not two as in
    C.
  - It checks opcodes, RSV, continuation and FIN ordering, masking by
    side, control-frame length and fragmentation, and the 64-bit length
    top bit.
  - The configured frame and message maxima apply on both sides.
  - UTF-8 is validated incrementally, with close codes 1002 and 1007 as
    C uses them.
- **Tx framing** as a pull, the mask drawn per frame.
- **The close machine**:
  - `WaitingToSendClose`, then `AwaitingCloseAck`;
  - `ReturnedClose`, where the peer's payload is echoed;
  - `FlushingBeforeClose`;
  - the received-code rewrite to 1002 per side;
  - 5 s CLOSE_SEND and CLOSE_ACK deadlines, 3 s on the client's reply;
  - the one-pending-pong rule, and the POLLOUT priority order: CLOSE,
    then PONG or the echoed CLOSE, then keepalive PING, then the
    application.
- **Keepalive**: 40 / 50 s by default, with the ping payload being the
  8-byte `now`.

**Exit check**: `ws-client` (seeded) and `h1-ws-server` replay byte for
byte, as do the new ws transcripts.  The fuzz target is seeded from
`fuzz/fuzz-ws/seeds`.

### Phase 1f: permessage-deflate (feature `pmd`)

- Negotiation, the parameters with their C ranges, the zip-bomb cap of
  256 MiB per message (configurable), and the drain budget.
- Parameters are chosen per direction by role, as C now does (`c85cd0c`).
- The fuzz target is seeded from `fuzz/fuzz-ws-pmd/seeds`, which includes
  `bomb-2mb-zeros`.

### Phase 1g: minimal `npro-io`

- std TCP, plain poll-style loop, no tls yet.  Enough to run:
  - **autobahn's fuzzingclient** against the ws server.  This is a
    conformance gate.  It needs a Python tool, so Andy must say where it
    may run;
  - **a differential run** of the port's client against C's
    `minimal-http-server` and ws echo, and the reverse.
- tls: rustls is the obvious candidate.  It is a large dependency tree,
  so it is a separate decision, not taken here.

### Later stages

Later stages follow the port guide's order and wait for their C
transcripts: h2 (stage 2), quic and h3 (stage 3), and mqtt (stage 4).
The guide's "Do not copy" list stays in force: a quic frame in flight is
not pending output; mux parked rx; the kept-warm joiner's status.

## 4. Checks at a glance

| check | from | where it runs |
|---|---|---|
| transcripts byte for byte | C `api-test-sansio` | `cargo test`, every commit |
| state edge set vs C trace | C `LWS_WITH_STATE_TRACE` | `cargo test`, vendored edge file |
| one-shot vs fragmented parse | agent-context "Parsers" | proptest, every parser |
| fuzz, with an oracle per target | C's `fuzz/fuzz-*/seeds`, copied into `fuzz/seeds/` | smoke tests in `cargo test` everywhere; libFuzzer in sai CI and idle time ([fuzzing.md](fuzzing.md)) |
| differential parse vs C | C tree built outside the repo | optional CI job |
| autobahn / h2spec / h3spec | conformance suites | per phase, once `npro-io` exists |
| lints, docs, deny, audit, MSRV | AGENTS.md | CI, every commit |

## 5. Not settled by this plan

- The core crate's name (decision 0.1).
- The mapping from each of C's callback reasons to an `Event`.  This plan
  lists the stage-1 set only.
- Whether `Random` is `&mut dyn` or a generic parameter.  Generic avoids
  the vtable, but spreads a type parameter through every connection.
- tls in `npro-io`.
- Where autobahn and the C differential builds run in CI.
