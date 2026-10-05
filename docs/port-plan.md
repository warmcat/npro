# npro: plan for the sansIO port

Status: agreed, 2026-10-03.  Phases 0 to 1d are done.  npro is the Rust port of
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

The **connection** is four machines, each its own enum, with the role,
the side and the socket's usability: `npro_core::state::Machines`.  As
built in phase 1b, which departs from the first form of this plan (per-role
enums carrying each state's data) for reasons given there:

- `Transport`, `Carrier`, `Live` (the transaction) and `Close`, each one
  enum shared by every role, as in C; all of C's transport phases are
  declared.  The fields are private, and only the event table writes them.
- `Role` (`None`, `H1`, `Ws`, `RawSkt` so far) and `Side`; a role or side
  change is a transition like any other.
- **Events**: C's `LWS_WSIEV_*` are the `Event` enum.  The transition
  function is one `match` on the event, exhaustive, so an event cannot be
  added without its rows; within it, the rows are C's, in C's order, with
  `_` for C's `"*"` and `ANY`.  An event with no row is refused, as C
  refuses it (and `LWS_WITH_STATE_CHECK` aborts).  The `ANY` rows are C's
  as they are: `RESTART`, `CONN_FAILED`, `RETARGET`, the close events.
- **Trace**: every change is an `Edge`, whose `Display` is the line C's
  `LWS_WITH_STATE_TRACE` writes, less the connection's tag:
  `LRS h1/S:HEADERS -> h1/S:H1_UPGRADE set_state ev=REQ_HDRS_COMPLETE`.
  It needs no feature: writing lines is the IO side's business.  That
  makes C's edge set diffable against the port's: README.sans-io-split.md
  rule 3, "the trace is the oracle".
- **Close invariants** are refusals, as C's check makes them aborts: no
  polite close phase entered with the socket unusable, no shutdown on a
  raw socket, the close never going backwards, no live state while a
  client restarts.  The rows themselves keep `RETURNED_CLOSE` to ws and
  `SHUTDOWN` to servers.

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

### Phase 1b: the connection machines (done, 2026-10-04)

- **`npro_core::state`**: the four machines, the role, side and socket,
  the `Event` enum and C's event table rows for the stage-1 roles: h1
  client and server, ws, and raw sockets.  The setters are C's
  (`lws_wsi_set_state_ev()`, `lws_wsi_role_transition_ev()`): a live state
  ends the transport phase, a handshake-named state is the carrier's until
  it is established, a restart leaves the old socket and close behind.
- **The oracles**, in `crates/npro-test/states/` (`scripts/sync-c-states.sh`
  refreshes them): C's table rows with their line in `wsi-state.c`, every
  distinct edge C's ctest suite takes and every table row it fires (C's
  `LRSROW` trace), over the three builds C measures coverage with, all with
  `LWS_WITH_STATE_TRACE` and `LWS_WITH_STATE_CHECK`, and C's README, which
  lists the rows no test fires and why.
- **The tests**, `crates/npro-test/tests/states.rs`:
  - a second model of C's machines, in C's terms, reading its rows from
    the copy of C's table.  Every state the port reaches from a birth
    (3,022 of them, walked exhaustively, which subsumes the property
    tests this plan asked for) is driven with every event, with and
    without each role a site can give, through both: 604,400 cases,
    agreeing on refusal, machines after, setter and trace line;
  - every one of C's 244 stage-1 edges is one the port takes;
  - the structural invariants hold in every reachable state.

  Each was checked by planting bugs: a wrong row, a missing row, a setter
  keeping the transport or the dead socket, the close going backwards, no
  unusable-socket rule, tracing every edge.  Every one fails the tests.

**Exit check, met.**  The port takes every edge C's suite takes, and none
C's table does not.  The plan's other direction, every edge the port can
take seen in C's trace, was the wrong measure: rows that fire from any
state multiply into thousands of edges whose code is one path.  It is
replaced by row coverage.  C's trace now names each table row as it fires,
C's suite was given tests for the rows it never fired (and fixes where
those found bugs), unreachable rows were dropped, and C's README lists
every row still unfired with why: 21 over its three builds.  npro's states
test requires each row npro's machines can fire to be one C's suite fires
or one of those.  That check needs the oracle measured where C measures
it: a host without IPv6 never connects to a second address, and h3
needs gnutls.

**The machines' shape, agreed (2026-10-04)**: one enum per machine,
shared by the roles, as C's are, rather than per-role enums carrying each
state's data.  The protocols share the machines' abstractions: the close
machine is one ordered sequence the ws phases sit inside, which a role
change carries (h1 to ws), and the carrier's names are reused per
transaction.  Keeping C's shape also lets the port be held to C's table
row by row.  Typed per-role views for the protocol crates (an `H1Server`
that can only be in its states) can sit on top when phase 1d has callers
for them.

### Phase 1c: h1 parsing (done, 2026-10-04)

The crate `npro-h1`, `no_std` with no dependencies, is C's
`lib/sansio/http/parsers.c`:

- **`token`**: C's `enum lws_token_indexes`, its 97 tokens with C's
  indices and spellings, with every header option on as C's default build
  has it.  Name matching is `lookup()` over the spellings: no spelling is
  the start of another, so a name is matched exactly when C's lextable
  reaches its terminal, and the trie itself is not ported.
- **`table`**: C's ah, `HeaderTable<S>` over caller-owned storage, at most
  32768 bytes.  Its layout is C's byte for byte in what it uses up (each
  value's NUL, each unknown header's eight byte record, the `?`'s unused
  byte, C's 97 fragment slots), so a head fills it at the same byte as C's.
  Presence is a `Slot::Present`, not a nonzero index.  A client's own
  request goes in with `create()`, and an interim response is dropped with
  `snapshot()` and `rewind()`.
- **`head`**: C's `lws_parse()` and `lws_parse_urldecode()`, byte for byte
  restartable.  C's `parser_state`, `ues`, `ups`, `post_literal_equal`,
  `lextable_pos` and `unk_pos` are enums.  A refusal is a `Cause`, one per
  way out of C's parser, and what a server answers for it (`LPR_REFUSED`'s
  400, 403, 414, 431, 501 or 505, or none for `LPR_FAIL`).  Limits are the
  table's size and per-token `Config::with_limit()`, C's `token_limits`.
- **`chunked`**: C's `lws_http_dechunk_framing()`, handing back the payload
  where it lies in the input; **`fields`**: C's Content-Length and
  lone-`chunked` Transfer-Encoding readers.

Porting it found three bugs in C, fixed there first (lws 3c8459075 and
the two before it), so npro follows C as it now is: C marked "no name
begun" by the name's record being at offset 0, which a server's first
name is, so it began that name twice, losing nine bytes of every
request's ah, and took a LF as a request's second byte as a bare LF; C's
strict server took a header line starting with a bare CR into an unknown
header's name; and a repeated header's value kept its leading spaces,
where RFC 9110's OWS is not part of a value.

**The tests**, in `crates/npro-test`:

- **The differential test against C**, `tests/h1_c.rs`.  The plan had it as
  a C harness in an optional CI job; it is instead an oracle vendored like
  the state machines': `scripts/sync-c-h1.sh` builds C static, compiles
  `h1/c-heads.c` against its private headers to call `lws_parse()` and the
  dechunker directly, and records what C makes of a corpus (C's fuzz-h1
  seeds and heads written to reach each branch, as a server and as a
  client, and chunked bodies), with twelve variations of each, in C's
  default configuration and a tight one: 7,007 cases.  npro must reach
  the same verdict and leave the same table, down to the bytes used.
- **The one-shot vs fragmented oracle** over the same heads, each split
  three ways, and over every transcript's first request split at each
  byte.
- **The transcripts**: the `h1-uri-*`, `h1-reqline-*` and
  `h1-header-past-limit` requests come to the path, urlargs or refusal C's
  `sansio-uri` app answered with, and the h1 client cases' heads and
  framing headers read as C read them (`tests/h1_heads.rs`).
- **Fuzz targets** `h1-request`, `h1-response` and `chunked`, seeded from
  C's `fuzz/fuzz-h1/seeds` and the corpus ([fuzzing.md](fuzzing.md)).

**Exit check, met.**  Every case of the vendored oracle agrees with C,
and planted bugs in the
parser and dechunker (a limit off by one, `+` left alone in the query, the
continuation's SP dropped) each fail it.

### Phase 1d: the h1 transaction, server and client (done, 2026-10-05)

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

**The server half (done, 2026-10-05)**: `npro_h1::server::Server`, one
connection's transactions.  `rx` takes at most one thing per call, a
request's head, a piece of its body borrowed from the input, or the body's
end, and holds what it did not take, so pipelined requests wait and body
bytes that came with a head are never lost.  `respond` composes C's status
line and headers, `tx` writes what the connection owes and then pulls the
payload from a `TxSource`, and `complete` is C's
`lws_http_transaction_completed()`.  C's checks between head and app run
in C's order (400 for both framings or two Hosts, 417, 501, 400 for a bad
or second Content-Length, 413), a refusal is C's status page and a
shutdown, an answer short of its length or without one shuts down, and
keep-alive follows the version and `Connection`.  A request with neither
Content-Length nor Transfer-Encoding has no body, as C now has it
(`h1-post-no-length`).  `tests/h1_server_replay.rs` replays 19 of C's
server transcripts byte for byte with C's `sansio-uri` app: the `h1-uri-*`
and `h1-reqline-*` ones, `h1-header-past-limit`, `h1-post-no-length`,
`h1-short-answer` and `h1-body-done`.

**The client half (done, 2026-10-05)**: `npro_h1::client::Client`, one
connection's transaction.  `tx` writes the request head as C's
`lws_generate_client_handshake()` composes it, in C's order (request line,
`Pragma` and `Cache-Control`, `Host`, `Origin`, `connection: close`).
`rx` takes the response a thing at a time, as the server does, so the body
is pulled at the application's pace: a 1xx other than 101 is rewound out
of the table, up to 8; a HEAD's answer, a 204 or a 304 has no body; a
lone `chunked` wins over a Content-Length; a list of codings, or a second
or malformed Content-Length, fails the connection; with neither, the body
runs to the close, `rx_closed`.  The status is C's `atoi()` of the status
line.  `tests/h1_client_replay.rs` replays the seven h1 client transcripts
that need nothing more (not `h1-client-digest-retry`): the request byte
for byte, the body the app is given, and the release exactly where C
released, or else a complete transaction.

**Exit check, met**: `h1-client-get` and the first exchange of
`h1-ws-server` replay byte for byte, with the server and client
transcripts above.

Not yet, for later phases or when something needs them: the connection
machines of phase 1b drive neither side; no 100 Continue is sent; a
server's fallback role is a shutdown; a client sends no request body,
follows no redirect, does no digest auth, and has no kept-warm `IDLING`
state with its deadline; and neither side has a fuzz target of its own.

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

**The server half (done, 2026-10-05)**: the new crate `npro-ws`.
`handshake::server` is C's `lws_process_ws_upgrade()` over the h1
server's request: a GET, `upgrade` among the `Connection` tokens, a key
under 128 bytes and a Host, version 13 (none is a 400, another a 426
saying `sec-websocket-version: 13`), and the first subprotocol of the
request's list the server has, or its default for none; a refusal is
answered by the h1 server's new `refuse_upgrade`, with C's status page.
`response_101` is C's 101, header for header.  `conn::Ws` is the
connection after it, sans-IO as the h1 sides are: `rx` takes a thing at a
time and unmasks a payload where it lies, handing the application each
piece of a message as it arrives, with whether it starts and ends the
message, rather than C's whole frame up to its rx buffer; control frames
are gathered, a ping answered with C's one pending pong, the peer's close
answered with its own payload, its code made 1002 as C's
`answer_peer_close` makes it.  What C refuses is refused with C's close
code and reason, and nothing is read after either close.  `tx` writes in
C's order and pulls the application's payload, as the h1 server does;
`close_when_flushed` is C's close with no close frame once the last
message has gone.  `crates/npro-test/tests/ws_server_replay.rs` replays,
byte for byte, four bytes at a time, with C's echo app: all of
`h1-ws-server`; the refused upgrades `ws-server-version-8`, `-no-version`,
`-conn-no-upgrade`, `-no-subprotocol` and `-not-get`; and
`ws-server-ping-close`, `-close-partial`, `-close-when-flushed` and
`-huge-frame`.  The fuzz target `ws-server` is seeded from C's
`fuzz/fuzz-ws/seeds`.

**The client half (done, 2026-10-05)**: `handshake::ClientKey` is C's
`lws_generate_client_ws_handshake()` and `lws_client_ws_upgrade()`: a
key of 16 bytes drawn in one draw, the request's upgrade lines in C's
order, which the h1 client's request carries in place of `connection:
close` (`npro_h1::client::Connection::Upgrade`, after which the final
response is handed over unframed), and C's checks of the response in C's
order: a 101, an accept, `Upgrade: websocket`, `upgrade` among the
`Connection` tokens, a subprotocol, if named, that was offered, no
extension, and the key's accept.  `conn::Ws` is now one parser for both
ends, a client's `Ws::client` masking each frame with a mask drawn when
the frame is begun, and checking each end's rules in its C parser's order
("srv mask", "bad fin", the client taking 1012 to 1015 from a server).
After a refusal, as C, the rest of the read is dropped, and once our close
has gone, whatever comes ends the connection.
`crates/npro-test/tests/ws_client_replay.rs` replays, byte for byte, with
C's seeded random and C's `callback_client`, `ws-client`,
`ws-client-interim`, `ws-client-ping-close`, `ws-client-huge-frame`,
`ws-client-rsv1-no-ext` and `ws-client-rsv2`: the request, every masked
frame, the app's messages and where C closed.  The fuzz target `ws-client`
is seeded from those transcripts, C having no client corpus.

Porting it found one difference kept from C: C's client takes any
`Connection` token that starts `upgrade` (it compares only the token's
length of it), so `Connection: up` passes; npro takes only `upgrade`.

**Exit check, met**: `ws-client` (seeded) and `h1-ws-server` replay byte
for byte, as do the new ws transcripts but the pmd ones (phase 1f) and
`ws-client-digest-retry` (digest auth); the fuzz targets are seeded from
`fuzz/fuzz-ws/seeds` and the client transcripts.

Not yet: nothing here has time, so there are no close deadlines and no
keepalive pings; the application cannot yet begin a close of its own with
a code, only close once flushed; the frame maximum is C's fixed 256 MiB,
not configured, and there is no message maximum; the h1 server does not
yet answer an unknown `Upgrade` with C's 403, or an upgrade with a body
with its 400; a message's pieces are the application's to gather; and an
application's message goes as one final frame.

### Phase 1f: permessage-deflate (feature `pmd`)

- Negotiation, the parameters with their C ranges, the zip-bomb cap of
  256 MiB per message (configurable), and the drain budget.
- Parameters are chosen per direction by role, as C now does (`c85cd0c`).
- The fuzz target is seeded from `fuzz/fuzz-ws-pmd/seeds`, which includes
  `bomb-2mb-zeros`.

**Done (2026-10-05)**, behind npro-ws's `pmd` feature, with `miniz_oxide`
and `adler2` admitted as [dependencies.md](dependencies.md) has them.
`npro_ws::pmd` negotiates: a server takes the first `permessage-deflate`
offer it can keep to (`server_accept`), with `server_no_context_takeover`
and `client_no_context_takeover` as C takes them, and says so in its 101;
a client offers `permessage-deflate` and takes the server's answer if its
parameters are RFC 7692's, each once, in C's ranges (`client_accept`).
`Ws::with_pmd` then inflates a message whose first frame has RSV1, RSV1
being refused anywhere else as C refuses it: its payload is held, unmasked,
at most 1KiB at a time, inflated into at most 1KiB a call, the drain
budget, with `rx_pending` saying when there is more to give without input;
the trailer is put back at its end; data after a BFINAL that is not
padding, data that does not inflate, and a message past its limit (C's
256MiB, `Params::with_max_message`) drop the connection, as C marks its
socket unusable, what inflated before the failure given first.  What the
application sends is deflated into frames of at most 1KiB, RSV1 on the
first, the flush's trailer removed, an empty message after a flush C's
one octet.  Context is dropped per message as each side agreed: the
deflater for our own `*_no_context_takeover`, the inflater for the peer's,
or when its stream ended.

The tests: all four pmd transcripts replay (`ws-client-pmd-rsv2`,
`-rsv1-continuation`, `-rsv1-ping`, and `ws-server-pmd-rsv1-continuation`,
through the `sansio-pmd` vhost); RFC 7692 7.2.3's example frames inflate,
one piece at a time and in larger ones; messages of every size around the
1KiB bounds, compressible and not, go client to server and back, written
four bytes at a time and read a byte at a time, with and without context
takeover; and the fuzz target `ws-pmd`, seeded from C's
`fuzz/fuzz-ws-pmd/seeds`.  Fuzzing it found that a caller must be told to
come back for what inflates without more input (`rx_pending`), and that
what inflated before a failure must be given first, so the check of text
sees the stream in order.  What npro deflates was also inflated by zlib
(Python's), as C's peers would, by hand: that is how the window below was
found, and is not yet a test.

Differences from C, each where C does something RFC 7692 does not have:

- `miniz_oxide`'s smaller windows refer further back than they say (zlib
  finds distances too far back from a 9 bit window, and from any under
  14), so npro's deflater always uses 32KiB.  A server declines an offer
  asking for a smaller `server_max_window_bits`, and tries the next, as
  RFC 7692 7.1.2.1 has it; C takes the offer and leaves the parameter
  out, still deflating with 32KiB.  A client refuses a
  `client_max_window_bits` under 15, which it did not offer; C takes it.
- A client refuses the lws-private options C takes from a server
  (`rx_buf_size` and the like), and a parameter given twice.
- A server takes the first offer it can keep to; C takes the first
  `permessage-deflate`, and drops the connection if it is offered twice
  before an offer with parameters.

Not yet: the deflater's compression level and the 1KiB chunks are C's
defaults, not configurable; a client offers only `permessage-deflate`, with
no parameters; no permanent test inflates npro's output with zlib (the C
oracle's `sync-c-h1.sh` is where one would go); the `x-webkit-deflate-frame`
and other extensions are not ported.

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
| differential parse vs C | C's `lws_parse()` and dechunker over a corpus, `scripts/sync-c-h1.sh` | `cargo test`, vendored `c-heads.txt` |
| autobahn / h2spec / h3spec | conformance suites | per phase, once `npro-io` exists |
| lints, docs, deny, audit, MSRV | AGENTS.md | CI, every commit |

## 5. Not settled by this plan

- The core crate's name (decision 0.1).
- The mapping from each of C's callback reasons to an `Event`.  This plan
  lists the stage-1 set only.
- Whether `Random` is `&mut dyn` or a generic parameter.  Generic avoids
  the vtable, but spreads a type parameter through every connection.
- tls in `npro-io`.
- Where autobahn runs in CI, and whether the C oracles are measured there (`sync-c-states.sh` and `sync-c-h1.sh` are run by hand).
