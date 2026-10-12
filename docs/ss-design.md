# Secure Streams in npro: SS2

**Draft, 2026-10-12, for Andy to review before any of it is built.**  It
is the stream and service API that [ss-policy.md](ss-policy.md)
configures, over the driver of [io-model.md](io-model.md).  What is not
yet agreed is marked, and listed at the end.

**SS2** is npro's Secure Streams as a whole: the streams, the policy of
ss-policy.md (C's SS policy and lejp-conf blended into one), and the
serialised form for remote devices (SSPC, below).  Its main departure
from C's SS is that the policy is flexible and mostly invisible: a
program that names a URL needs none, and one that has a policy is not
shaped by it.  The crate is `npro-ss`, a name not yet reserved on
crates.io.

## Why it comes before the examples

C lws has around a hundred minimal examples, one per feature, each with its
own `main()` and its own way of doing the same few things.  npro is not to
repeat that: the boilerplate and the effort of keeping them are too
much, and the story they tell users is too complex.  SS is npro's user
API for client and server ([ss-policy.md](ss-policy.md)), so what the
examples did is done by **one utility**, as busybox is one program, or
curl one tool with many options.  Not yet designed; what is agreed of it
(Andy, 2026-10-12):

- **One program, client and server.**  What C has a minimal example for
  is an option or a subcommand of it: fetch, post, ws, raw, a large URL,
  metadata, many streams at once; serve a status page, files, ws echo,
  raw echo.
- **What it can do as a client it can test against itself as a server,
  and the reverse.**  Every client capability has its server
  counterpart in the same program, so each feature is checked end to end
  by the program against itself, and then against C's.  It is also
  autobahn's two ends.
- **What it does is said by policy.**  A policy fragment given on the
  command line, or the name of a streamtype or service in a policy it
  was given, says what to do, rather than options mirroring the policy's
  keys one by one.  On the command line, a fragment is one more layer of
  ss-policy.md, merged by namespace like the others, and binds
  parameters only.  *(How, open.)*
- **Services are crates any application can use**, whether in npro's
  tree or not.  lwsws with plugins was the better model on the server
  side, but its plugins only worked for protocols in lws' own tree, and
  could not be used as the base of an application outside lws.  A
  service in npro (files, a proxy, ws echo, later webrtc) is a crate
  implementing SS2's service trait, used the same way by the utility, by
  an application, or by a separate process fronted over a unix socket.

Between them, the utility and the service crates cover what C's minimal
examples and lwsws' plugins were for: showing how a thing is done, being
the program a test runs against, and being something to build on.

So the order is: SS, then the utility, then autobahn and the runs
against C over them.  The threads adapter (phase 1g) is built under SS,
since SS is what it is for.

## What SS is, from C

A **stream** is the user's object.  It carries payload and metadata, and
says nothing of addresses, tls or protocol: those are the streamtype's,
from the policy.  A client stream outlives its connections: it may
connect, lose the connection and retry by its backoff, and is told
"all retries failed" only when its retry policy stops concealing
failures.  A server streamtype is a listener; each connection, or h2
stream, that arrives is an accepted stream with the connection's
lifetime, and no retry.

What C does that npro keeps:

- the user API is payload in, payload out, and state as information;
- metadata, by name, is how anything else crosses: the endpoint, headers,
  the path and method on a server;
- `request_tx` asks for a chance to write, and the write is a pull into a
  buffer the library owns (C's `tx(buf, *len)`); `request_tx_len` says
  how long the whole of it is, so http can send a Content-Length;
- an http transaction's success is `QOS_ACK_REMOTE` (2xx) or `NACK`;
- a server sees `SERVER_TXN` once the request's head is in, to set its
  response's metadata, and `SERVER_UPGRADE` when the request became ws;
- the `__default` streamtype, made from a URL with no policy.

What changes, and why:

- **Events, not callbacks.**  As the driver: the user loops on
  `poll_event()`, and an `App` trait over it is for whoever prefers
  callbacks (Andy, 2026-10-09).  C's return codes from a callback
  (`DISCONNECT_ME`, `DESTROY_ME`, `SS_HANDLE_DESTROYED`) become calls the
  user makes after the event, and the trouble C had with a callback
  destroying its own stream cannot arise.
- **Streams are ids**, not pointers (port plan, "cross-owner references
  are ids").  An id whose stream has gone is refused, not a dangling
  pointer; ids carry a generation so a reused slot is not mistaken for the
  old stream.
- **C's states are split in two.**  `lws_ss_constate_t` mixes where the
  stream is (connecting, connected) with things that happened to it (an
  ack, a timeout).  npro has a `Stream` state enum, private, and events
  that report changes of it and the rest.
- **Metadata is copied**, never held by pointer, so a stream can cross a
  process boundary (ss-policy.md); C's `lws_ss_alloc_set_metadata()` is
  the only form.
- **The API is values both ways**: the user's calls and SS2's events are
  enums, so the same API can be fulfilled in the process or serialised
  to a proxy (SSPC, below) without the user's code changing.

## Where it sits

```
  user code:  the utility, an application, a service
     |  events, calls on stream ids
  npro-ss     streams, streamtypes, retry, metadata    sansIO, no_std
     |  one Driver per connection; requests for IO
  npro-io     Driver, Conn, tls                         sansIO, no_std
     |
  adapter     sockets, dns, timers, the loop           std / mio / tokio / embassy
```

**`npro-ss` is sansIO**, as the protocol crates are.  It holds the
streams and their connections' drivers, and asks for what it cannot do:

| npro-ss asks | the adapter does, and answers |
|---|---|
| `Resolve { conn, host }` | dns; `resolved(conn, addrs)` or `unresolved(conn)` |
| `Connect { conn, addr }` | a non-blocking connect; `connected(conn)` or `connect_failed(conn)` |
| `Listen { listener, addr }` | bind and listen; `accepted(listener, peer)` as each comes |
| the connection's `Want` | as io-model.md; `read_done`, `write_done`, `hangup` |
| `until` | the earliest deadline of everything it holds |

This keeps "anything that could block is a request" (io-model.md) for
the parts the driver never had: dns, connect and listen.  It also means
SS is tested as the driver is, over the in-memory transport, with no
sockets: a stream's whole life, with retries and redirects, in
`cargo test`.

So npro-ss is a loop of many connections, where a driver is one.  That
suits a readiness loop (mio, embassy, your own) directly.  The threads
adapter can host it, with npro-ss behind one `Mutex` and a thread per
connection doing the socket calls; tokio, with npro-ss in one task.
The threads adapter is first (Andy, 2026-10-12): it is std alone, and
the utility needs little scale.  `mio` comes when a server needs
it, with its dependencies' admission.

## The API, a sketch

```rust
let mut ss = Ss::new(policy, Storage { streams: .., conns: .. }, random);

let id = ss.create(&streamtype, user)?;   // CREATING; no connection yet
ss.set_metadata(id, "endpoint", b"https://warmcat.com/")?;
ss.request_tx(id)?;                       // connects, if it needs to

loop {
    // the adapter's part: act on ss.want(now), feed back what happened
    while let Some(ev) = ss.poll_event(now) {
        let user: &mut U = ev.user;        // this stream's own state
        match ev.kind {
            Event::Rx { payload, som, eom } => user.got(payload),
            Event::Tx { buf } => { let n = fill(buf); ev.wrote(n, Eom::Yes) }
            Event::State(State::Connected) => ..,
            Event::QosAck | Event::QosNack(status) => ..,
            Event::Disconnected => ..,
            Event::AllRetriesFailed => ..,
            Event::ServerTxn => { ev.set_metadata("mime", b"text/html"); .. }
            Event::ServerUpgrade => ..,
            Event::Timeout => ..,
        }
    }
}
```

- **The methods are `Call`s.**  `ss.set_metadata(id, ..)` and the rest
  are each a short form of `ss.call(id, Call::SetMetadata { .. })`, the
  value SSPC serialises (below); the front they are made on is npro-ss
  in the process, or an SSPC client.
- **`Event::Tx` hands the user a buffer** the core owns, to fill, and
  `Rx` one to read (Andy, 2026-10-09).  `Tx` is the pull through the
  driver into the frame or chunk npro has reserved, with no copy.
- **The user's per-stream state** is a value `U` the stream holds, given
  at `create`, and every event comes with `&mut U` beside it, as the
  driver's `Delivery` comes with `&mut Conn`.  This is C's user object
  (`userobj` in each callback, `lws_ss_from_user()` back to the handle),
  typed instead of `void *`: reaching it costs nothing, there is no map
  from id to state for the user to keep, and the compiler checks its
  type.  The event borrows the stream table, so the user cannot destroy
  the stream while holding its `U`; destroying is a call made after the
  event.  One `U` per `Ss`: a program with several kinds of stream makes
  `U` an enum of them, which a `match` on the streamtype picks.
- **Storage** is the caller's and bounded, as everywhere in npro: the
  number of streams, connections and listeners, metadata bytes per
  stream.  Each limit, when hit, is an error the user sees, never a
  quiet refusal (agent-context, "silent limits").  `alloc` is an
  additive feature that makes them growable up to a configured maximum.
- **Time** is `now` on every call; **random** (for the backoff's jitter
  and the ws key) is the `Random` the user gives.

### The stream's states

One enum, private, each variant carrying what exists only then:

- client: `Idle`, `Resolving`, `Connecting { attempt }`,
  `Joining { conn }`, `Connected { conn }`, `Backoff { until, attempt }`, `Failed` (all
  retries), and `Restarting { conn }` for a redirect, which C found to
  need its own transport phase (agent-context);
- accepted: `Connected { conn }`, then gone with the connection.

**`Connected` means the stream can communicate now, as the peer has
agreed** (Andy, 2026-10-12).  It is not given when a connection is
merely to hand: a stream whose request goes on a kept-warm connection
is `Joining { conn }` until the peer answers (the response's head on
h1, the 101 on ws), since the peer may already have closed that
connection without our having heard, and the stream is then doomed.
This differs from C, whose SS is told `CONNECTED` at the join, with
status 0.  The answer's outcome is still `QosAck` or `QosNack`.

A warm connection found dead before the peer answered (closed, or reset,
with no byte of a response) is the connection's failure, not the
stream's (Andy, 2026-10-12).  The stream backs up: it takes no other
warm connection, a new one is made, and the stream is put on it as for
the first time, without this counting against its retry policy.

This resends nothing the stream would not resend anyway: any retry of a
stream puts its request on a new connection, and its payload is pulled
from the user again there, as C's SS calls tx again after a reconnect.
Whether a request may be acted on twice is the same question for every
retry, not one this case adds.  The window is also kept small: a warm
connection keeps reading while it is idle, so a FIN or reset that has
already arrived ends it before any stream can join it, and only one
still in flight is found by a joiner.

`Destroying` is not a state: `destroy(id)` ends the stream at once,
closing its connection by the role's own close, and the id is refused
from then on.

### What the policy gives a stream, first

Of ss-policy.md, the first form needs only the streamtype, as Rust
types: endpoint and port, protocol (`h1`, `ws`, `raw`), tls and its
trust, retry, `allow_redirects`, `timeout_ms`, metadata names and their
header mappings, `http_method`, `http_url`, `ws_subprotocol`, `ws_binary`,
and for a server, listeners with their bind address and certs.  The
layers, the distribution link and the authority come after; nothing in
the first form stops them.

JSON is how the utility takes a policy, so `npro-json` comes with
them: in-tree, no serde, restartable, bounded depth, refusing a member
named twice (ss-policy.md).  A program that builds its policy in Rust
does not link it.

## What the layers below lack

SS asks for these, and each is its own commit in its own crate, ahead of
the SS commit that needs it:

- **h1 client**: a request body, by Content-Length and chunked (C's
  client sends one with neither, chunked: port plan 1a); redirects, as a
  restart of the same connection; keep-alive, with the kept-warm
  `IDLING` and its deadline, so a second request to the endpoint reuses
  the connection.
- **h1 server**: the response's headers from metadata, and a request's
  metadata (path, method, `Authorization`, url arguments) cleared per
  transaction, as C's are.
- **ws**: the application's own close with a code; a configured frame
  and message maximum.  Both are "not yet" in phase 1e.
- **raw**: a role, which `Conn` does not have yet.
- **npro-io**: the connect, tls handshake and `SHUTDOWN_FLUSH`
  deadlines, which io-model.md left to the driver.
- **dns**: the adapter's for now, by the platform's resolver (with std,
  `ToSocketAddrs`, which blocks, so off the loop's thread).  Porting C's
  async dns, with its dnssec validation, is its own phase, later.

## Phases

1. **`npro-ss`, client**, over the in-memory transport: create, connect
   by request, rx and tx, metadata to h1 headers, QoS from the status,
   retry and backoff with C's table and conceal count, redirects, ws.
   Tests: every C h1 client and ws client transcript replays through a
   stream as it does through the driver; retry and backoff against C's
   `lws_retry_get_delay_ms()` over a table of cases; a stream's life
   across a lost connection, a refused connect and a redirect, each by
   the in-memory transport.
2. **`npro-ss`, server**: listeners, accepted streams, `SERVER_TXN`,
   metadata from the request and into the response, `SERVER_UPGRADE` to
   ws.  Tests: C's server transcripts replay through an accepted stream.
3. **The first adapter** with real sockets and the platform's dns, and
   `npro-json` for policies.
4. **The utility**, with its `--help` and README, and the first
   services, doing over sockets what the tests did in memory: npro against itself, then against C's
   `minimal-examples/client/*` and `server/*`, then the same over tls.
5. **autobahn** both ways against it, as phase 1g planned it.

### Where the utility lives, and what applications may know

**An SS2 application is the same code whatever is underneath it**
(Andy, 2026-10-12).  It is written against SS2's calls and events and
nothing else: it does not know which loop drives it, whether its streams
are fulfilled in the process or by a proxy, or whether tls is there and
whose it is.  Trust, certs and the protocol are the streamtype's, from
the policy; the loop and the tls provider are bound where the program is
linked, never in it.  An application that has to name any of them is a
sign that SS2's API is missing something, to be fixed in SS2.

So the utility is a workspace of its own *(name open)*, beside
`npro-aws-lc/` and `fuzz/`:

- what it does is applications and services, each a type implementing
  SS2's application or service trait, none knowing the utility;
- its `main()` hands what the command line chose to a runner;
- the runner is the only code that names a loop and a provider: the
  threads adapter and aws-lc, to begin with, through `npro-aws-lc`.
  Another runner (tokio, mio) is an additive feature of the workspace,
  chosen when the program starts, and the applications do not change;
- its tests run each application over the in-memory transport, as
  `npro-test` runs the roles, and over sockets against C.

A workspace of its own, rather than a crate under `crates/`, because the
runner links aws-lc, and npro's own graph may hold no provider's C
(io-model.md): `cargo deny` checks every optional dependency too, so even
an opt-in feature naming aws-lc would put it in npro's graph.  The
services and applications do not depend on that, and are crates in
npro's own workspace, usable by anyone; only the utility, which links
them to a runner, is outside it.

## SSPC: the working plan

Not to be built yet (Andy, 2026-10-12), but the API is shaped now so
that it can be.

### What it is for

A remote, dumb microcontroller, with no network of its own, connected to
a smarter box by UART, bluetooth or similar, uses the smart box's
network, tls and policy through the SS API, so it can still do what
needs the internet, a firmware update among them, without a tcp/ip
stack.  In C that is `LWS_ONLY_SSPC`: under 25KB of text on armv7, no
tls, no IP, no lws event loop.

The other ways to do it are worse for that device:

- **IP over the serial link** (SLIP or PPP, and smoltcp on the device):
  the device then needs tls, a trust store and the protocols, which is
  what it cannot afford, and its credentials and policy live on it.
- **Bytes forwarded by the smart box** (SOCKS-like, the cut below SS
  rather than at it): the same, the device runs tls and h1 itself.

The cost SSPC most avoids is tls on the device: the record buffers
alone are about 40KB per connection (a 16KB record each way, and its
overheads), and each stream would be a connection.  SSPC's cut, the SS
API itself, leaves the device nothing but payload and metadata, and
keeps the trust, the policy, the protocols and their buffers on the box
that can hold them.  So the cut is kept, and what is improved is the
link.

### The shape

```
  device                                  smart box
  user code                               npro-ss, policy, tls, h1, ws ...
     | Call / Event                          ^ Call / Event, per client stream
  npro-sspc client role  == link ==>      npro-sspc proxy role (an npro-ss app)
     | rx / tx pull                          | rx / tx pull
  device's UART / BT                      its UART / BT / UDS / tcp
```

- **The user's API is two enums**, `Call` (create a streamtype, set
  metadata, request tx with an optional length, payload, connect,
  destroy, timeout, tx credit) and `Event` (created or refused, state,
  rx payload, metadata, tx credit).  They are near one for one C's
  `LWSSS_SER_TXPRE_*` and `LWSSS_SER_RXPRE_*`.  User code takes events
  and makes calls on a front that is either `npro-ss` in the process, or
  `npro-sspc`'s client.  The code is the same either way, where C swaps
  `lws_ss_*` for `lws_sspc_*` with `LWS_SS_USE_SSPC` in the preprocessor.
- **`npro-sspc` is sansIO**, a role like h1 or ws: `rx(now, &[u8])`, the
  `tx` pull, deadlines.  On the device it needs `npro-core` and nothing
  else: no tls, no h1, no `alloc`, its streams in caller storage.  The
  device's adapter drives it directly, or through the driver.
- **The proxy is an npro-ss application**: each link is an accepted
  connection whose role turns the client's calls into calls on the local
  npro-ss, for that client's streams, and their events back into frames.

### What the link does better than C's

- **Credit both ways, always.**  Locally, a tx is pulled at the
  connection's pace.  Across the link the payload has to wait in the
  proxy until the onward connection takes it, so each stream has a
  bounded window each way, and payload crosses only within it.  That is
  C's `TXCR_UPDATE` and its `proxy_buflen` rx flow thresholds, made the
  only way, so a firmware image fetched faster than the UART drains
  is held back by the onward TCP window, not buffered in the proxy.
- **Channels in the link**, one link for every stream, over any
  transport: a channel id in each frame.  C has a UDS connection per
  stream, and `lws_transport_mux`'s 250 channels added for UART; npro
  has one form.
- **Integrity on links that need it.**  C's mux over UART has link
  detection by PING but no check of the bytes: a corrupted frame is a
  lost coherence and a reset.  Over UART and bluetooth, frames resync on
  a marker and are checked (by the link's encryption, below, or a CRC
  without it); lost or bad frames are resent by the sequencing C already
  has for the DHT (`lws_transport_sequencer`: offsets, SACK, retransmit
  with backoff), so a long download survives a noisy line rather than
  starting again.  Over UDS or tcp the transport is already reliable,
  and the layer is not there.
- **Link loss is a stream state** on the device, `LinkDown { since }`,
  with backoff to the proxy by the same retry policy as any connection;
  its streams are made again on the new link.  C's
  `UPSTREAM_LINK_RETRY`.
- **Who may use what.**  C's proxy lets anything that can reach its
  socket use every streamtype.  npro's proxy knows the link's identity
  (the peer's credentials on UDS, a client cert on tcp, the port it is
  wired to on UART), and its policy says which streamtypes each identity
  may create.

### Securing the link, cheaply

The link itself should be encrypted and authenticated (bluetooth can be
overheard, and a UART can be tapped), at a cost the device can carry:
records the size of a link frame, a few hundred bytes, not 16KB; no
x.509; one algorithm each for key agreement, signatures, the cipher and
the hash, with no negotiation.  Since the link has its own security,
there is no wire compatibility with C's SSPC to keep (Andy,
2026-10-12).

**Trust is by a vendor's key, not only by the peer's** (Andy,
2026-10-12).  A vendor signs each of its devices' keys with a key of
its own, and a hub that trusts the vendor's key accepts any of that
vendor's devices, so an accessory works with any of the vendor's hubs.
The same holds the other way, a device trusting a hub because a vendor
key it carries signed the hub's.  Trusting a single peer's key as it is
configured is also supported, but secondary.  So each end has:

- its own key pair, and a **credential**: its public key, an id (the
  vendor's and the device's), and the signature over them of the key
  that vouches for it.  A small fixed binary layout, not x.509;
- a set of **trusted keys**: vendor keys, which vouch for others, and
  optionally individual peers' keys, trusted as they are.

A chain is bounded: a credential is signed by a trusted key directly,
or through at most one intermediate, a vendor's per-product key, whose
credential is sent with it.  Validity periods are carried, but a device
with no clock cannot check them, so expiry and revocation are the hub's
side, where there is time and a policy: the hub's policy can refuse a
device id, or a whole intermediate.

Candidates, to be decided when SSPC is built:

- **Noise** (the framework WireGuard uses), the `XX` pattern, in which
  neither end knows the other's key beforehand: each sends its static
  key encrypted in the handshake, with its credential as the
  handshake's payload, and each checks the other's against its trusted
  keys.  `IK` or `KK` when a peer's key is configured directly.  One
  fixed suite: X25519, ChaCha20-Poly1305, BLAKE2s, and Ed25519 for the
  credentials' signatures.  Three handshake messages, 16 bytes of tag
  per frame, no buffers beyond the frame.  As in WireGuard, each frame
  carries its counter, so a lost or bad frame is dropped and resent by
  the sequencing above without breaking the cipher's state, and a
  replay window refuses old ones.  The credential format is then npro's
  own, which is small but is a format to define and fuzz.  The
  primitives would come from the RustCrypto crates (`x25519-dalek`,
  `ed25519-dalek`, `chacha20poly1305`, `blake2`), `no_std`, without
  `alloc`, pure Rust: admitting them is the dependency decision this
  needs.
- **EDHOC** (RFC 9528), the IETF's key exchange for constrained devices,
  whose credentials can be CWTs or compact certificates (C509) signed by
  a trusted key, which is this trust model as a standard.  EDHOC does
  not need CoAP (OSCORE, which is often used after it, does), so after
  the handshake its keys can drive the same per-frame AEAD as above.
  It brings CBOR and COSE encodings, which are more to parse.
- **DTLS 1.3** (RFC 9147) with x.509 for the vendor chain: the standard
  answer, but x.509 and DTLS's handshake fragmentation, cookies and
  suite negotiation are what this link is meant to avoid, and there is
  little of it in Rust without `alloc`.  picotls is TLS 1.3, as far as
  found, not DTLS, and is C, so it could only be a binding outside
  npro's graph, as aws-lc is.

All three are feasible (Andy, 2026-10-12), but CBOR and COSE are a lot
of code, as C's lecp and cose showed, and EDHOC and C509 bring both.
So the leaning is Noise `XX` with npro's own small credential: the least
code for exactly this trust model.

### What this asks of what is built now

- The SS2 API is `Call` and `Event` values from the start, not methods
  acting on the core directly (above).
- **The driver is generic over its role**, so a link role can use its
  buffer, close and deadline rules without bringing in h1 and ws:
  `npro_io::conn::Conn` stays as the default role set.  *(Proposal; it
  is a change to npro-io when SSPC is built, not before.)*

### Open, for when it is built

- **The link's security**: Noise `XX` or EDHOC, above, the credential's
  format, and the primitives' admission.
- **The front and its instances** (ss-policy.md, "Proxying between
  participants"): whether that link is SSPC carrying accepted streams,
  so an instance needs no h1, ws or tls, or stays h1 and ws over UDS,
  which ordinary tools can talk to.

## Decided

- 2026-10-12: SS2 is npro's Secure Streams as a whole, and comes before
  the examples.  It is sansIO, asking the adapter for dns, connect and
  listen.
- 2026-10-12: the threads adapter carries it first.
- 2026-10-12: an SS2 application is the same code whatever loop, tls or
  proxy is underneath; the examples are a workspace of their own whose
  runner alone binds those.
- 2026-10-12: SSPC is planned for, not built: the API is shaped for it
  now.  Its link is secured cheaply, trusting vendor keys that sign
  device keys, and it keeps no wire compatibility with C's.
- 2026-10-12: `Connected` means the peer has agreed: a stream joining a
  kept-warm connection is told so when the peer answers, not at the join.

## Open

For Andy:

1. **The utility**: its name, its subcommands and options, and how a
   policy fragment or a named streamtype is given on its command line.
   To be designed once npro-ss is far enough along to see it.
2. SSPC's two questions above, when it is built.
