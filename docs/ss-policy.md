# Secure Streams policy

**Draft, for iteration.**  It records what was decided with Andy from
2026-10-07 to 2026-10-09, and marks what is still open.  The stream and
service API it configures is a separate document, still to be written
(`ss-design.md`); [io-model.md](io-model.md) is the layer underneath.

## What this replaces

C lws has two configuration languages that grew apart:

- **lwsws' lejp-conf** (`lib/io/lejp-conf.c`).  It composes a server:
  vhosts with listeners and tls, protocols enabled per vhost with their
  options (pvo), and mounts that place them in the vhost's URL space
  (`file://`, `cgi://`, proxy, redirect, `callback://`).
- **The Secure Streams policy** (`lib/secure-streams/policy-json.c`).  It
  describes streamtypes: endpoints, protocol, tls trust, retry, metadata.
  Its server side is much smaller: a streamtype with `"server": true` is
  one listener and one handler for every path, which is what lejp-conf
  would call a single protocol plugin.

npro has one: the SS policy, grown to do lejp-conf's job as well.  SS is
npro's user API for client and server, and its policy is the only
configuration language.

## Principles

- **The policy is Rust types.**  JSON (parsed by `npro-json`) is one way
  to build them; Rust code is another.  A `const` policy in code needs no
  code generator, so C's `policy2c` and static-policy builds have no
  equivalent: an embedded build simply has no JSON.
- **Most programs need no policy at all.**  A stream made from a URL
  derives what C's built-in `__default` streamtype gives: protocol and tls
  from the scheme, the default port, the system's trust store, redirects
  followed, headers read and written by name.  A policy carries
  deployment decisions (endpoints, trust, certs, retry, listeners,
  routes) for when someone other than the programmer should make them.
- **Parameters only.**  Configuration binds declared parameters; nothing
  else can be changed from outside.
- **Merging is by namespace, never by file order.**  There is no
  equivalent of `conf.d`'s alphabetical loading.
- **Nothing is accepted and ignored.**  An unknown key, a parameter
  bound to the wrong type or out of its bounds, or a required parameter
  left unbound, fails resolution, and the error names its path, for
  example `vhosts."warmcat.com".routes[2].to: no endpoint
  "mirror.wss"`.
- **npro is not an orchestrator.**  It defines the policy, resolves it
  and serves it to the processes that need it.  Starting, restarting and
  placing processes is systemd's job, or whatever the deployment uses.

## Parameters

A **parameter** is a declared, typed setting: its name, its type, its
default or that it is required, its bounds, and one line of
documentation.  Configuration does nothing but bind parameters.

Parameters are declared by:

- **npro itself**, under the top-level `npro` namespace.  Every
  configuration struct in the core is declared this way: h1 header
  limits, the ws rx buffer and the permessage-deflate message cap,
  keepalive and other timeouts, tls ciphers, retry defaults.  Bounds come
  from C's ranges.  Names are not settled; for illustration,
  `npro.h1.header-bytes`, `npro.ws.pmd.max-message`,
  `npro.tls.ciphers`.
- **each service**, in its structure (below): its options, and the bind
  address of each of its named listeners, which is always a parameter.

The declarations are written once in Rust, in a `macro_rules!` table
beside the configuration struct, with no serde and no proc-macros, and
`no_std` is unaffected.  Two things come from them:

- the decoder from the policy into the struct, so a declared parameter
  can never be silently ignored;
- **the reference documentation of every parameter**, generated, so it
  cannot drift from the code as lejp-conf's README has.

### Scopes

A parameter is bound at a scope: the whole process, a listener, a vhost,
a route, or an instance.  The rules:

- binding the same parameter twice in one scope is an error;
- a nested scope refines its parent for everything inside it: a route
  inside a vhost, a vhost inside a listener, an instance inside its
  deployment.

Precedence is decided by the structure, never by which file was read
last.  *(Open: agreed in discussion, not yet confirmed.)*

### Exports and references

Some facts belong to one layer and are needed by another: the front's
public host name, which a webrtc instance announces in its URLs; its
external address, which ICE needs.  The owner **exports** them by name,
and a binding elsewhere **refers** to them:

```json
"public-host": "${front.public-host}"
```

The dependency is then visible where it is used, and no layer reaches
into another's namespace.  An unknown reference fails resolution.  This
is the only substitution there is: lejp-conf's `"=NAME"` / `${NAME}`
preprocessor is not carried over.

## The layers

Taking a webrtc service as the example, which runs as its own process
and has both ws and udp listeners:

| layer | written by | changes when | says |
|---|---|---|---|
| **structure** | the service's developer; it ships with the crate | the code changes | its named listeners and what each is ("signalling": ws, "media": datagram), with **no addresses**; its parameters, with their types, defaults and bounds; the client streamtypes it uses |
| **deployment** | whoever runs it | instances or machines change | the instances (`webrtc.eu1`, `webrtc.eu2`), and for each, the bind address of each named listener and its parameter values |
| **front** | whoever runs the public face | public names or certs change | listeners, tls, vhosts, routes, guards, the exports, and `npro.*` parameters at any scope |
| **local** | whoever runs the machine | the machine changes | the process's mutual tls identity (cert and key, issued by the authority's CA), where the distribution endpoint is, and the CA that checks it |

The deployment and front layers are held by the authority (below); how
they are split into files is up to the operator, since they merge by
namespace.  The structure comes from the service: from its crate, for a
service linked into the process, or from the instance itself, for one
in another process (see "The handshake").  The local layer stays on its
machine and never travels.

The instances are the namespace: `webrtc.eu1.media.bind`,
`webrtc.eu1.max-rooms`.  A shorthand for "n instances, ports from a
base" may come later; instances are listed explicitly for now.

### An example

The structure, as `npro-webrtc` declares it (shown as JSON, which is
also how an instance sends it):

```json
{
  "component": "npro-webrtc", "version": "0.3.0",
  "listeners": {
    "signalling": { "kind": "ws", "subprotocol": "lws-webrtc" },
    "media":      { "kind": "datagram" }
  },
  "params": {
    "max-rooms":   { "type": "u32", "default": 64, "min": 1, "max": 4096 },
    "public-host": { "type": "host", "required": true }
  }
}
```

The deployment:

```json
{
  "instances": {
    "webrtc.eu1": {
      "component": "npro-webrtc",
      "bind":   { "signalling": "unix:/run/npro/webrtc-eu1.sock",
                  "media": "[::]:3478" },
      "params": { "max-rooms": 128, "public-host": "${front.public-host}" }
    }
  }
}
```

The front:

```json
{
  "exports": { "public-host": "rtc.example.com" },
  "listeners": {
    "https": { "bind": "[::]:443", "tls": { "cert": "rtc" },
               "vhosts": ["rtc.example.com"] }
  },
  "vhosts": {
    "rtc.example.com": {
      "params": { "npro.h1.keepalive": "5s" },
      "routes": [
        { "path": "/",    "to": "www.http" },
        { "path": "/rtc", "to": "webrtc.eu1.signalling" }
      ]
    }
  },
  "services": {
    "www": { "type": "files", "params": { "root": "/var/www/rtc" } }
  }
}
```

The route names `webrtc.eu1.signalling`, not an address: resolution
finds where that is from the deployment, so each address is written
once.  `media` faces the public directly; a datagram listener cannot be
proxied by the front.

## Roles

Policy is resolved and handed out where the certs already are.  C lws
has this flow today, for certs: dnssec-monitor and cert distribution
(`plugins/protocol_lws_cert_dist_server`, `-client`), running live for
selfdns.org and npro.rs, and the planned home of warmcat.com and
libwebsockets.org.

| role | where | reachable | holds |
|---|---|---|---|
| **authority** (dnssec-monitor) | the operator's trusted physical space, LAN only | nobody from outside; it reaches out to the ACME CA, the DHT and the authoritative dns servers | the zones and their dnssec keys, every policy layer but the local ones, and the certs it obtains by dns-01 |
| **distribution endpoint** (cert distribution) | beside the authority, with the PKI root; its privileged stub is the only part that reads it | inbound, only over mutual tls with a client cert from the authority's CA | nothing of its own beyond its tls identity |
| **participants** (fronts, instances) | anywhere | they connect out to the distribution endpoint | their local layer, and the last fragment and certs they accepted |

A front is an ordinary participant: it fetches its own fragment like any
instance.  The authority's web UI is where the layers are edited, and
JSON is how they are kept.

## The distribution link

Each participant keeps one mutual tls link up to the distribution
endpoint, as cert distribution's clients do now, and gets both its certs
and its policy fragment over it.

- **Identity is the client cert**, not anything the participant says.
  The authority hands a namespace only to an identity it has explicitly
  been granted to, in the deployment layer, and refuses otherwise: as
  cert distribution refuses unless the client's issued cert has been
  placed in the domain's `dist-client/` dir.
- **A fragment** is everything bound in one namespace, flattened, with
  the exports it refers to and the `npro.*` parameters that apply to it.
  It carries its namespace and a version; a participant refuses one for
  another namespace, or older than the one it has.
- **No signing.**  The link is mutual tls to the box where the policy is
  resolved, so the transport says where a fragment came from.  The
  cached copy sits under the participant's own permissions, as its local
  layer does.  Signing would be needed only if fragments were relayed
  through something not trusted, which this design does not do.
- **Private keys** of distributed certs come over the link as cert
  distribution sends them now.  A fragment never carries one.
- **Push.**  The link stays up, and the endpoint pushes what changes:
  renewed certs, which a participant applies while running by building
  new tls contexts, and a notice that the participant's namespace has
  changed, on which it exits cleanly and systemd brings it back.
- **At start** a participant takes the latest fragment from the link.  If
  the link cannot be had, it starts from the fragment it cached last; with
  none, it fails, and systemd tries again.  There is no resolving at
  deploy time, which could only produce configuration that had gone
  stale.
- **Cert distribution's payload rules hold for fragments too**: a size
  cap; a refusal answered without dropping the link; nothing installed
  under a name the server chose rather than the local one; and **a JSON
  object with a member appearing twice is refused**, which `npro-json`
  must therefore be able to detect.

### The handshake

The authority links none of the separately built services, so it cannot
know their structure by itself.  **The participant sends its structure
when it asks for its fragment**: "built from npro-webrtc 0.3.0, and these
are my listeners and parameters".  Its identity comes from its cert.  The
authority resolves against that, and answers with the fragment or with
the resolution's errors.  So:

- the authority stays generic;
- an instance whose new binary declares a new parameter gets its
  default, or a clear refusal if it is required and unbound;
- the authority knows which policy version each participant took, which,
  with the health the fronts see by proxying, gives a status view such as
  "eu1: healthy, policy v42" or "eu2: refused, `media.bind` unbound".

*(Open: agreed in discussion as the direction, not yet confirmed.)*

### Compatibility with C, and the switchover

The C flow is production, and moving warmcat.com and libwebsockets.org
onto it must not depend on npro.  So:

- npro participants speak the C cert distribution protocol as it is, and
  are tested against the C server;
- fragments are an addition to that protocol, made in C first, which a
  client that does not know them ignores;
- nothing in this design asks the C side for a change on the
  switchover's schedule.

### Proxying between participants

On one machine, a front reaches an instance over a unix domain socket
whose permissions admit only the two of them.  Across machines, over tcp
with mutual tls, using the same identities as the distribution link.

### Health

systemd keeps processes running.  The front sees whether each instance
is healthy by proxying to it: failed connects and timeouts.  It uses that
for a fast 503 on the routes of an instance that is down, for backing off
its reconnects with the instance's retry policy, and for the status page.
An optional active probe may come later.

## From the C SS policy

| C | npro |
|---|---|
| `release`, `product`, `schema-version` | the policy's header; the version a participant checks is the fragment's, set by the authority |
| `retry` | named retry schemes, as now; their limits (C: at most 8 backoff steps) become declared bounds |
| `certs` (base64 DER inline) | public certs may still be inline; private keys come only from the local layer or a file, never inline |
| `trust_stores` | kept, referenced by name |
| `s` (client streamtypes) | client streamtypes, declared in a structure by the service or program that uses them, with parameters the policy binds (endpoint, trust, retry) |
| `"server": true` streamtypes | listeners, vhosts, services and routes.  C's one-listener server is the smallest case, and a short form of it stays |
| `metadata`, `${metadata}` | stream metadata, copied, never held by pointer, so a stream's state can cross a process boundary; headers by name are the default, which C has only with `direct_proto_str` |
| `options[]` (parsed, never used in C) | service parameters |
| overlay (modifies existing streamtypes only) | the layers |
| replacing the policy (destroys every stream) | restart into the new fragment |
| `fetch_policy` | the fragment, over the distribution link |
| static policy, `policy2c` | a `const` policy in Rust |
| `auth`, `metrics` | later; not designed here |

## From lejp-conf

Where each group of lejp-conf's keys lands.  "Param" means a declared
parameter bound at the scope named.

**Globals**

| lejp-conf | npro |
|---|---|
| uid, gid, username, groupname, rlimit-nofile | not npro: systemd's `User=`, `Group=`, `LimitNOFILE=` |
| count-threads, count-async-threads | the runner's parameters |
| plugin-dir | gone: services are compiled in, or run as their own process |
| init-ssl | gone |
| server-string, timeout-secs, http-header-data | `npro.*` params, process scope |
| ip-limit-ah, ip-limit-wsi | `npro.*` limit params |
| default-alpn | listener tls |
| quic-* | `npro.quic.*` params |
| reject-service-keywords | a route guard |
| cpd-bypass | the client side's captive portal detection, a param |
| ws-pingpong-secs | gone (deprecated in C) |

**Per vhost**

| lejp-conf | npro |
|---|---|
| name | the vhost's key |
| port, interface, unix-socket, unix-socket-perms, noipv6, ipv6only, fo-listen-queue | listeners, which are separate from vhosts; a listener lists the vhosts it serves |
| host-ssl-key, -cert, -ca, -cert-grace-secs | listener tls, chosen per vhost by SNI; the private key from the local layer or a file |
| ciphers, tls13-ciphers, ecdh-curve, ssl-option-set/clear, alpn, client-cert-required, ignore-missing-cert | listener tls params |
| sts, redirect-http, allow-non-tls, allow-http-on-https, strict-host-check, sni-fallback | listener and vhost params |
| access-log, keepalive_timeout, h2-half-closed-long-poll, quic-mtu, quic-preferred-addresses | `npro.*` params, vhost scope |
| headers[] | the vhost's response headers |
| error-document-404 | the vhost's error documents |
| listen-accept-role, -protocol, apply-, fallback-listen-accept, onlyraw | a listener's kind, and its `Raw` endpoint |
| disable-no-protocol-ws-upgrades | a route rule |
| enable-client-ssl, client-ssl-* | client trust and certs, at the scope of the streams that use them |
| ws-protocols[] (pvo) | services, with their parameters |
| dht[] | a dht service |

**Per mount**

| lejp-conf | npro |
|---|---|
| mountpoint, exact-match, append-path | the route's path and how it matches; the longest matching path wins |
| origin `file://`, `gzip://` | the files service, with precompressed variants as its param |
| origin `http://`, `https://` | the proxy service: a route bridged to a client stream |
| origin `>http://`, `>https://` | a redirect route |
| origin `callback://` | a service's endpoint, by name |
| origin `cgi://`, cgi-* | open: a cgi service, or not carried over |
| default, extra-mimetypes, interpret, cache-* | the files service's params |
| auth-mask, basic-auth, interceptor-path | route guards |
| headers[], keepalive-timeout, no-ws-upgrades | route params |
| pmo[] | service params, route scope |

**Not carried over**: the `"=NAME"` / `${NAME}` preprocessor (exports
and references cover what it was used for), and `conf.d` order.

## Decided

- 2026-10-07: the SS policy is npro's one configuration language, and
  takes over lejp-conf's job.  Services in their own processes are
  fronted over unix domain sockets, or mutual tls across machines.
- 2026-10-08: parameters only; npro's own configuration is parameters
  too, under the `npro` namespace.
- 2026-10-08: participants take their fragment when they start, and
  cache the last good one; there is no resolving at deploy time.
- 2026-10-09: the authority is dnssec-monitor, in the operator's
  trusted space, LAN only.  Fragments travel over cert distribution's
  mutual tls link with the certs, unsigned; identity is the client cert.
  Fronts are participants like any other.  The C flow stays production,
  and npro is not on the path of switching warmcat.com and
  libwebsockets.org to it.
- 2026-10-08: npro does not supervise processes; systemd does.  npro
  knows their health from proxying to them.

## Open

- The scope rule (same-scope duplicates are errors; nested scopes
  refine).
- The handshake, with the instance sending its structure.
- Names for the `npro.*` parameters, and how they are grouped.
- The fragment's place in the C cert distribution protocol.
- cgi.
- The JSON shapes above, which are illustrations, not a schema.
