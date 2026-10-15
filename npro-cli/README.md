# npro, the utility

`npro` is one program, server and client: the server for npro.rs, and
the thing a test runs against.  Its package is `npro-cli`, since
`npro` is the library's name on crates.io.  What it does is said by a
policy (docs/ss-policy.md), never by options mirroring the policy's
keys.

So far it serves.

```text
npro serve [--policy FILE] [-p FRAGMENT]...
npro --help | --version
```

`serve` serves everything the policy says until it is killed.  The
policy is read in layers, each over the last:

1. what is built in: `{"npro": {"slots": 64, "workers": 2}}`;
2. `/etc/npro/defaults.json`, if there;
3. `~/.config/npro/defaults.json`, if there;
4. `--policy FILE`, or `/etc/npro/policy.json` if none is named (which
   may be absent; a file named must be there);
5. each `-p FRAGMENT`, in order: a JSON object, or `key.path=value`
   with the value JSON if it reads as JSON (`npro.slots=8`,
   `listeners.www.bind="[::]:8080"`) and a string otherwise.

A higher layer's member replaces a lower's, except an object, whose
members are merged one by one.  Within one layer a member named twice
is refused, as npro-json refuses it.  Nothing is accepted and ignored:
a member nothing is declared for fails the load, naming its path, as
does a wrong type, a missing requirement, or a name that refers to
nothing (`vhosts.x.routes[1].to: no "login"; there is www, git`).

Once its listeners are bound the process drops every capability it
has, so it is started with `CAP_NET_BIND_SERVICE` alone (docs/ss-design.md,
"Privileges").

## The policy, as this version reads it

The first form (docs/ss-policy.md's layers, parameters and the
authority come after; nothing here stops them):

```json
{
  "listeners": {
    "https": { "bind": "[::]:443",
               "tls": { "cert": "/path/fullchain.pem", "key": "/path/key.pem" },
               "vhosts": ["example.com"] },
    "http":  { "bind": "[::]:80", "vhosts": ["example.com-http"] }
  },
  "vhosts": {
    "example.com": {
      "headers": { "strict-transport-security": "max-age=15768000" },
      "not-found": "/404.html",
      "access-log": "/var/log/npro/example.com.log",
      "routes": [
        { "path": "/",     "to": "www" },
        { "path": "/git",  "to": "git", "headers": { "x-git": "1" } },
        { "path": "/chat", "to": "www", "exact": true,
          "ws": { "protocols": ["chat"], "default": "chat", "binary": false, "deflate": true } }
      ]
    },
    "example.com-http": { "routes": [ { "path": "/", "to": "to-https" } ] }
  },
  "services": {
    "www":      { "type": "files", "root": "/var/www/example.com",
                  "default": "index.html",
                  "cache": { "max-age": 172800, "revalidate": false, "public": false },
                  "mimes": { ".tar.gz": "application/x-gtar" } },
    "git":      { "type": "proxy", "address": "unix:/var/run/gitohashi", "path": "/git" },
    "repo":     { "type": "cgi", "exec": "/usr/libexec/git-core/git-http-backend",
                  "env": { "GIT_PROJECT_ROOT": "/srv/git", "GIT_HTTP_EXPORT_ALL": "" },
                  "dir": "/tmp", "timeout": 30 },
    "to-https": { "type": "redirect", "to": "https://example.com", "append-path": true }
  },
  "npro": { "slots": 64, "workers": 2 }
}
```

- **listeners**: each binds where `bind` says (`[::]:443`,
  `127.0.0.1:8080`, `unix:/run/npro/www.sock`), with tls if `tls`
  names a certificate chain and key (PEM, looked at again every 10s and
  reloaded when they change), and serves the named `vhosts`, at least
  one: a request goes to the one its `Host` names, or the first.
- **vhosts**: each has `routes`, C's mounts, the longest `path` that
  leads the request's winning (`exact` for one that must match whole),
  each sent `to` a service by name, with its own `headers` and, if `ws`
  is given, ws taken on it with those `protocols`; `headers` on every
  response; `not-found`, a document a request nothing serves is
  redirected to (C's `error-document-404`); and `access-log`, a file
  a line is appended to for each request, in C's (Apache's) form, as
  its transaction ends: the peer's address (`-` on a unix domain
  socket), the time in UTC, the request line, the status, the bytes
  the answer took, the referrer and the user agent.  The file is
  opened before the listeners are bound, made if it is not there.
  A request upgraded to ws is not yet logged.
- **services**, by name, each of a `type` built into this program:
  - `files`: the directory `root` served, `default` (`index.html`) for
    a directory, `cache` as C's `cache-*` (`no-cache`, or `max-age`
    with `revalidate` and `public`; nothing for `no-store`), and
    `mimes`, the mount's own types by suffix before the built-in table;
  - `proxy`: requests passed to the origin at `address` (`unix:/path`
    or a host and port) under its `path`, with `host` the `Host` sent
    when the request had none;
  - `redirect`: 301 to `to`, the rest of the request's path appended
    if `append-path`;
  - `cgi`: each request answered by a process running `exec` (C's
    `cgi://` origin), given the request as its environment (RFC 3875's
    variables as lwsws sets them, `PATH_INFO` the path after the
    route's) and the script's own `env` (C's `cgi-env`), run in `dir`
    (`/tmp` if none, C's `cgi-chdir`), its stdin the request's body,
    its stdout the answer: `Status`, `Location` (a 302), the headers,
    then the payload, close-delimited when the script gives no length.
    It may take `timeout` seconds (30 if not given, C's `cgi-timeout`)
    to begin its answer.  Its stderr is this process' stderr.  Each read
    of its output occupies a worker thread while it waits, so `workers`
    should allow for the scripts expected at once.
- **npro**: `slots`, how many streams at once; `workers`, how many
  threads for what is done off the loop (file reads).

`policies/npro.rs.json` is npro.rs' policy in this form, from its lwsws
configuration: files, git and sai proxied over their unix domain
sockets, `/repo` served by `git-http-backend` as a cgi (its
`GIT_PROJECT_ROOT` is a guess until the box's is known), the port-80
redirect, and the mounts not yet ported proxied
to an lwsws kept listening on a unix domain socket of its own (the
path there is a placeholder until that lwsws is set up).  A test keeps
it loading.

Not in this form yet: the h1 limits and timeouts per listener (the
defaults are C's), client streamtypes, the deployment and front layers
with their instances, the login guard, and `cgi-chroot`.
