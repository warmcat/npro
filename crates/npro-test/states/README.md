# C's connection state machines, as oracles

npro's connection state machines (`npro_core::state`) are C lws'
(`lib/sansio/wsi-state.c`, specified in C's
`READMEs/README.wsi-state-machines.md`).  These files, copied from the C
tree at the commit in `C-COMMIT`, are what `tests/states.rs` holds them to.

| file | what it is |
|---|---|
| `wsi-event-edges.txt` | C's event table, `lws_wsi_event_edges[]`, each line prefixed by its line in `wsi-state.c`, by which C's trace names a row |
| `edges.txt` | every distinct state edge C's ctest suite took, from builds with `LWS_WITH_STATE_TRACE`, sorted, with each connection's tag removed |
| `rows-fired.txt` | every row of the table the suite fired: C's `LRSROW` lines |
| `README.lws.md` | C's `README.wsi-state-machines.md`, whose "Rows no test fires" says which rows the suite never fires, and why |
| `C-COMMIT` | the C commit all of them came from |

The suite runs in the three builds C's README measures coverage over: the
default, one adding the options some rows need (socks5, mqtt, the http
and raw proxies, the async queue, fault injection, email), and one with
tls accepts on a worker.  Each has `LWS_WITH_STATE_CHECK` too, which
aborts on any edge the table does not allow, and every test passed: the
observed edges are all the table's.

The tests:

- drive every state npro's machines can reach from a connection's birth
  with every event, both through npro and through a model of C's machines
  written in C's terms that reads its rows from `wsi-event-edges.txt`, and
  require them to agree: on refusing it, on the machines after, on the
  setter, and on the trace line;
- require every edge in `edges.txt` between npro's roles to be one npro
  takes;
- require every row npro's machines can fire to be one C's suite fires,
  or one C's README lists as never fired, with why.

`edges.txt` and `rows-fired.txt` hold every role's, not only npro's, so
that the roles arriving later are checked against the same runs.  A few
edges depend on timing, such as a stream closing while a file is still
being served, so two runs can differ by an edge or two.  A refresh that
only adds edges like that needs no more than saying so.

## Refreshing

```sh
scripts/sync-c-states.sh ~/libwebsockets
```

builds C three times with the trace and the check, runs its ctest suite in
each, and replaces these files.  Say in the commit what moved, and why npro
follows it.
