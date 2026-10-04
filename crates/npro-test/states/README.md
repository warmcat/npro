# C's connection state machines, as oracles

npro's connection state machines (`npro_core::state`) are C lws'
(`lib/sansio/wsi-state.c`, specified in C's
`READMEs/README.wsi-state-machines.md`).  These files, copied from the C
tree at the commit in `C-COMMIT`, are what `tests/states.rs` holds them to.

| file | what it is |
|---|---|
| `wsi-event-edges.txt` | the rows of C's event table, `lws_wsi_event_edges[]`, verbatim |
| `edges.txt` | every distinct state edge C's ctest suite took, from a build with `LWS_WITH_STATE_TRACE`, sorted, with each connection's tag removed |
| `C-COMMIT` | the C commit both came from |

The test drives every state npro's machines can reach from a connection's
birth with every event, both through npro and through a model of C's
machines written in C's terms that reads its rows from
`wsi-event-edges.txt`, and requires them to agree: on refusing it, on the
machines after, on the setter, and on the trace line.  Then every edge in
`edges.txt` between npro's roles must be one npro takes.

The C suite ran with `LWS_WITH_STATE_CHECK` too, which aborts on any edge
the table does not allow, and passed: the observed edges are all the
table's.  `edges.txt` holds every role's edges, not only npro's, so that
the roles arriving later are checked against the same run.

## Refreshing

```sh
scripts/sync-c-states.sh ~/libwebsockets
```

builds C with the trace and the check, runs its ctest suite, and replaces
these files.  Say in the commit what moved, and why npro follows it.
