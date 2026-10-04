//! npro's connection state machines (`npro_core::state`) against C's.
//!
//! Two oracles, both copied from the C tree into `states/` (see its
//! README):
//!
//! - `wsi-event-edges.txt`, the rows of C's event table, verbatim.  This
//!   test has a second model of C's machines, written in C's terms (the
//!   names, the fields of the state word, and C's setters), which reads its
//!   rows from that file.  Every state npro's machines can reach from a
//!   connection's birth is driven with every event, with and without each
//!   role a site can give, and with the socket's usability changed, through
//!   both; they must agree on refusing it, on the machines after, on which
//!   setter made the change, and on the trace line.
//! - `edges.txt`, every distinct edge C's ctest suite took, from C's
//!   `LWS_WITH_STATE_TRACE`.  Each edge between npro's roles must be one
//!   npro's machines take.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses only npro-core"
)]
#![expect(
    clippy::std_instead_of_alloc,
    reason = "a test, which has std: its collections are std's"
)]

// the C model is test code throughout, held to clippy's rules for tests
#[cfg(test)]
mod states {
    use std::collections::{BTreeSet, HashSet, VecDeque};
    use std::fs;
    use std::path::Path;

    use npro_core::state::{
        Carrier, Close, Edge, Event, Live, Machines, Role, Side, Socket, Transport,
    };

    fn states_dir() -> &'static Path {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/states"))
    }

    /// The roles npro has, as C names them.
    const ROLES: [&str; 4] = ["(none)", "h1", "ws", "raw-skt"];

    // ---- C's names for the machines' phases, from private-lib-sansio.h ----

    /// `enum lws_transport_phase`, in order.
    const LTS: [&str; 13] = [
        "NONE",
        "WAITING_DNS",
        "WAITING_CONNECT",
        "WAITING_PROXY_REPLY",
        "WAITING_SSL",
        "WAITING_SOCKS_GREETING_REPLY",
        "WAITING_SOCKS_CONNECT_REPLY",
        "WAITING_SOCKS_AUTH_REPLY",
        "SSL_INIT",
        "SSL_ACK_PENDING",
        "AWAITING_SSL_ACCEPT",
        "FAILED",
        "RESTARTING",
    ];

    /// `enum lws_carrier_phase`, in order.
    const LCR: [&str; 11] = [
        "NONE",
        "H1C_ISSUE_HANDSHAKE",
        "H1C_ISSUE_HANDSHAKE2",
        "WAITING_SERVER_REPLY",
        "H2_AWAIT_PREFACE",
        "H2_AWAIT_SETTINGS",
        "H2_WAITING_TO_SEND_HEADERS",
        "H1_UPGRADE",
        "MQTTC_IDLE",
        "MQTTC_AWAIT_CONNACK",
        "ESTABLISHED",
    ];

    /// `enum lws_close_phase`, in order: the machine only goes forwards.
    const LCS: [&str; 10] = [
        "NONE",
        "CLOSE_WHEN_FLUSHED",
        "CLOSING",
        "WAITING_TO_SEND_CLOSE",
        "RETURNED_CLOSE",
        "AWAITING_CLOSE_ACK",
        "FLUSHING_BEFORE_CLOSE",
        "SHUTDOWN",
        "DEAD_SOCKET",
        "USER_TOLD",
    ];

    fn idx(names: &[&str], name: &str) -> usize {
        names
            .iter()
            .position(|n| *n == name)
            .unwrap_or_else(|| panic!("no phase {name}"))
    }

    /// The transport phase an `LRS_` name stands for (`lws_lts_of_lrs()`).
    fn lts_of(lrs: &str) -> Option<&'static str> {
        LTS[1..=10].iter().copied().find(|n| *n == lrs)
    }

    /// The carrier phase an `LRS_` name stands for (`lws_lcr_of_lrs()`).
    fn lcr_of(lrs: &str) -> Option<&'static str> {
        LCR[1..=9].iter().copied().find(|n| *n == lrs)
    }

    // ---- C's state word ----

    /// The fields of C's `wsistate`, and the role ops, by name.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Word {
        role: &'static str,
        side: char,
        transport: &'static str,
        carrier: &'static str,
        live: &'static str,
        close: &'static str,
        unusable: bool,
    }

    impl Word {
        /// `lwsi_state_of_word()`: what the connection reports.
        fn reported(&self) -> &'static str {
            if self.close != "NONE" && self.close != "CLOSING" {
                return match self.close {
                    "CLOSE_WHEN_FLUSHED" => "FLUSHING_BEFORE_CLOSE",
                    "USER_TOLD" => "DEAD_SOCKET",
                    c => c,
                };
            }
            if self.transport != "NONE" {
                return match self.transport {
                    "FAILED" | "RESTARTING" => "UNCONNECTED",
                    t => t,
                };
            }
            if self.carrier != "NONE" && self.carrier != "ESTABLISHED" {
                return self.carrier;
            }
            self.live
        }

        /// `lws_wsi_state_fmt()`.
        fn fmt(&self) -> String {
            let mut s = format!("{}/{}:{}", self.role, self.side, self.reported());
            if self.transport == "FAILED" {
                s.push_str("+failed");
            }
            if self.transport == "RESTARTING" {
                s.push_str("+restarting");
            }
            if self.close == "USER_TOLD" {
                s.push_str("+told");
            }
            if self.close == "CLOSING" {
                s.push_str("+closing");
            }
            if self.unusable {
                s.push_str("+unusable");
            }
            s
        }

        /// `lws_wsi_set_state_ev()`.
        fn set_state(&mut self, lrs: &'static str) {
            self.transport = "NONE";
            match lcr_of(lrs) {
                Some(lcr) if self.carrier != "ESTABLISHED" => self.carrier = lcr,
                _ => {
                    self.carrier = if lrs == "UNCONNECTED" {
                        "NONE"
                    } else {
                        "ESTABLISHED"
                    };
                    self.live = lrs;
                }
            }
        }

        /// `lws_wsi_role_transition_ev()`.
        fn role_transition(&mut self, role: &'static str, side: char, lrs: &'static str) {
            let old = self.clone();
            let (lts, lcr) = (lts_of(lrs), lcr_of(lrs));

            *self = Word {
                role,
                side,
                transport: "NONE",
                carrier: "NONE",
                live: "UNCONNECTED",
                close: "NONE",
                unusable: false,
            };
            if let Some(t) = lts {
                self.transport = t;
            } else if let Some(c) = lcr {
                self.carrier = c;
            } else if lrs != "UNCONNECTED" {
                self.live = lrs;
                self.carrier = "ESTABLISHED";
            }
            if lts.is_some() || lcr.is_some() || lrs != "UNCONNECTED" {
                self.unusable = old.unusable;
                self.close = old.close;
            }
        }

        /// `lws_state_invariant()`.
        fn invariant(&self) -> bool {
            let r = self.reported();
            !(self.unusable
                && matches!(
                    r,
                    "WAITING_TO_SEND_CLOSE" | "RETURNED_CLOSE" | "AWAITING_CLOSE_ACK" | "SHUTDOWN"
                )
                || self.transport == "RESTARTING" && self.side != 'C'
                || r == "RETURNED_CLOSE" && self.role != "ws"
                || r == "SHUTDOWN" && (self.side == 'C' || self.role == "raw-skt"))
        }
    }

    // ---- C's event table ----

    #[derive(Clone, Debug)]
    enum RowTo {
        Lrs(&'static str),
        Lts(&'static str),
        Lcs(&'static str),
    }

    #[derive(Clone, Debug)]
    struct Row {
        /// The row's line in C's wsi-state.c, by which C's trace names it.
        line: u32,
        role: String,
        side: String,
        from: Option<String>,
        ev: String,
        to_role: Option<String>,
        to_side: Option<String>,
        to: RowTo,
    }

    /// C's `lws_lrs_names[]`, the names of the states a connection reports.
    const LRS: [&str; 38] = [
        "UNCONNECTED",
        "WAITING_DNS",
        "WAITING_CONNECT",
        "WAITING_PROXY_REPLY",
        "WAITING_SSL",
        "WAITING_SOCKS_GREETING_REPLY",
        "WAITING_SOCKS_CONNECT_REPLY",
        "WAITING_SOCKS_AUTH_REPLY",
        "SSL_INIT",
        "SSL_ACK_PENDING",
        "H1_UPGRADE",
        "WAITING_SERVER_REPLY",
        "H2_AWAIT_PREFACE",
        "H2_AWAIT_SETTINGS",
        "TXN_COMPLETED",
        "H2_WAITING_TO_SEND_HEADERS",
        "DEFERRING_ACTION",
        "IDLING",
        "H1C_ISSUE_HANDSHAKE",
        "H1C_ISSUE_HANDSHAKE2",
        "ISSUE_HTTP_BODY",
        "ISSUING_FILE",
        "HEADERS",
        "BODY",
        "DISCARD_BODY",
        "ESTABLISHED",
        "DOING_TRANSACTION",
        "WAITING_TO_SEND_CLOSE",
        "RETURNED_CLOSE",
        "AWAITING_CLOSE_ACK",
        "FLUSHING_BEFORE_CLOSE",
        "SHUTDOWN",
        "DEAD_SOCKET",
        "MQTTC_IDLE",
        "MQTTC_AWAIT_CONNACK",
        "AWAITING_FILE_READ",
        "AWAITING_SSL_ACCEPT",
        "TXN_COMPLETING",
    ];

    /// The name in `names` that is `s`: the table names nothing else.
    fn named(names: &[&'static str], s: &str) -> &'static str {
        names
            .iter()
            .copied()
            .find(|n| *n == s)
            .unwrap_or_else(|| panic!("no name {s} here"))
    }

    /// The rows of `lws_wsi_event_edges[]`, from the copy of C's table.
    fn rows() -> Vec<Row> {
        let text = fs::read_to_string(states_dir().join("wsi-event-edges.txt")).unwrap();
        let mut rows = Vec::new();

        // each line of the table, after its line in wsi-state.c and a tab;
        // a row is R(role, side, from, event, to_role, to_side, to)
        for line in text.lines() {
            let (n, src) = line.split_once('\t').unwrap();
            let Some(row) = src.trim().strip_prefix("R(") else {
                continue;
            };
            let body = &row[..row.find("),").unwrap()];
            let f: Vec<&str> = body.split(',').map(str::trim).collect();
            assert_eq!(f.len(), 7, "row {line}");

            let unquote = |s: &str| -> Option<String> {
                (s != "NULL").then(|| s.trim_matches('"').to_owned())
            };
            let from = (f[2] != "ANY").then(|| f[2].strip_prefix("LRS_").unwrap().to_owned());
            let to = if let Some(t) = f[6].strip_prefix("XT(LTS_") {
                RowTo::Lts(named(&LTS, t.trim_end_matches(')')))
            } else if let Some(c) = f[6].strip_prefix("XC(LCS_") {
                RowTo::Lcs(named(&LCS, c.trim_end_matches(')')))
            } else {
                RowTo::Lrs(named(&LRS, f[6].strip_prefix("LRS_").unwrap()))
            };

            rows.push(Row {
                line: n.parse().unwrap(),
                role: f[0].trim_matches('"').to_owned(),
                side: f[1].trim_matches('"').to_owned(),
                from,
                ev: f[3].strip_prefix("LWS_WSIEV_").unwrap().to_owned(),
                to_role: unquote(f[4]),
                to_side: unquote(f[5]),
                to,
            });
        }
        assert!(rows.len() > 150, "only {} rows read", rows.len());
        rows
    }

    /// What C does with an event.
    #[derive(Debug, PartialEq, Eq)]
    enum COutcome {
        /// It changes the word, by this setter.
        Edge(Word, &'static str),
        /// It refuses: no row, a close going back, or a broken invariant (which
        /// `LWS_WITH_STATE_CHECK` aborts on).
        Refused,
    }

    /// The row of C's table an event matches: the first, as in C.
    fn c_row<'a>(
        rows: &'a [Row],
        w: &Word,
        ev: &str,
        ops: Option<&'static str>,
    ) -> Option<&'a Row> {
        let from = w.reported();
        let w_side = w.side.to_string();

        rows.iter().find(|r| {
            r.ev == ev
                && r.from.as_deref().is_none_or(|f| f == from)
                && (r.role == "*" || r.role == w.role)
                && (r.side == "*" || r.side == w_side)
                && match (r.to_role.as_deref(), ops) {
                    (Some("?"), o) => o.is_some(),
                    (_, None) => true,
                    (Some(t), Some(o)) => t != "P" && t == o,
                    (None, Some(_)) => false,
                }
        })
    }

    /// `lws_wsi_event_x()`, with `LWS_WITH_STATE_CHECK`'s check of the result.
    fn c_event(rows: &[Row], w: &Word, ev: &str, ops: Option<&'static str>) -> COutcome {
        let Some(r) = c_row(rows, w, ev, ops) else {
            return COutcome::Refused;
        };

        let mut to = w.clone();
        let how = match (&r.to, r.to_role.as_deref(), r.to_side.as_deref()) {
            (RowTo::Lts(t), _, _) => {
                to.transport = t;
                "set_transport"
            }
            (RowTo::Lcs(c), _, _) => {
                if idx(&LCS, c) < idx(&LCS, w.close) {
                    return COutcome::Refused;
                }
                to.close = c;
                "set_close"
            }
            (RowTo::Lrs(lrs), None, None) => {
                // set_state asserts a retargeted wsi has no live state
                if w.transport == "RESTARTING" {
                    return COutcome::Refused;
                }
                to.set_state(lrs);
                "set_state"
            }
            (RowTo::Lrs(lrs), role, side) => {
                let role = match role {
                    None => w.role,
                    Some("?") => ops.unwrap(),
                    // a row to a role npro lacks fails here
                    Some(to_role) => named(&ROLES, to_role),
                };
                let side = match side {
                    None => w.side,
                    Some(s) => {
                        assert!(matches!(s, "C" | "S"), "row to side {s}");
                        s.chars().next().unwrap()
                    }
                };
                to.role_transition(role, side, lrs);
                "role_transition"
            }
        };

        let attr_only = w.reported() == to.reported() && w.side == to.side && w.role == to.role;
        if !attr_only && !to.invariant() {
            return COutcome::Refused;
        }
        COutcome::Edge(to, how)
    }

    /// Whether C's trace records an edge (`lws_wsi_state_changed()`).
    fn c_traced(from: &Word, to: &Word) -> bool {
        let attr_only =
            from.reported() == to.reported() && from.side == to.side && from.role == to.role;
        !attr_only
            || from.unusable != to.unusable
            || from.close != to.close
            || from.transport != to.transport
    }

    // ---- npro's machines, in C's names ----

    fn word(m: Machines) -> Word {
        Word {
            role: m.role().name(),
            side: m.side().letter(),
            transport: match m.transport() {
                Transport::None => "NONE",
                Transport::WaitingDns => "WAITING_DNS",
                Transport::WaitingConnect => "WAITING_CONNECT",
                Transport::WaitingProxyReply => "WAITING_PROXY_REPLY",
                Transport::WaitingSsl => "WAITING_SSL",
                Transport::WaitingSocksGreetingReply => "WAITING_SOCKS_GREETING_REPLY",
                Transport::WaitingSocksConnectReply => "WAITING_SOCKS_CONNECT_REPLY",
                Transport::WaitingSocksAuthReply => "WAITING_SOCKS_AUTH_REPLY",
                Transport::SslInit => "SSL_INIT",
                Transport::SslAckPending => "SSL_ACK_PENDING",
                Transport::AwaitingSslAccept => "AWAITING_SSL_ACCEPT",
                Transport::Failed => "FAILED",
                Transport::Restarting => "RESTARTING",
            },
            carrier: match m.carrier() {
                Carrier::None => "NONE",
                Carrier::H1cIssueHandshake => "H1C_ISSUE_HANDSHAKE",
                Carrier::H1cIssueHandshake2 => "H1C_ISSUE_HANDSHAKE2",
                Carrier::WaitingServerReply => "WAITING_SERVER_REPLY",
                Carrier::H2WaitingToSendHeaders => "H2_WAITING_TO_SEND_HEADERS",
                Carrier::H1Upgrade => "H1_UPGRADE",
                Carrier::Established => "ESTABLISHED",
            },
            live: match m.live() {
                Live::Unconnected => "UNCONNECTED",
                Live::H1cIssueHandshake => "H1C_ISSUE_HANDSHAKE",
                Live::H1cIssueHandshake2 => "H1C_ISSUE_HANDSHAKE2",
                Live::WaitingServerReply => "WAITING_SERVER_REPLY",
                Live::H2WaitingToSendHeaders => "H2_WAITING_TO_SEND_HEADERS",
                Live::H1Upgrade => "H1_UPGRADE",
                Live::IssueHttpBody => "ISSUE_HTTP_BODY",
                Live::Headers => "HEADERS",
                Live::Established => "ESTABLISHED",
                Live::DoingTransaction => "DOING_TRANSACTION",
                Live::Body => "BODY",
                Live::DiscardBody => "DISCARD_BODY",
                Live::IssuingFile => "ISSUING_FILE",
                Live::AwaitingFileRead => "AWAITING_FILE_READ",
                Live::TxnCompleting => "TXN_COMPLETING",
                Live::TxnCompleted => "TXN_COMPLETED",
                Live::Idling => "IDLING",
            },
            close: LCS[match m.close() {
                Close::None => 0,
                Close::CloseWhenFlushed => 1,
                Close::Closing => 2,
                Close::WaitingToSendClose => 3,
                Close::ReturnedClose => 4,
                Close::AwaitingCloseAck => 5,
                Close::FlushingBeforeClose => 6,
                Close::Shutdown => 7,
                Close::DeadSocket => 8,
                Close::UserTold => 9,
            }],
            unusable: m.socket() == Socket::Unusable,
        }
    }

    /// The roles a site can give with an event: none, or one of npro's.
    fn sites() -> [Option<Role>; 4] {
        [None, Some(Role::H1), Some(Role::Ws), Some(Role::RawSkt)]
    }

    /// Every state npro's machines reach from a birth, and the trace line of
    /// every edge between them that C's trace would record.
    fn reachable() -> (Vec<Machines>, BTreeSet<String>) {
        let mut seen = HashSet::new();
        let mut order = Vec::new();
        let mut lines = BTreeSet::new();
        let mut queue = VecDeque::new();

        lines.insert(Machines::birth().to_string());
        queue.push_back(Machines::new());
        seen.insert(Machines::new());

        while let Some(m) = queue.pop_front() {
            order.push(m);
            let mut edges: Vec<Edge> = Vec::new();
            for ev in Event::ALL {
                for site in sites() {
                    let mut n = m;
                    let r = match site {
                        None => n.event(ev),
                        Some(role) => n.event_as(ev, role),
                    };
                    if let Ok(e) = r {
                        edges.push(e);
                    }
                }
            }
            for s in [Socket::Usable, Socket::Unusable] {
                let mut n = m;
                let e = n.set_socket(s);
                if e.from != Some(e.to) {
                    edges.push(e);
                }
            }
            for e in edges {
                if e.traced() {
                    lines.insert(e.to_string());
                }
                if seen.insert(e.to) {
                    queue.push_back(e.to);
                }
            }
        }
        (order, lines)
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "600,000 comparisons over 3,000 states: native runs keep it"
    )]
    fn npro_takes_every_event_as_c_does() {
        let rows = rows();
        let (states, _) = reachable();
        let mut compared = 0usize;

        for m in &states {
            let w = word(*m);
            for ev in Event::ALL {
                for site in sites() {
                    let mut n = *m;
                    let ours = match site {
                        None => n.event(ev),
                        Some(role) => n.event_as(ev, role),
                    };
                    let theirs = c_event(&rows, &w, ev.name(), site.map(Role::name));
                    // C's row, by its line in wsi-state.c, if one matches
                    let row = c_row(&rows, &w, ev.name(), site.map(Role::name)).map_or_else(
                        || "no row".to_owned(),
                        |r| format!("wsi-state.c:{}", r.line),
                    );
                    let what = format!("{} ev={} site={site:?} ({row})", w.fmt(), ev.name());

                    match (ours, theirs) {
                        (Err(_), COutcome::Refused) => {}
                        (Ok(e), COutcome::Edge(to, how)) => {
                            assert_eq!(word(e.to), to, "{what}");
                            assert_eq!(e.how.name(), how, "{what}");
                            assert_eq!(e.traced(), c_traced(&w, &to), "{what}");
                            assert_eq!(
                                e.to_string(),
                                format!("LRS {} -> {} {how} ev={}", w.fmt(), to.fmt(), ev.name()),
                                "{what}"
                            );
                            assert_eq!(n, e.to, "{what}");
                        }
                        (Ok(e), COutcome::Refused) => panic!("{what}: npro takes {e}, C refuses"),
                        (Err(r), COutcome::Edge(to, _)) => {
                            panic!("{what}: npro refuses ({r}), C goes to {}", to.fmt())
                        }
                    }
                    compared += 1;
                }
            }
        }
        assert!(states.len() > 100, "only {} states reached", states.len());
        assert!(compared > 10_000, "only {compared} compared");
    }

    #[test]
    #[cfg_attr(miri, ignore = "the walk of 3,000 states: native runs keep it")]
    fn every_edge_c_takes_between_npros_roles_npro_takes() {
        let (_, ours) = reachable();
        let text = fs::read_to_string(states_dir().join("edges.txt")).unwrap();

        let ours_role = |s: &str| {
            let (role, rest) = s.split_once('/').unwrap();
            let side = rest.split(':').next().unwrap();
            ROLES.contains(&role) && matches!(side, "-" | "C" | "S")
        };

        let mut checked = 0usize;
        let mut missing = Vec::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            // a birth's "from" has no role yet
            let from_ok = f[1] == "(none)/-:(zero)" || ours_role(f[1]);
            if !from_ok || !ours_role(f[3]) {
                continue;
            }
            checked += 1;
            if !ours.contains(line) {
                missing.push(line);
            }
        }
        assert!(
            missing.is_empty(),
            "C takes edges npro does not:\n{}",
            missing.join("\n")
        );
        assert!(
            checked > 150,
            "only {checked} of C's edges are between npro's roles"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "the walk of 3,000 states: native runs keep it")]
    fn the_invariants_hold_in_every_state_npro_reaches() {
        let (states, _) = reachable();
        for m in &states {
            let w = word(*m);
            // C's lws_state_invariant() is about entering a state by an event,
            // and the comparison with C holds npro to it there: a socket can
            // still die under a close already in progress.  These hold in
            // every state: only a client restarts or has failed, only a ws
            // peer's close is answered, only a server stages a shutdown, and
            // never on a raw socket.
            if matches!(m.transport(), Transport::Restarting | Transport::Failed) {
                assert_eq!(m.side(), Side::Client, "{}", w.fmt());
            }
            if m.close() == Close::ReturnedClose {
                assert_eq!(m.role(), Role::Ws, "{}", w.fmt());
            }
            if m.close() == Close::Shutdown {
                assert_eq!(m.side(), Side::Server, "{}", w.fmt());
                assert_ne!(m.role(), Role::RawSkt, "{}", w.fmt());
            }
        }
    }

    #[test]
    fn the_c_table_copy_has_rows_for_every_event_npro_has() {
        let rows = rows();
        for ev in Event::ALL {
            assert!(
                rows.iter().any(|r| r.ev == ev.name()),
                "no C row for {}",
                ev.name()
            );
        }
    }

    #[test]
    fn every_side_and_role_named() {
        // the trace's names for what npro calls them
        assert_eq!(Side::ALL.map(Side::letter), ['-', 'C', 'S']);
        assert_eq!(Role::ALL.map(Role::name), ROLES);
    }
}
