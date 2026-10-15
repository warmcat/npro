//! The certificate distribution client, as `npro serve` runs it: a ws
//! link per certificate to the distribution server under mTLS, kept up,
//! and what the server sends installed under the pki directory.
//!
//! The protocol is npro-certdist's ([`npro_certdist`]); this is its
//! runner: the links are client streams of the front's own, their tls
//! identities the client certificates the policy names, and the install
//! is lws' (`cdc_install()`), done by this process into a directory it
//! owns rather than by a privileged stub, since npro runs unprivileged
//! and the pki directory is its own: `<pki>/<name>/` holds
//! `fullchain.pem.<time>` and `privkey.pem.<time>`, written new with the
//! key readable by this user alone, and `fullchain.pem` and
//! `privkey.pem` are symlinks moved onto them atomically, the key's
//! first.  A listener whose certificate is `<pki>/<name>/fullchain.pem`
//! serves it as it is installed, and renewed, by the runner's own look
//! at its files.
//!
//! What C does that this does too: the hash of the installed chain sent
//! first; an unchanged answer installed as nothing; a chain already
//! installed left alone; a name the server answers with other than the
//! link's own only reported; the link dropped on anything the server
//! sends that cannot be installed, and made again after the install
//! backoff; a dropped link made again after the connect backoff.  What
//! it does not: run as a separate privileged stub; reopen or reload
//! anything (the listener looks at its files itself).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use npro_certdist::{
    Backoff, CONNECT_BACKOFF, INSTALL_BACKOFF, MAX_PEM, PATH, PROTOCOL, Progress, Received,
    Storage, Update, hash, pem, valid_name,
};
use npro_core::time::Instant;
use npro_io::threads::Jobs;
use npro_io::tls::rustls::RustlsAny;
use npro_ss::event::{Filled, Kind};
use npro_ss::policy::Payload;
use npro_ss::ss::ClientTls;

use crate::front::Front;
use crate::random::ProviderRandom;
use crate::runner::Streams;

/// Where the certificates are installed when the policy names nowhere.
pub const DEFAULT_PKI: &str = "/var/npro/pki";

/// The distribution server, from the policy's URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server {
    /// Where to connect: `host:port`.
    pub address: String,
    /// The host, for the server name and the request's `Host`.
    pub host: String,
    /// Whether the link is tls: `wss://`, as it is in deployment;
    /// `ws://` serves a test with no certificates.
    pub wire: Wire,
}

/// What carries the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    /// tls, with the link's identity presented.
    Wss,
    /// Plain.
    Ws,
}

impl Server {
    /// The server `url` names: `wss://host[:port][/]`, or `ws://`.
    #[must_use]
    pub fn parse(url: &str) -> Option<Self> {
        let (wire, rest) = match (url.strip_prefix("wss://"), url.strip_prefix("ws://")) {
            (Some(r), _) => (Wire::Wss, r),
            (None, Some(r)) => (Wire::Ws, r),
            (None, None) => return None,
        };
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(']') || h.ends_with(']') => (h, p.parse::<u16>().ok()?),
            _ => (
                authority,
                match wire {
                    Wire::Wss => 443,
                    Wire::Ws => 80,
                },
            ),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return None;
        }
        Some(Self {
            address: format!("{host}:{port}"),
            host: host.to_owned(),
            wire,
        })
    }
}

/// One certificate's link: the name it is installed under, which is
/// also its identity's.
#[derive(Debug)]
struct Link {
    name: String,
    state: LinkState,
    /// How many connects in a row failed or dropped.
    retries: u16,
    /// How many installs in a row failed.
    install_failures: u16,
    /// The link is to be dropped for an install that failed, and made
    /// again after the install backoff.
    install_failed: bool,
}

/// Where a link is.
#[derive(Debug)]
enum LinkState {
    /// Not up: made at `due`, or at once if none.
    Down { due: Option<Instant> },
    /// Asked for, until the server agrees or not.
    Connecting,
    /// Up: the server's messages are parsed into `update`; `say` is the
    /// hash message to send first, until it has gone.
    Up {
        update: Box<Update<Vec<u8>>>,
        say: Option<[u8; hash::MESSAGE_LEN]>,
    },
}

/// The client: every link, kept up.
#[derive(Debug)]
pub struct Dist {
    server: Server,
    pki: PathBuf,
    links: Vec<Link>,
    random: ProviderRandom,
}

/// What the front does after a link's event, since the event borrows the
/// streams.
pub(crate) enum Then {
    Nothing,
    /// The link has a message to send: the hash.
    Say,
    /// The link is dropped: the server sent what cannot be installed.
    Drop,
}

impl Dist {
    /// The client for `server`, installing under `pki`, one link per name
    /// in `names`, each with an identity of that name among the runner's.
    #[must_use]
    pub fn new(server: Server, pki: PathBuf, names: &[&str], random: ProviderRandom) -> Self {
        Self {
            server,
            pki,
            links: names
                .iter()
                .map(|n| Link {
                    name: (*n).to_owned(),
                    state: LinkState::Down { due: None },
                    retries: 0,
                    install_failures: 0,
                    install_failed: false,
                })
                .collect(),
            random,
        }
    }

    /// Where `name`'s certificate chain is installed: what a listener
    /// names as its `cert`.
    #[must_use]
    pub fn fullchain_path(pki: &Path, name: &str) -> PathBuf {
        pki.join(name).join("fullchain.pem")
    }

    /// Where `name`'s key is installed: what a listener names as its
    /// `key`.
    #[must_use]
    pub fn privkey_path(pki: &Path, name: &str) -> PathBuf {
        pki.join(name).join("privkey.pem")
    }

    /// The front's turn: every link that is down and due is made.
    pub fn tick<'s>(
        &mut self,
        ss: &mut Streams<'s, Front>,
        now: Instant,
        jobs: &Jobs<'_, Streams<'s, Front>>,
    ) {
        for i in 0..self.links.len() {
            let due = match self.links.get(i).map(|l| &l.state) {
                Some(LinkState::Down { due }) => due.is_none_or(|d| d <= now),
                Some(LinkState::Connecting | LinkState::Up { .. }) | None => false,
            };
            if due {
                self.connect(i, ss, now, jobs);
            }
        }
    }

    /// Makes link `i`: the hash of what is installed goes first once the
    /// server agrees.
    fn connect<'s>(
        &mut self,
        i: usize,
        ss: &mut Streams<'s, Front>,
        now: Instant,
        jobs: &Jobs<'_, Streams<'s, Front>>,
    ) {
        let Some(link) = self.links.get_mut(i) else {
            return;
        };
        let tls = match self.server.wire {
            Wire::Wss => Some(ClientTls {
                server_name: &self.server.host,
                identity: Some(&link.name),
            }),
            Wire::Ws => None,
        };
        let made = ss.connect_ws(
            &self.server.address,
            tls,
            self.server.host.as_bytes(),
            PATH,
            Some(PROTOCOL),
            Payload::Text,
            self.random.clone(),
            Front::dist(i),
        );
        match made {
            Ok(_) => {
                report(format_args!(
                    "{}: connecting to {}",
                    link.name, self.server.address
                ));
                link.state = LinkState::Connecting;
            }
            Err(e) => {
                report(format_args!("{}: cannot connect: {e}", link.name));
                self.down(i, now, jobs);
            }
        }
    }

    /// Link `i` is down: made again after its backoff, the install one if
    /// an install failed, the connect one otherwise.
    fn down(&mut self, i: usize, now: Instant, jobs: &Jobs<'_, Streams<'_, Front>>) {
        let Some(link) = self.links.get_mut(i) else {
            return;
        };
        let (table, count): (Backoff, u16) = if link.install_failed {
            link.install_failed = false;
            link.install_failures = link.install_failures.saturating_add(1);
            (INSTALL_BACKOFF, link.install_failures.saturating_sub(1))
        } else {
            link.retries = link.retries.saturating_add(1);
            (CONNECT_BACKOFF, link.retries.saturating_sub(1))
        };
        let delay = table.delay(count, &mut self.random);
        report(format_args!(
            "{}: link down; again in {}s",
            link.name,
            delay.as_millis().saturating_add(500) / 1000
        ));
        link.state = LinkState::Down {
            due: Some(now.saturating_add(delay)),
        };
        // the front's turn after it is when the link is made
        jobs.after(delay, |_, _| {});
    }

    /// A link's event: what the front does after.
    pub(crate) fn event(
        &mut self,
        i: usize,
        kind: Kind<'_, Vec<u8>, ProviderRandom, RustlsAny>,
        now: Instant,
        jobs: &Jobs<'_, Streams<'_, Front>>,
    ) -> Then {
        match kind {
            Kind::ClientUpgraded { .. } => self.up(i),
            Kind::Rx { data, .. } => self.rx(i, data),
            Kind::NotUpgraded { status } => {
                if let Some(link) = self.links.get(i) {
                    report(format_args!(
                        "{}: the server would not switch: {status}",
                        link.name
                    ));
                }
                Then::Nothing
            }
            Kind::ConnectFailed => {
                if let Some(link) = self.links.get(i) {
                    report(format_args!("{}: connect failed", link.name));
                }
                self.down(i, now, jobs);
                Then::Nothing
            }
            Kind::Disconnected => {
                self.down(i, now, jobs);
                Then::Nothing
            }
            Kind::Tx(tx) => {
                let message = match self.links.get_mut(i).map(|l| &mut l.state) {
                    Some(LinkState::Up { say, .. }) => say.take(),
                    Some(LinkState::Down { .. } | LinkState::Connecting) | None => None,
                };
                tx.fill(|buf| match message {
                    Some(m) => {
                        let n = m.len().min(buf.len());
                        if let (Some(to), Some(from)) = (buf.get_mut(..n), m.get(..n)) {
                            to.copy_from_slice(from);
                        }
                        Filled::Last(n)
                    }
                    None => Filled::Last(0),
                });
                Then::Nothing
            }
            Kind::ServerTxn(_)
            | Kind::ServerUpgrade { .. }
            | Kind::UpgradeRefused(_)
            | Kind::ServerTxnEnd(_)
            | Kind::Response(_)
            | Kind::Pong
            | Kind::PeerClose { .. } => Then::Nothing,
        }
    }

    /// The server agreed to link `i`: it is up, and the hash of what is
    /// installed is said first, if anything is.
    fn up(&mut self, i: usize) -> Then {
        let Some(link) = self.links.get_mut(i) else {
            return Then::Nothing;
        };
        if !matches!(link.state, LinkState::Connecting) {
            return Then::Nothing;
        }
        link.retries = 0;
        let Ok(update) = update_storage() else {
            report(format_args!("{}: no storage for the link", link.name));
            return Then::Drop;
        };
        let say = installed_hash(&self.pki, &link.name).map(|h| {
            let mut m = [0u8; hash::MESSAGE_LEN];
            hash::message(&h, &mut m);
            m
        });
        report(format_args!(
            "{}: link up{}",
            link.name,
            if say.is_some() {
                ", saying the hash of what is installed"
            } else {
                ", nothing installed yet"
            }
        ));
        link.state = LinkState::Up {
            update: Box::new(update),
            say,
        };
        if say.is_some() {
            Then::Say
        } else {
            Then::Nothing
        }
    }

    /// A piece of what the server sent on link `i`: parsed, and once a
    /// message is whole, installed, or not.
    fn rx(&mut self, i: usize, data: &[u8]) -> Then {
        let Some(link) = self.links.get_mut(i) else {
            return Then::Nothing;
        };
        let LinkState::Up { update, .. } = &mut link.state else {
            return Then::Nothing;
        };
        match update.feed(data) {
            // a message ends with its object, as C resets its parser
            // there, whatever the ws message's framing
            Ok(Progress::More) => return Then::Nothing,
            Ok(Progress::Done { .. }) => {}
            Err(e) => {
                report(format_args!(
                    "{}: the server sent what cannot be installed ({e}); dropping the link",
                    link.name
                ));
                link.install_failed = true;
                return Then::Drop;
            }
        }
        let outcome = match update.received() {
            Received::Pair => {
                if update.subdomain() != link.name.as_bytes() {
                    report(format_args!(
                        "{}: the server answered for '{}'; installing as '{}'",
                        link.name,
                        update.subdomain().escape_ascii(),
                        link.name
                    ));
                }
                install(&self.pki, &link.name, update.fullchain(), update.privkey())
            }
            Received::Unchanged | Received::Nothing => Ok(Installed::Unchanged),
            Received::OneSided => Err("the server sent a one-sided update".to_owned()),
        };
        update.reset();
        match outcome {
            Ok(Installed::Installed) => {
                link.install_failures = 0;
                report(format_args!("{}: certificate installed", link.name));
                Then::Nothing
            }
            Ok(Installed::Unchanged) => {
                link.install_failures = 0;
                report(format_args!("{}: certificate unchanged", link.name));
                Then::Nothing
            }
            Err(why) => {
                report(format_args!(
                    "{}: not installed: {why}; still serving the previous certificate, fetching again after a backoff",
                    link.name
                ));
                link.install_failed = true;
                Then::Drop
            }
        }
    }
}

/// The storage one link parses the server's messages into: the token
/// buffer holds the longest string and the escapes JSON adds to it.
fn update_storage() -> Result<Update<Vec<u8>>, npro_json::NamesTooLarge> {
    Update::new(Storage {
        token: vec![0; MAX_PEM.saturating_add(4096)],
        names: vec![0; 256],
        fullchain: vec![0; MAX_PEM],
        privkey: vec![0; MAX_PEM],
    })
}

/// The SHA-1 of the chain installed as `name`, if one is.
fn installed_hash(pki: &Path, name: &str) -> Option<[u8; 20]> {
    let bytes = fs::read(Dist::fullchain_path(pki, name)).ok()?;
    Some(hash::of(&bytes))
}

/// What an install came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Installed {
    Installed,
    Unchanged,
}

/// Installs `fullchain` and `privkey` as `name` under `pki`, as C's
/// `cdc_install()` does: refused unless they are a pair; a chain already
/// installed is left; otherwise each is written new, the key readable by
/// this user alone, and the symlinks moved onto them, the key's first,
/// so a retry after a failure between the two finds the chain not yet
/// installed and completes the pair.
fn install(pki: &Path, name: &str, fullchain: &[u8], privkey: &[u8]) -> Result<Installed, String> {
    if !valid_name(name) {
        return Err("the name is not one to install under".to_owned());
    }
    if !pem::is_pair(fullchain, privkey) {
        return Err("the certificate or key is not PEM".to_owned());
    }
    let dir = pki.join(name);
    fs::create_dir_all(&dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    private_dir(&dir)?;
    if fs::read(dir.join("fullchain.pem")).is_ok_and(|have| have == fullchain) {
        return Ok(Installed::Unchanged);
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
        |_| "0".to_owned(),
        |d| format!("{}.{:06}", d.as_secs(), d.subsec_micros()),
    );
    let fc_name = format!("fullchain.pem.{stamp}");
    let pk_name = format!("privkey.pem.{stamp}");
    write_new(&dir.join(&fc_name), fullchain, 0o644)?;
    if let Err(e) = write_new(&dir.join(&pk_name), privkey, 0o600) {
        drop(fs::remove_file(dir.join(&fc_name)));
        return Err(e);
    }
    if let Err(e) = relink(&dir, &pk_name, "privkey.pem") {
        drop(fs::remove_file(dir.join(&fc_name)));
        drop(fs::remove_file(dir.join(&pk_name)));
        return Err(e);
    }
    // the key names the new file already: leave both, a retry completes
    // the pair
    relink(&dir, &fc_name, "fullchain.pem")?;
    Ok(Installed::Installed)
}

/// The directory a key is about to be written into is a real one, not
/// a symlink, that nobody but its owner can write to.
#[cfg(unix)]
fn private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let m = fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !m.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if m.permissions().mode() & 0o022 != 0 {
        return Err(format!(
            "{} is writable by others: not a private directory",
            dir.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_dir(dir: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !m.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    Ok(())
}

/// Writes `bytes` to a file that must not exist yet, with `mode`, and
/// syncs it.
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f: File = options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Points the symlink `name` in `dir` at its sibling `target`,
/// atomically: made as `name.tmp`, then renamed over.
fn relink(dir: &Path, target: &str, name: &str) -> Result<(), String> {
    let tmp = dir.join(format!("{name}.tmp"));
    drop(fs::remove_file(&tmp));
    symlink(target, &tmp).map_err(|e| format!("cannot link {}: {e}", tmp.display()))?;
    fs::rename(&tmp, dir.join(name)).map_err(|e| {
        drop(fs::remove_file(&tmp));
        format!("cannot move {name} into place: {e}")
    })
}

#[cfg(unix)]
fn symlink(target: &str, at: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

#[cfg(not(unix))]
fn symlink(target: &str, at: &Path) -> std::io::Result<()> {
    // no symlinks to speak of: the file itself, copied
    fs::copy(at.parent().unwrap_or(Path::new(".")).join(target), at).map(|_| ())
}

/// What the client has to say: this process' stderr, as C's log is.
#[expect(
    clippy::print_stderr,
    reason = "the client's reports go to the process' stderr, as C's log does; npro has no logger yet"
)]
fn report(what: core::fmt::Arguments<'_>) {
    eprintln!("npro: cert-dist: {what}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_servers_url_is_read_with_its_port_or_the_default() {
        let plain = Server::parse("wss://dist.example.com").unwrap();
        assert_eq!(
            (plain.address.as_str(), plain.host.as_str(), plain.wire),
            ("dist.example.com:443", "dist.example.com", Wire::Wss)
        );
        let with_port = Server::parse("wss://dist.example.com:8443/").unwrap();
        assert_eq!(with_port.address, "dist.example.com:8443");
        let ws = Server::parse("ws://127.0.0.1:9000").unwrap();
        assert_eq!((ws.address.as_str(), ws.wire), ("127.0.0.1:9000", Wire::Ws));
        let v6 = Server::parse("ws://[::1]:9000").unwrap();
        assert_eq!((v6.address.as_str(), v6.host.as_str()), ("::1:9000", "::1"));
        assert!(Server::parse("https://x").is_none());
        assert!(Server::parse("wss://").is_none());
        assert!(Server::parse("wss://x:notaport").is_none());
    }

    #[test]
    fn an_install_writes_new_files_and_moves_the_links_the_keys_first() {
        let dir = std::env::temp_dir().join(format!("npro-certdist-{}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        let c = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        let k = b"-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----\n";
        assert_eq!(install(&dir, "npro.rs", c, k), Ok(Installed::Installed));
        assert_eq!(fs::read(dir.join("npro.rs/fullchain.pem")).unwrap(), c);
        assert_eq!(fs::read(dir.join("npro.rs/privkey.pem")).unwrap(), k);
        assert!(
            fs::symlink_metadata(dir.join("npro.rs/fullchain.pem"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(installed_hash(&dir, "npro.rs"), Some(hash::of(c)));
        // the same again is unchanged; a new chain moves the links
        assert_eq!(install(&dir, "npro.rs", c, k), Ok(Installed::Unchanged));
        let c2 = b"-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n";
        assert_eq!(install(&dir, "npro.rs", c2, k), Ok(Installed::Installed));
        assert_eq!(fs::read(dir.join("npro.rs/fullchain.pem")).unwrap(), c2);
        let files = fs::read_dir(dir.join("npro.rs")).unwrap().count();
        assert_eq!(files, 6, "two of each, and the two links");
        // what is not a pair, or a name, is refused
        assert!(install(&dir, "npro.rs", c, b"").is_err());
        assert!(install(&dir, "../x", c, k).is_err());
        drop(fs::remove_dir_all(&dir));
    }
}
