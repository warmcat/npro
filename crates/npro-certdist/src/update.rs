//! The server's message, parsed as it comes: `{"subdomain":"<name>",
//! "fullchain":"<PEM>","privkey":"<PEM>"}`, one ws text message, in
//! whatever pieces the frames bring it.  C parses it with lejp as the
//! frames come, and resets its parser when the object ends; here
//! npro-json does the same, into storage the caller gives, the chain and
//! key copied out of its token buffer as each lands.

use npro_json::{Config, Error as JsonError, Event, Parser};

use crate::{MAX_NAME, MAX_PEM, pem};

/// The storage an [`Update`] parses into: the parser's token and names
/// buffers, and the chain and key copied out.  `token` must hold the
/// longest string the server may send, [`MAX_PEM`] and the escapes
/// JSON adds to it; `fullchain` and `privkey` [`MAX_PEM`] each; `names`
/// a few member names.  A string that does not fit `token` refuses the
/// message, as C refuses one past the cap.
#[derive(Clone, Debug)]
pub struct Storage<S> {
    /// The parser's token buffer.
    pub token: S,
    /// The parser's names buffer.
    pub names: S,
    /// Where the chain goes.
    pub fullchain: S,
    /// Where the key goes.
    pub privkey: S,
}

/// What [`Update::feed`] came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// The message is not whole yet: feed it more.
    More,
    /// The message is whole, and took this much of the piece: see
    /// [`Update::received`].  The rest of the piece is the next
    /// message's, for an [`Update`] reset.
    Done {
        /// How many bytes of the piece were the message's.
        consumed: usize,
    },
}

/// What a whole message said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// Nothing yet: the message is not whole.
    Nothing,
    /// The chain and key are unchanged: both empty.  There is nothing
    /// to install, and the link stays up.
    Unchanged,
    /// A chain and a key: [`Update::fullchain`] and [`Update::privkey`]
    /// hold them, plausible as PEM.  Whether they are a pair worth
    /// installing is [`pem::is_pair`]'s to say.
    Pair,
    /// One of the two came and not the other: malformed, nothing is
    /// installed, as C warns and goes on.
    OneSided,
}

/// Why the message was refused: C drops the link, and fetches again
/// after the install backoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// It is not JSON.
    Json(JsonError),
    /// It is JSON, but not an object.
    NotAnObject,
    /// A chain or key is longer than [`MAX_PEM`], or does not fit the
    /// storage.
    TooLong,
    /// A chain or key is not plausibly PEM ([`pem::plausible`]).
    NotPem,
}

impl core::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "not JSON: {e}"),
            Self::NotAnObject => f.write_str("not an object"),
            Self::TooLong => f.write_str("a certificate or key longer than allowed"),
            Self::NotPem => f.write_str("a certificate or key that is not PEM"),
        }
    }
}

impl core::error::Error for UpdateError {}

/// Which member of the object a value belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Member {
    /// None of the three: ignored, whatever it is, as lejp ignores it.
    Other,
    Subdomain,
    Fullchain,
    Privkey,
}

/// Where the parse is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Before the object.
    Start,
    /// In the object, at depth `nesting` below it (0 at its members).
    Inside {
        nesting: u8,
        /// The member whose value is next, or is being skipped.
        member: Member,
    },
    /// The object ended.
    Done,
    /// Refused: nothing more is taken.
    Failed(UpdateError),
}

/// A message being taken, into caller storage.
#[derive(Debug)]
pub struct Update<S> {
    parser: Parser<S>,
    held: Held<S>,
}

/// What is held of the message, beside the parser: the parser's events
/// borrow it, so this is what they are applied to.
#[derive(Debug)]
struct Held<S> {
    fullchain: S,
    fullchain_len: usize,
    privkey: S,
    privkey_len: usize,
    subdomain: [u8; MAX_NAME],
    subdomain_len: usize,
    state: State,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Update<S> {
    /// Ready for the first message, parsing into `storage`.
    ///
    /// # Errors
    ///
    /// [`npro_json::NamesTooLarge`], if `storage.names` is more than a
    /// parser can address.
    pub fn new(storage: Storage<S>) -> Result<Self, npro_json::NamesTooLarge> {
        let Storage {
            token,
            names,
            fullchain,
            privkey,
        } = storage;
        let parser = Parser::new(npro_json::Storage { token, names }, Config::new())?;
        Ok(Self {
            parser,
            held: Held {
                fullchain,
                fullchain_len: 0,
                privkey,
                privkey_len: 0,
                subdomain: [0; MAX_NAME],
                subdomain_len: 0,
                state: State::Start,
            },
        })
    }

    /// Ready for the next message: what the last said is forgotten, and
    /// the key's bytes are cleared.
    pub fn reset(&mut self) {
        self.parser.reset();
        let h = &mut self.held;
        h.privkey.as_mut().fill(0);
        h.fullchain_len = 0;
        h.privkey_len = 0;
        h.subdomain_len = 0;
        h.state = State::Start;
    }

    /// Takes the next piece of the message.
    ///
    /// # Errors
    ///
    /// [`UpdateError`], and nothing more is taken until [`Update::reset`].
    pub fn feed(&mut self, piece: &[u8]) -> Result<Progress, UpdateError> {
        let mut at = 0usize;
        loop {
            match self.held.state {
                State::Failed(e) => return Err(e),
                State::Done => return Ok(Progress::Done { consumed: at }),
                State::Start | State::Inside { .. } => {}
            }
            let rest = piece.get(at..).unwrap_or_default();
            if rest.is_empty() {
                return Ok(Progress::More);
            }
            let step = match self.parser.next(rest) {
                Ok(s) => s,
                Err(e) => return Err(self.held.fail(UpdateError::Json(e))),
            };
            at = at.saturating_add(step.consumed);
            let Some(event) = step.event else {
                if step.consumed == 0 {
                    return Ok(Progress::More);
                }
                continue;
            };
            if let Err(e) = self.held.take(event) {
                return Err(self.held.fail(e));
            }
        }
    }

    /// What the whole message said: [`Received::Nothing`] before it is
    /// whole.
    #[must_use]
    pub fn received(&self) -> Received {
        if self.held.state != State::Done {
            return Received::Nothing;
        }
        match (self.held.fullchain_len, self.held.privkey_len) {
            (0, 0) => Received::Unchanged,
            (0, _) | (_, 0) => Received::OneSided,
            (_, _) => Received::Pair,
        }
    }

    /// The name the server said, which the client logs if it disagrees
    /// with its own and otherwise ignores.
    #[must_use]
    pub fn subdomain(&self) -> &[u8] {
        self.held
            .subdomain
            .get(..self.held.subdomain_len)
            .unwrap_or_default()
    }

    /// The chain, as it came.
    #[must_use]
    pub fn fullchain(&self) -> &[u8] {
        self.held
            .fullchain
            .as_ref()
            .get(..self.held.fullchain_len)
            .unwrap_or_default()
    }

    /// The key, as it came.
    #[must_use]
    pub fn privkey(&self) -> &[u8] {
        self.held
            .privkey
            .as_ref()
            .get(..self.held.privkey_len)
            .unwrap_or_default()
    }
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Held<S> {
    const fn fail(&mut self, e: UpdateError) -> UpdateError {
        self.state = State::Failed(e);
        e
    }

    /// One event of the parse, where the state says it belongs.
    fn take(&mut self, event: Event<'_>) -> Result<(), UpdateError> {
        match (self.state, event) {
            (State::Start, Event::ObjectStart) => {
                self.state = State::Inside {
                    nesting: 0,
                    member: Member::Other,
                };
                Ok(())
            }
            // anything but an object is not the server's
            (
                State::Start,
                Event::ObjectEnd
                | Event::ArrayStart
                | Event::ArrayEnd
                | Event::Name(_)
                | Event::String(_)
                | Event::Number(_)
                | Event::Bool(_)
                | Event::Null,
            ) => Err(UpdateError::NotAnObject),
            (State::Inside { nesting: 0, .. }, Event::ObjectEnd) => {
                self.state = State::Done;
                Ok(())
            }
            (State::Inside { nesting: 0, .. }, Event::Name(name)) => {
                // a member twice is npro-json's to refuse
                let member = match name {
                    "subdomain" => Member::Subdomain,
                    "fullchain" => Member::Fullchain,
                    "privkey" => Member::Privkey,
                    _ => Member::Other,
                };
                self.state = State::Inside { nesting: 0, member };
                Ok(())
            }
            (
                State::Inside {
                    nesting: 0,
                    member: member @ (Member::Subdomain | Member::Fullchain | Member::Privkey),
                },
                Event::String(s),
            ) => {
                self.string(member, s.as_bytes())?;
                self.state = State::Inside {
                    nesting: 0,
                    member: Member::Other,
                };
                Ok(())
            }
            // a value of another kind where a string belongs, or any
            // value of a member not ours: skipped, as lejp skips it
            (State::Inside { nesting, .. }, event) => {
                self.state = State::Inside {
                    nesting: skipped(nesting, event),
                    member: Member::Other,
                };
                Ok(())
            }
            // never so: feed stops at these
            (State::Done | State::Failed(_), _) => Ok(()),
        }
    }

    /// A string where one of ours belongs: the name copied as far as it
    /// fits, a chain or key whole or refused.
    fn string(&mut self, member: Member, body: &[u8]) -> Result<(), UpdateError> {
        if member == Member::Subdomain {
            let n = body.len().min(MAX_NAME);
            if let (Some(to), Some(from)) = (self.subdomain.get_mut(..n), body.get(..n)) {
                to.copy_from_slice(from);
            }
            self.subdomain_len = n;
            return Ok(());
        }
        if body.len() > MAX_PEM {
            return Err(UpdateError::TooLong);
        }
        if !pem::plausible(body) {
            return Err(UpdateError::NotPem);
        }
        let (into, len) = match member {
            Member::Fullchain => (self.fullchain.as_mut(), &mut self.fullchain_len),
            Member::Privkey | Member::Subdomain | Member::Other => {
                (self.privkey.as_mut(), &mut self.privkey_len)
            }
        };
        let room = into.get_mut(..body.len()).ok_or(UpdateError::TooLong)?;
        room.copy_from_slice(body);
        *len = body.len();
        Ok(())
    }
}

/// The nesting after `event` is skipped at `nesting`: one deeper into a
/// value that is an object or array, one shallower out of it.
const fn skipped(nesting: u8, event: Event<'_>) -> u8 {
    match event {
        Event::ObjectStart | Event::ArrayStart => nesting.saturating_add(1),
        Event::ObjectEnd | Event::ArrayEnd => nesting.saturating_sub(1),
        Event::Name(_) | Event::String(_) | Event::Number(_) | Event::Bool(_) | Event::Null => {
            nesting
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    const CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----\n";

    fn update() -> Update<Vec<u8>> {
        Update::new(Storage {
            token: vec![0; 512],
            names: vec![0; 256],
            fullchain: vec![0; 256],
            privkey: vec![0; 256],
        })
        .unwrap()
    }

    /// The message with `cert` and `key`, JSON-escaped.
    fn message(cert: &str, key: &str) -> Vec<u8> {
        let esc = |s: &str| s.replace('\n', "\\n");
        alloc::format!(
            "{{\"subdomain\":\"npro.rs\",\"fullchain\":\"{}\",\"privkey\":\"{}\"}}",
            esc(cert),
            esc(key)
        )
        .into_bytes()
    }

    #[test]
    fn a_pair_comes_in_pieces_and_is_held_unescaped() {
        let mut u = update();
        let m = message(CERT, KEY);
        let (a, b) = m.split_at(37);
        assert_eq!(u.feed(a), Ok(Progress::More));
        assert_eq!(u.received(), Received::Nothing);
        let mut rest = b.to_vec();
        rest.extend_from_slice(b"{\"next\":");
        assert_eq!(u.feed(&rest), Ok(Progress::Done { consumed: b.len() }));
        assert_eq!(u.received(), Received::Pair);
        assert_eq!(u.subdomain(), b"npro.rs");
        assert_eq!(u.fullchain(), CERT.as_bytes());
        assert_eq!(u.privkey(), KEY.as_bytes());
        assert!(pem::is_pair(u.fullchain(), u.privkey()));
        // whole, it takes nothing more; reset, it takes the next
        assert_eq!(u.feed(b"x"), Ok(Progress::Done { consumed: 0 }));
        u.reset();
        assert_eq!(u.received(), Received::Nothing);
        assert_eq!(u.privkey(), b"");
        let m2 = message("", "");
        assert_eq!(u.feed(&m2), Ok(Progress::Done { consumed: m2.len() }));
        assert_eq!(u.received(), Received::Unchanged);
    }

    #[test]
    fn one_side_alone_other_members_and_order_are_as_c_takes_them() {
        let mut u = update();
        let m = message(CERT, "");
        u.feed(&m).unwrap();
        assert_eq!(u.received(), Received::OneSided);
        let mut u2 = update();
        let m2 = alloc::format!(
            "{{\"v\":1,\"privkey\":\"{}\",\"extra\":{{\"a\":[1,{{\"b\":null}}]}},\"fullchain\":\"{}\"}}",
            KEY.replace('\n', "\\n"),
            CERT.replace('\n', "\\n")
        );
        u2.feed(m2.as_bytes()).unwrap();
        assert_eq!(u2.received(), Received::Pair);
        assert_eq!(u2.subdomain(), b"");
    }

    #[test]
    fn what_is_not_the_servers_is_refused_and_stays_so() {
        let refused = |m: &[u8]| {
            let mut u = update();
            let e = u.feed(m).unwrap_err();
            assert_eq!(u.feed(b"{}"), Err(e));
            e
        };
        assert_eq!(refused(b"[1]"), UpdateError::NotAnObject);
        assert_eq!(refused(b"\"s\""), UpdateError::NotAnObject);
        assert!(matches!(refused(b"{\"a\":}"), UpdateError::Json(_)));
        // a member twice is npro-json's refusal
        assert!(matches!(
            refused(b"{\"fullchain\":\"a\",\"fullchain\":\"b\"}"),
            UpdateError::Json(_)
        ));
        assert_eq!(
            refused(b"{\"fullchain\":\"\\\"quoted\\\"\"}"),
            UpdateError::NotPem
        );
        assert_eq!(refused(b"{\"privkey\":\"\\u0001\"}"), UpdateError::NotPem);
        // longer than the storage for it
        let long = alloc::format!("{{\"fullchain\":\"{}\"}}", "A".repeat(300));
        assert_eq!(refused(long.as_bytes()), UpdateError::TooLong);
        // longer than the parser's token buffer: npro-json's refusal
        let longer = alloc::format!("{{\"fullchain\":\"{}\"}}", "A".repeat(600));
        assert!(matches!(refused(longer.as_bytes()), UpdateError::Json(_)));
    }
}
