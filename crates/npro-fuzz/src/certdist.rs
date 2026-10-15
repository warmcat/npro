//! The certdist-update target: the distribution server's message,
//! parsed in pieces.

use npro_certdist::{Progress, Received, Storage, Update, UpdateError, pem};

use crate::targets::{Pieces, control, finding};

const TARGET: &str = "certdist-update";

/// Small storage, so the caps are reached.
fn update() -> Update<Vec<u8>> {
    match Update::new(Storage {
        token: vec![0; 1024],
        names: vec![0; 256],
        fullchain: vec![0; 512],
        privkey: vec![0; 512],
    }) {
        Ok(u) => u,
        Err(e) => finding(TARGET, format_args!("storage refused: {e:?}")),
    }
}

/// Feeds `bytes` whole to one parser and in pieces to another: both
/// must come to the same, and what either holds must be plausible PEM
/// of no more than its storage, with the message's end at the same byte.
pub fn certdist_update(data: &[u8]) {
    let (ctl, bytes) = control(data);
    let mut whole = update();
    let at_once = whole.feed(bytes);
    let mut pieced = update();
    let mut fed = 0usize;
    let mut in_pieces: Result<Progress, UpdateError> = Ok(Progress::More);
    for piece in Pieces::new(ctl, bytes) {
        in_pieces = pieced.feed(piece);
        match in_pieces {
            Ok(Progress::More) => fed = fed.saturating_add(piece.len()),
            Ok(Progress::Done { consumed }) => {
                if consumed > piece.len() {
                    finding(
                        TARGET,
                        format_args!("consumed {consumed} of {}", piece.len()),
                    );
                }
                fed = fed.saturating_add(consumed);
                break;
            }
            Err(_) => break,
        }
    }
    match (at_once, in_pieces) {
        (Ok(Progress::Done { consumed }), Ok(Progress::Done { .. })) => {
            if consumed != fed || consumed > bytes.len() {
                finding(TARGET, format_args!("whole took {consumed}, pieces {fed}"));
            }
            let (a, b) = (whole.received(), pieced.received());
            if a != b || a == Received::Nothing {
                finding(TARGET, format_args!("whole {a:?}, pieces {b:?}"));
            }
            if whole.fullchain() != pieced.fullchain()
                || whole.privkey() != pieced.privkey()
                || whole.subdomain() != pieced.subdomain()
            {
                finding(
                    TARGET,
                    format_args!("whole and pieces hold different things"),
                );
            }
            if !pem::plausible(whole.fullchain()) || !pem::plausible(whole.privkey()) {
                finding(TARGET, format_args!("held what is not PEM"));
            }
            if a == Received::Pair && (whole.fullchain().is_empty() || whole.privkey().is_empty()) {
                finding(TARGET, format_args!("a pair with a side empty"));
            }
            // reset, the next message is taken afresh
            whole.reset();
            if whole.received() != Received::Nothing || !whole.privkey().is_empty() {
                finding(TARGET, format_args!("reset kept something"));
            }
        }
        (Ok(Progress::More), Ok(Progress::More)) | (Err(_), Err(_)) => {}
        (a, b) => finding(TARGET, format_args!("whole {a:?}, pieces {b:?}")),
    }
}
