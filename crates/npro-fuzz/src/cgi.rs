//! The cgi-head target: a script's answer's head, parsed in pieces.

use npro_cgi::{Head, HeadError, MAX_HEAD, Progress};

use crate::targets::{Pieces, control, finding};

const TARGET: &str = "cgi-head";

/// The input, behind a control byte choosing the pieces, is what a script
/// wrote: it is fed whole and in pieces, and both must come to the same,
/// the head taking no more than [`MAX_HEAD`] and the payload's start left
/// exactly where the blank line ended.
pub fn cgi_head(data: &[u8]) {
    let (ctl, bytes) = control(data);
    let mut whole = Head::new();
    let at_once = whole.feed(bytes);
    let mut pieced = Head::new();
    let mut fed = 0usize;
    let mut in_pieces: Result<Progress, HeadError> = Ok(Progress::More);
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
            // a CR is dropped as it is read, so a head of CRLF lines takes
            // up to twice what it keeps, and the blank line
            if consumed > MAX_HEAD.saturating_mul(2).saturating_add(4) {
                finding(TARGET, format_args!("a head of {consumed}"));
            }
            let (a, b) = (whole.parsed(), pieced.parsed());
            if a != b {
                finding(TARGET, format_args!("whole {a:?}, pieces {b:?}"));
            }
            if a.lines().count() < a.passed().count() {
                finding(TARGET, format_args!("more passed than there are"));
            }
        }
        (Ok(Progress::More), Ok(Progress::More)) | (Err(_), Err(_)) => {}
        (a, b) => finding(TARGET, format_args!("whole {a:?}, pieces {b:?}")),
    }
}
