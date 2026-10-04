//! Every transcript copied from C reads, and says what its README says.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses only npro-test"
)]

use npro_test::{Side, StepKind, vendored};

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of kilobytes of transcripts: native runs keep it"
)]
fn every_vendored_transcript_reads() {
    let all = vendored().unwrap();

    // as many as the sync copied: a file that failed to read would have
    // failed vendored() itself, so this catches a sync that copied none
    let files = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/transcripts"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|x| x == "json")
        })
        .count();
    assert!(files > 0);
    assert_eq!(all.len(), files);

    for t in &all {
        // the harness starts every run at the same times
        assert_eq!(t.t0_us, 1_000_000_000, "{}", t.case);
        assert_eq!(t.t0_wall, 1_767_225_600, "{}", t.case);

        // only a client draws lws' random in what these record: its ws key
        // and its masks
        if t.seed.is_some() {
            assert_eq!(t.side, Side::Client, "{} is seeded", t.case);
        }

        // a connection with no bytes either way records nothing
        assert!(
            t.steps
                .iter()
                .any(|s| matches!(s.kind, StepKind::Rx(_) | StepKind::Tx(_))),
            "{} moves no bytes",
            t.case
        );
    }
}

#[test]
fn the_c_commit_is_recorded() {
    let c = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/transcripts/C-COMMIT"))
        .unwrap();
    let hash = c.split_whitespace().next().unwrap();
    assert_eq!(hash.len(), 40);
    assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
}
