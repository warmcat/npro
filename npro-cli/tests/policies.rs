//! The policies shipped under `policies/` load: each is what a
//! deployment starts from, and must read as this version reads it.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses npro-cli and npro-ss"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod policies {
    use npro_cli::front::check;
    use npro_cli::policy::{parse, policy};
    use npro_ss::policy::Tls;

    #[test]
    fn the_npro_rs_policy_loads_and_names_only_built_in_services() {
        let text = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/policies/npro.rs.json"
        ))
        .unwrap();
        let v = parse("npro.rs.json", &text).unwrap();
        let p = policy(&v).unwrap();
        check(&p.services, p.listeners).unwrap();
        assert_eq!(p.listeners.len(), 2);
        assert!(matches!(p.listeners[0].tls, Tls::Server { .. }));
        assert_eq!(p.listeners[0].vhosts[0].routes.len(), 8);
        assert!(p.services.by_name.iter().any(|(n, _)| *n == "repo"));
        assert_eq!(p.logs, &[("npro.rs", "/srv/log/lwsws/npro-access-log")]);
        assert_eq!((p.slots, p.workers), (256, 4));
    }
}
