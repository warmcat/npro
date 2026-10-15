//! The `npro` command: `serve` on a policy file serving a directory over
//! a unix domain socket, with a `-p` fragment over it; and what it says
//! when it cannot.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one runs the npro binary alone"
)]

// held to clippy's rules for tests
#[cfg(test)]
#[cfg(unix)]
mod cli {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn npro() -> Command {
        Command::new(env!("CARGO_BIN_EXE_npro"))
    }

    /// A directory with a policy serving it over a unix socket: the
    /// policy file's path, and the socket's.
    fn setup(name: &str) -> (PathBuf, PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("npro-cli-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), b"<html>served</html>").unwrap();
        let sock = dir.join("npro.sock");
        let policy = dir.join("policy.json");
        std::fs::write(
            &policy,
            format!(
                r#"{{
  "listeners": {{ "main": {{ "bind": "unix:{sock}", "vhosts": ["localhost"] }} }},
  "vhosts": {{ "localhost": {{ "headers": {{ "x-npro": "1" }},
                               "access-log": "{dir}/access.log",
                               "routes": [ {{ "path": "/", "to": "www" }},
                                           {{ "path": "/old", "to": "moved" }} ] }} }},
  "services": {{ "www": {{ "type": "files", "root": "{dir}" }},
                 "moved": {{ "type": "redirect", "to": "https://example.com/new", "append-path": true }} }}
}}"#,
                sock = sock.display(),
                dir = dir.display()
            ),
        )
        .unwrap();
        (dir, policy, sock)
    }

    /// Asks the server at `sock` for `request`, once it is there.
    fn ask(sock: &PathBuf, request: &[u8]) -> Vec<u8> {
        let start = Instant::now();
        let mut c = loop {
            match UnixStream::connect(sock) {
                Ok(c) => break c,
                Err(_) if start.elapsed() < Duration::from_secs(10) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("{}: {e}", sock.display()),
            }
        };
        c.write_all(request).unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        got
    }

    #[test]
    #[cfg_attr(miri, ignore = "runs the binary: native runs keep it")]
    fn serve_serves_the_policy_with_a_fragment_over_it() {
        let (dir, policy, sock) = setup("serve");
        let mut child = npro()
            .args(["serve", "--policy"])
            .arg(&policy)
            // a layer over the file: the slots, which the file leaves to
            // the built-in default
            .args(["-p", "npro.slots=3"])
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let outcome = std::panic::catch_unwind(|| {
            let got = ask(
                &sock,
                b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            );
            let text = String::from_utf8_lossy(&got);
            assert!(
                text.starts_with("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 19\r\nx-npro: 1\r\n"),
                "{text}"
            );
            assert!(text.ends_with("<html>served</html>"));
            let moved = ask(
                &sock,
                b"GET /old/thing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            );
            assert!(
                moved.starts_with(
                    b"HTTP/1.1 301 Redirect\r\nlocation: https://example.com/new/thing\r\n"
                ),
                "{}",
                moved.escape_ascii()
            );
        });
        child.kill().unwrap();
        let out = child.wait_with_output().unwrap();
        let log = std::fs::read_to_string(dir.join("access.log")).unwrap_or_default();
        drop(std::fs::remove_dir_all(&dir));
        assert!(
            outcome.is_ok(),
            "npro said: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // the access log: a line per request, the peer `-` on a unix
        // socket, the bytes being the whole answer
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2, "{log}");
        assert!(
            lines[0].starts_with("- - - [") && lines[0].contains("] \"GET / HTTP/1.1\" 200 "),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].contains("] \"GET /old/thing HTTP/1.1\" 301 ")
                && lines[1].ends_with("\"\" \"\""),
            "{}",
            lines[1]
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "runs the binary: native runs keep it")]
    fn a_policy_that_is_wrong_is_refused_saying_where() {
        let (dir, policy, _) = setup("wrong");
        let out = npro()
            .args(["serve", "--policy"])
            .arg(&policy)
            .args(["-p", r#"{"services": {"www": {"type": "cgi"}}}"#])
            .output()
            .unwrap();
        drop(std::fs::remove_dir_all(&dir));
        assert!(!out.status.success());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("policy: services.www.type: no \"cgi\"; there is files, proxy, redirect"),
            "{err}"
        );
        // a policy file that is not there, when named, is refused
        let missing = npro()
            .args(["serve", "--policy", "/nonexistent/policy.json"])
            .output()
            .unwrap();
        assert!(!missing.status.success());
        assert!(String::from_utf8_lossy(&missing.stderr).contains("/nonexistent/policy.json"));
        // and so is an option it does not have
        let bogus = npro().args(["serve", "--bogus"]).output().unwrap();
        assert_eq!(bogus.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&bogus.stderr).contains("usage:"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "runs the binary: native runs keep it")]
    fn help_and_version_are_said() {
        let help = npro().arg("--help").output().unwrap();
        assert!(help.status.success());
        assert!(String::from_utf8_lossy(&help.stdout).contains("npro serve [--policy FILE]"));
        let version = npro().arg("--version").output().unwrap();
        assert!(String::from_utf8_lossy(&version.stdout).starts_with("npro "));
    }
}
