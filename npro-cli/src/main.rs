//! `npro`: npro's utility.  So far, the server: `npro serve` serves
//! everything its policy says (docs/ss-design.md, "Where the utility
//! lives").
//!
//! ```text
//! npro serve [--policy FILE] [-p FRAGMENT]...
//! npro --help | --version
//! ```
//!
//! The policy is read in layers (`npro_cli::policy`): what is built in,
//! `/etc/npro/defaults.json`, `~/.config/npro/defaults.json`, the
//! `--policy` file (`/etc/npro/policy.json` when none is named), and
//! each `-p` fragment, a JSON object or `key.path=value`, each layer
//! over the last.  Once its listeners are bound the process drops every
//! capability it has, and serves until it is killed.

#![forbid(unsafe_code)]
#![expect(
    clippy::print_stderr,
    clippy::print_stdout,
    reason = "the command line's own: what it says to its user"
)]
#![expect(
    unused_crate_dependencies,
    reason = "the binary goes through the library crate alone; the dependencies are the library's, which the binary sees too"
)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use npro_cli::front::{Front, Logs, act, check};
use npro_cli::policy::{self, Policy};
use npro_cli::runner::{Streams, bind};
use npro_io::threads::{Stop, Workers};

const HELP: &str = "npro: npro's utility

usage:
  npro serve [--policy FILE] [-p FRAGMENT]...
  npro --help
  npro --version

serve        serves everything the policy says, until killed
--policy     the policy file; /etc/npro/policy.json if not given
-p FRAGMENT  one more layer over the policy: a JSON object, or
             key.path=value, as many times as wanted

The policy is read in layers, each over the last: what is built in,
/etc/npro/defaults.json, ~/.config/npro/defaults.json, the policy
file, then the fragments.  docs/ss-policy.md says what goes in it;
npro-cli/README.md, the shape this version reads.
";

/// What the command line asked for.
enum Command {
    Help,
    Version,
    Serve {
        policy: Option<PathBuf>,
        fragments: Vec<String>,
    },
}

/// Why the command line was not understood.
struct Usage(String);

fn parse(args: &[String]) -> Result<Command, Usage> {
    let mut it = args.iter();
    let Some(first) = it.next() else {
        return Err(Usage("nothing to do".into()));
    };
    match first.as_str() {
        "--help" | "-h" | "help" => Ok(Command::Help),
        "--version" | "-V" => Ok(Command::Version),
        "serve" => {
            let mut policy = None;
            let mut fragments = Vec::new();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--policy" => {
                        let f = it
                            .next()
                            .ok_or_else(|| Usage("--policy needs a file".into()))?;
                        policy = Some(PathBuf::from(f));
                    }
                    "-p" => {
                        let f = it
                            .next()
                            .ok_or_else(|| Usage("-p needs a fragment".into()))?;
                        fragments.push(f.clone());
                    }
                    other => return Err(Usage(format!("serve: {other:?} is not an option"))),
                }
            }
            Ok(Command::Serve { policy, fragments })
        }
        other => Err(Usage(format!("{other:?} is not a command"))),
    }
}

/// Serves the policy until killed: why it stopped before, if it did.
fn serve(policy: Option<&Path>, fragments: &[String]) -> Result<(), String> {
    let merged = policy::layers(policy, fragments).map_err(|e| format!("policy: {e}"))?;
    let Policy {
        listeners,
        services,
        logs,
        slots,
        workers,
    } = policy::policy(&merged).map_err(|e| format!("policy: {e}"))?;
    if listeners.is_empty() {
        return Err("policy: no listeners: nothing to serve".into());
    }
    check(&services, listeners).map_err(|e| format!("policy: {e}"))?;
    // the logs before the listeners: a log that cannot be opened is
    // refused before a port is taken
    let logs = Logs::open(logs).map_err(|e| e.to_string())?;
    let bound = bind(listeners).map_err(|e| e.to_string())?;
    let stop = Stop::new();
    bound
        .serve(
            slots,
            move |ss: &mut Streams<'_, Front>, now, jobs| act(&services, &logs, ss, now, jobs),
            Workers(workers),
            &stop,
        )
        .map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse(&args) {
        Ok(c) => c,
        Err(Usage(why)) => {
            eprintln!("npro: {why}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    match command {
        Command::Help => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("npro {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Serve { policy, fragments } => match serve(policy.as_deref(), &fragments) {
            Ok(()) => ExitCode::SUCCESS,
            Err(why) => {
                eprintln!("npro: {why}");
                ExitCode::FAILURE
            }
        },
    }
}
