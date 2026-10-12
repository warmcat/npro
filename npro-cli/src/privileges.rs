//! Dropping the process' privileges once its listeners are bound.
//!
//! systemd starts the server as its own user with only
//! `CAP_NET_BIND_SERVICE`, so it can bind 80 and 443.  Once they are bound
//! it needs no privilege at all, so it drops every capability it has,
//! from every set it can (Andy, 2026-10-12): code an attacker gets running
//! in it then cannot bind a port below 1024 of its own.  The bounding set
//! is left as systemd's `CapabilityBoundingSet=` made it: clearing it
//! takes `CAP_SETPCAP`, which the server is not given.
//!
//! Capabilities belong to each thread, and a thread starts with its
//! creator's, so they are dropped on the thread that goes on to start the
//! others, before it starts any.  Elsewhere than Linux there are none.

/// Why the capabilities could not be dropped.  The server does not go
/// on: it would be running with more than it should.
#[derive(Debug)]
pub struct Kept {
    /// What the system said.
    pub why: String,
}

impl core::fmt::Display for Kept {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "capabilities not dropped: {}", self.why)
    }
}

impl core::error::Error for Kept {}

/// Drops every capability the calling thread has, ambient, inheritable,
/// effective and permitted, and checks none is left, so none can be
/// raised again.  Call it before starting any thread.
///
/// ```
/// npro_cli::privileges::drop_all()?;
/// # Ok::<(), npro_cli::privileges::Kept>(())
/// ```
///
/// # Errors
///
/// [`Kept`], if one could not be dropped, or is still there.
#[cfg(target_os = "linux")]
pub fn drop_all() -> Result<(), Kept> {
    use caps::CapSet;
    let kept = |e: caps::errors::CapsError| Kept { why: e.to_string() };
    // ambient must stay within permitted and inheritable: it goes first
    for set in [
        CapSet::Ambient,
        CapSet::Inheritable,
        CapSet::Effective,
        CapSet::Permitted,
    ] {
        caps::clear(None, set).map_err(kept)?;
    }
    let left = caps::read(None, CapSet::Permitted).map_err(kept)?;
    if left.is_empty() {
        Ok(())
    } else {
        Err(Kept {
            why: format!("{left:?} still permitted"),
        })
    }
}

/// There are no capabilities to drop.
///
/// # Errors
///
/// None.
#[cfg(not(target_os = "linux"))]
pub fn drop_all() -> Result<(), Kept> {
    Ok(())
}
