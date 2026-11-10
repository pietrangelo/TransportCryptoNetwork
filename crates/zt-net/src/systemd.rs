//! Notifications to systemd (`Type=notify`): readiness, status lines, stopping and the
//! watchdog, with no dependencies and no `unsafe` code.
//!
//! The service declares itself ready only once it has loaded its key and trust files and already
//! handles `SIGHUP`: this way systemd never sends a `reload` to a process that would die from it
//! (finding 0004-2).

/// Environment variable holding the notification socket, set by systemd.
const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";

/// Sends `READY=1` to systemd if the service was started with `Type=notify`; otherwise does
/// nothing. An error is not fatal: it is just logged.
pub fn notify_ready() {
    notify("READY=1");
}

/// Whether a failed notification was already reported at warning level.
static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Sends one notification (`STATUS=...`, `STOPPING=1`, `WATCHDOG=1`, ...) if the service runs
/// under systemd with a notification socket; otherwise does nothing. The socket is
/// non-blocking (finding A10-3): a service manager that stops draining its queue costs a lost
/// notification, never a blocked hub. The first error is logged as a warning, the next ones at
/// debug level: the service keeps running without them.
pub fn notify(message: &str) {
    let Some(socket) = std::env::var_os(NOTIFY_SOCKET).filter(|s| !s.is_empty()) else {
        return;
    };
    if let Err(err) = send(&socket, message.as_bytes()) {
        if WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::debug!(error = %err, "cannot notify systemd");
        } else {
            tracing::warn!(error = %err, "cannot notify systemd (further failures at debug level)");
        }
    }
}

/// `CLOCK_MONOTONIC` in microseconds, for `MONOTONIC_USEC=` next to `RELOADING=1`.
#[must_use]
pub fn monotonic_usec() -> u64 {
    #[cfg(unix)]
    {
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        let secs = u64::try_from(now.tv_sec).unwrap_or(0);
        let micros = u64::try_from(now.tv_nsec).unwrap_or(0) / 1_000;
        secs.saturating_mul(1_000_000).saturating_add(micros)
    }
    #[cfg(not(unix))]
    0
}

/// A one-line status for `systemctl status` (`STATUS=`).
pub fn status(line: &str) {
    notify(&format!("STATUS={}", line.replace('\n', " ")));
}

/// The watchdog interval systemd expects (`WatchdogSec=`, passed as `WATCHDOG_USEC`), if it is
/// enabled for this process (`WATCHDOG_PID` absent or equal to our pid).
#[must_use]
pub fn watchdog_interval() -> Option<std::time::Duration> {
    if let Some(pid) = std::env::var_os("WATCHDOG_PID")
        && pid.to_str().and_then(|p| p.parse::<u32>().ok()) != Some(std::process::id())
    {
        return None;
    }
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    (usec > 0).then(|| std::time::Duration::from_micros(usec))
}

#[cfg(unix)]
fn send(socket: &std::ffi::OsStr, message: &[u8]) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixDatagram;
    let raw = socket.as_bytes();
    let sock = UnixDatagram::unbound()?;
    sock.set_nonblocking(true)?;
    match raw.split_first() {
        Some((b'/', _)) => sock.send_to(message, socket).map(drop),
        #[cfg(target_os = "linux")]
        Some((b'@', name)) => {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            sock.send_to_addr(message, &addr).map(drop)
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET is neither a path nor an abstract socket",
        )),
    }
}

#[cfg(not(unix))]
fn send(_socket: &std::ffi::OsStr, _message: &[u8]) -> std::io::Result<()> {
    Ok(())
}
