//! Startup notification to systemd (`Type=notify`), with no dependencies and no `unsafe` code.
//!
//! The service declares itself ready only once it has loaded its key and trust files and already
//! handles `SIGHUP`: this way systemd never sends a `reload` to a process that would die from it
//! (finding 0004-2).

/// Environment variable holding the notification socket, set by systemd.
const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";

/// Sends `READY=1` to systemd if the service was started with `Type=notify`; otherwise does
/// nothing. An error is not fatal: it is just logged.
pub fn notify_ready() {
    let Some(socket) = std::env::var_os(NOTIFY_SOCKET).filter(|s| !s.is_empty()) else {
        return;
    };
    if let Err(err) = send(&socket, b"READY=1") {
        tracing::warn!(error = %err, "cannot notify systemd");
    }
}

#[cfg(unix)]
fn send(socket: &std::ffi::OsStr, message: &[u8]) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixDatagram;
    let raw = socket.as_bytes();
    let sock = UnixDatagram::unbound()?;
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
