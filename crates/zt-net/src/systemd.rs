//! Notifica di avvio a systemd (`Type=notify`), senza dipendenze e senza codice `unsafe`.
//!
//! Il servizio si dichiara pronto solo quando ha caricato chiave e file di trust e gestisce già
//! `SIGHUP`: così systemd non invia un `reload` a un processo che ne morirebbe (finding 0004-2).

/// Variabile d'ambiente con il socket di notifica, impostata da systemd.
const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";

/// Invia `READY=1` a systemd se il servizio è stato avviato con `Type=notify`; altrimenti non
/// fa nulla. Un errore non è fatale: lo registra e basta.
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
