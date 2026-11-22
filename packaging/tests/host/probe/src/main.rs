//! Sandbox probe: what can code running inside the relay's unit do?
//!
//! Each attempt prints one JSON line `{"probe":…,"result":"allowed"|"denied","detail":…}`;
//! `packaging/tests/host/systemd-e2e.sh` asserts on them. The probe judges nothing itself.
#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Threads the probe tries to start at most (the unit allows 512 tasks).
const MAX_THREADS: usize = 4096;

fn line(probe: &str, result: &str, detail: &str) {
    let mut out = io::stdout().lock();
    // A failed write has nowhere to be reported.
    let _ = writeln!(
        out,
        "{{\"probe\":\"{probe}\",\"result\":\"{result}\",\"detail\":\"{detail}\"}}"
    );
    let _ = out.flush();
}

fn report(probe: &str, outcome: io::Result<()>) {
    match outcome {
        Ok(()) => line(probe, "allowed", "ok"),
        Err(e) => {
            let detail = match e.raw_os_error() {
                Some(code) => format!("errno {code} {:?}", e.kind()),
                None => format!("{:?}", e.kind()),
            };
            line(probe, "denied", &detail);
        }
    }
}

fn connect(addr: &str) -> io::Result<()> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map(drop)
}

fn bind(addr: &str) -> io::Result<()> {
    TcpListener::bind(addr).map(drop)
}

fn write(path: &str) -> io::Result<()> {
    std::fs::write(path, b"x")
}

fn exec(path: &str) -> io::Result<()> {
    Command::new(path).arg("-c").arg("true").status().map(drop)
}

/// Starts threads that wait on one lock until the kernel refuses one; reports how many ran.
fn threads() {
    let gate = Arc::new(Mutex::new(()));
    let held = gate.lock();
    let mut handles = Vec::new();
    let mut refused = None;
    for _ in 0..MAX_THREADS {
        let gate = Arc::clone(&gate);
        let spawned = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || drop(gate.lock()));
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => {
                refused = Some(e);
                break;
            }
        }
    }
    let started = handles.len();
    drop(held);
    for h in handles {
        let _ = h.join();
    }
    match refused {
        Some(e) => line(
            "threads",
            "denied",
            &format!("{started} threads, then {:?}", e.kind()),
        ),
        None => line("threads", "allowed", &format!("{started} threads")),
    }
}

fn main() {
    report("exec_sh", exec("/bin/sh"));
    report("exec_usr_bin_env", exec("/usr/bin/env"));
    // The test script runs a root listener there: only the firewall stands in the way.
    report("connect_loopback", connect("127.0.0.1:2222"));
    report("connect_metadata", connect("169.254.169.254:80"));
    report("bind_other_port", bind("0.0.0.0:8080"));
    report("bind_relay_port", bind("0.0.0.0:7443"));
    report("write_etc_tcn", write("/etc/tcn/probe"));
    report("write_usr_local_bin", write("/usr/local/bin/probe"));
    threads();
}
