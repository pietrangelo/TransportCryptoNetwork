//! End-to-end with real OpenSSH and Ansible: `ssh`/`scp`/`ansible-playbook` use `zt-client`
//! as `ProxyCommand` toward an `sshd` reachable only by the agent.
//!
//! They require `sshd`, `ssh`, `scp`, `ssh-keygen` and `ansible-playbook`; they are marked
//! `#[ignore]` and run in the `e2e-openssh` CI job with `cargo test -- --ignored`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::similar_names
)]

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use common::{BIN, ClientDir, Fleet, set_mode};
use tokio::process::{Child, Command};

const NEEDS: &str = "needs OpenSSH (sshd, ssh, scp, ssh-keygen) and ansible-playbook";

fn sshd_path() -> PathBuf {
    for p in ["/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"] {
        if Path::new(p).exists() {
            return p.into();
        }
    }
    panic!("sshd not found");
}

async fn run(cmd: &mut Command) -> std::process::Output {
    tokio::time::timeout(Duration::from_secs(120), cmd.output())
        .await
        .expect("command timed out")
        .unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// sshd on 127.0.0.1 (free port), relay and agent in-process, ssh configuration ready.
struct Lab {
    fleet: Fleet,
    _client: ClientDir,
    dir: PathBuf,
    ssh_config: PathBuf,
    _sshd: Child,
}

impl Lab {
    async fn start() -> Self {
        Self::start_with(false).await
    }

    /// With `hybrid`, the agent accepts both suites and the client pins the hybrid one for
    /// `web-01` (PQ-1); the relay is configured as always.
    async fn start_with(hybrid: bool) -> Self {
        let fleet = Fleet::start().await;
        let client = fleet.client_dir(&fleet.ansible);
        if hybrid {
            client.pin_last_node_suite("Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s");
        }
        let dir = client.dir.join("ssh");
        std::fs::create_dir_all(&dir).unwrap();
        let keygen = |name: &str| {
            let path = dir.join(name);
            async move {
                let out = run(Command::new("ssh-keygen")
                    .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                    .arg(&path))
                .await;
                assert!(out.status.success(), "{}", text(&out.stderr));
            }
        };
        keygen("host_key").await;
        keygen("user_key").await;
        std::fs::copy(dir.join("user_key.pub"), dir.join("authorized_keys")).unwrap();
        set_mode(&dir.join("authorized_keys"), 0o600);

        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let sshd_config = dir.join("sshd_config");
        std::fs::write(
            &sshd_config,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/host_key\nPidFile {d}/sshd.pid\n\
                 AuthorizedKeysFile {d}/authorized_keys\nPasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\nPubkeyAuthentication yes\nUsePAM no\nStrictModes no\n\
                 PermitRootLogin prohibit-password\nSubsystem sftp internal-sftp\nLogLevel ERROR\n",
                d = dir.display()
            ),
        )
        .unwrap();
        // sshd started as root requires the privilege separation directory.
        let _ = std::fs::create_dir_all("/run/sshd");
        let sshd = Command::new(sshd_path())
            .args(["-D", "-e", "-f"])
            .arg(&sshd_config)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if hybrid {
            fleet
                .start_agent_with(
                    addr,
                    zt_domain::AcceptedSuites::new([
                        zt_domain::HandshakeSuite::NoiseIk25519,
                        zt_domain::HandshakeSuite::NoiseIkhfs25519MlKem768,
                    ])
                    .unwrap(),
                )
                .await;
        } else {
            fleet.start_agent(addr).await;
        }

        let host_pub = std::fs::read_to_string(dir.join("host_key.pub")).unwrap();
        std::fs::write(dir.join("known_hosts"), format!("web-01 {host_pub}")).unwrap();
        let user = text(&run(Command::new("id").arg("-un")).await.stdout)
            .trim()
            .to_owned();
        let ssh_config = dir.join("ssh_config");
        std::fs::write(
            &ssh_config,
            format!(
                "Host web-01\n  User {user}\n  IdentityFile {d}/user_key\n  IdentitiesOnly yes\n\
                 UserKnownHostsFile {d}/known_hosts\n  GlobalKnownHostsFile /dev/null\n\
                 StrictHostKeyChecking yes\n  BatchMode yes\n  ControlMaster no\n  ControlPath none\n\
                 ProxyCommand {bin} --config {cfg} connect %n\n",
                d = dir.display(),
                bin = BIN,
                cfg = client.config().display()
            ),
        )
        .unwrap();
        Self {
            fleet,
            _client: client,
            dir,
            ssh_config,
            _sshd: sshd,
        }
    }

    fn ssh(&self) -> Command {
        let mut c = Command::new("ssh");
        c.arg("-F").arg(&self.ssh_config).arg("web-01");
        c
    }
}

async fn sha256(path: &Path) -> String {
    let out = run(Command::new("sha256sum").arg(path)).await;
    text(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

fn random_file(path: &Path, len: usize) {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let data: Vec<u8> = (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(path, data).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs OpenSSH (sshd, ssh, scp, ssh-keygen) and ansible-playbook"]
async fn ssh_runs_a_command_through_tcn() {
    let lab = Lab::start().await;
    let out = run(lab.ssh().arg("echo tcn-ok")).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "tcn-ok\n");
}

/// PQ-1: real OpenSSH over the hybrid end-to-end suite, through an unchanged relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs OpenSSH (sshd, ssh, scp, ssh-keygen) and ansible-playbook"]
async fn ssh_runs_a_command_over_the_hybrid_suite() {
    let lab = Lab::start_with(true).await;
    let out = run(lab.ssh().arg("echo tcn-pq-ok")).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "tcn-pq-ok\n");
    let upload = lab.dir.join("pq-upload.bin");
    random_file(&upload, 4 * 1024 * 1024);
    let out = run(lab
        .ssh()
        .arg("sha256sum")
        .stdin(std::fs::File::open(&upload).unwrap()))
    .await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let remote = text(&out.stdout);
    assert_eq!(
        remote.split_whitespace().next().unwrap(),
        sha256(&upload).await
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs OpenSSH (sshd, ssh, scp, ssh-keygen) and ansible-playbook"]
async fn bulk_upload_download_and_scp_are_byte_exact() {
    let lab = Lab::start().await;
    let file = lab.dir.join("blob");
    random_file(&file, 8 * 1024 * 1024 + 3);
    let local = sha256(&file).await;

    let up = run(lab
        .ssh()
        .arg("sha256sum")
        .stdin(std::fs::File::open(&file).unwrap()))
    .await;
    assert!(up.status.success(), "{}", text(&up.stderr));
    assert!(text(&up.stdout).starts_with(&local), "upload corrupted");

    let down = run(lab.ssh().arg(format!("cat {}", file.display()))).await;
    assert!(down.status.success());
    assert_eq!(
        down.stdout,
        std::fs::read(&file).unwrap(),
        "download corrupted"
    );

    let copy = lab.dir.join("copy");
    let scp = run(Command::new("scp")
        .arg("-q")
        .arg("-F")
        .arg(&lab.ssh_config)
        .arg(&file)
        .arg(format!("web-01:{}", copy.display())))
    .await;
    assert!(scp.status.success(), "{}", text(&scp.stderr));
    assert_eq!(sha256(&copy).await, local);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs OpenSSH (sshd, ssh, scp, ssh-keygen) and ansible-playbook"]
async fn parallel_ssh_sessions() {
    let lab = Lab::start().await;
    let mut tasks = Vec::new();
    for i in 0..6 {
        let mut cmd = lab.ssh();
        cmd.arg(format!("echo session-{i}"));
        tasks.push(tokio::spawn(async move { (i, run(&mut cmd).await) }));
    }
    for t in tasks {
        let (i, out) = t.await.unwrap();
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(text(&out.stdout), format!("session-{i}\n"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs OpenSSH (sshd, ssh, scp, ssh-keygen) and ansible-playbook"]
async fn ssh_host_key_verification_still_applies_end_to_end() {
    // TCN does not replace SSH authentication: a host key different from the known one fails.
    let lab = Lab::start().await;
    let other = lab.dir.join("other_key");
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&other))
    .await;
    let other_pub = std::fs::read_to_string(other.with_extension("pub")).unwrap();
    std::fs::write(lab.dir.join("known_hosts"), format!("web-01 {other_pub}")).unwrap();
    let out = run(lab.ssh().arg("echo should-not-run")).await;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs OpenSSH (sshd, ssh, scp, ssh-keygen) and ansible-playbook"]
async fn ansible_playbook_runs_through_tcn() {
    let lab = Lab::start().await;
    let d = &lab.dir;
    std::fs::write(
        d.join("inventory.ini"),
        "[fleet]\nweb-01 ansible_python_interpreter=/usr/bin/python3\n",
    )
    .unwrap();
    std::fs::write(
        d.join("ansible.cfg"),
        format!(
            "[defaults]\nhost_key_checking = True\nlocal_tmp = {d}/ansible-local\nremote_tmp = /tmp/.tcn-ansible\n\
             [ssh_connection]\nssh_args = -F {cfg} -o ControlMaster=auto -o ControlPersist=5s -o ControlPath={d}/cm-%%C\npipelining = True\n",
            d = d.display(),
            cfg = lab.ssh_config.display()
        ),
    )
    .unwrap();
    std::fs::write(
        d.join("play.yml"),
        format!(
            "- hosts: fleet\n  gather_facts: true\n  tasks:\n\
             \x20   - ansible.builtin.ping:\n\
             \x20   - ansible.builtin.copy:\n        content: \"deployed via tcn\\n\"\n        dest: {d}/deployed.txt\n\
             \x20   - ansible.builtin.command: cat {d}/deployed.txt\n      register: r\n\
             \x20   - ansible.builtin.assert:\n        that: r.stdout == 'deployed via tcn'\n\
             \x20   - ansible.builtin.fetch:\n        src: {d}/deployed.txt\n        dest: {d}/fetched/\n        flat: true\n",
            d = d.display()
        ),
    )
    .unwrap();
    let out = run(Command::new("ansible-playbook")
        .arg("-i")
        .arg(d.join("inventory.ini"))
        .arg(d.join("play.yml"))
        .env("ANSIBLE_CONFIG", d.join("ansible.cfg"))
        .env("ANSIBLE_HOME", d.join("ansible-home"))
        .env("ANSIBLE_NOCOLOR", "1"))
    .await;
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "{stdout}\n{}", text(&out.stderr));
    assert!(
        stdout.contains("failed=0") && stdout.contains("unreachable=0"),
        "{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(d.join("fetched/deployed.txt")).unwrap(),
        "deployed via tcn\n"
    );
    let _ = (&lab.fleet, NEEDS);
}
