#![cfg(unix)]

use std::{
    fs,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Exercise the signal used by service managers against the actual executable,
/// including the reporter after the runtime has completed its cleanup.
#[test]
fn sigterm_finishes_server_statistics_and_releases_the_socket() {
    let directory = tempfile::tempdir().unwrap();
    let identity = directory.path().join("identity");
    let binary = env!("CARGO_BIN_EXE_braidpath");
    assert!(
        Command::new(binary)
            .args(["init", "--dir"])
            .arg(&identity)
            .output()
            .unwrap()
            .status
            .success()
    );
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let log = directory.path().join("server.log");
    let stats = directory.path().join("stats.json");
    let mut child = Child(
        Command::new(binary)
            .env("RUST_LOG", "braidpath=info")
            .args([
                "server",
                "--listen",
                &address.to_string(),
                "--target",
                "127.0.0.1:9",
            ])
            .arg("--cert")
            .arg(identity.join("cert.pem"))
            .arg("--key")
            .arg(identity.join("key.pem"))
            .arg("--token-file")
            .arg(identity.join("token"))
            .arg("--stats-file")
            .arg(&stats)
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .unwrap(),
    );
    let result = (|| -> Result<(), String> {
        let until = Instant::now() + Duration::from_secs(8);
        while !fs::read_to_string(&log)
            .unwrap()
            .contains("HTTP/3 server ready")
        {
            if child.0.try_wait().unwrap().is_some() || Instant::now() >= until {
                return Err(format!(
                    "server not ready: {}",
                    fs::read_to_string(&log).unwrap()
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            Command::new("kill")
                .args(["-TERM", &child.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                if !status.success() {
                    return Err(format!("SIGTERM exit: {status}"));
                }
                break;
            }
            if Instant::now() >= until {
                return Err("SIGTERM cleanup timed out".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        let snapshot: serde_json::Value =
            serde_json::from_slice(&fs::read(&stats).unwrap()).unwrap();
        assert_eq!(snapshot["final"], true);
        assert_eq!(snapshot["stats"]["shutdown_complete"], true);
        assert_eq!(snapshot["stats"]["drain_incomplete"], false);
        assert!(std::net::UdpSocket::bind(address).is_ok());
        Ok(())
    })();
    assert!(result.is_ok(), "{}", result.unwrap_err());
}
