use super::*;
use std::process::Command;
use tokio::signal::unix::{SignalKind, signal};

#[test]
fn interrupt_between_waits_remains_pending() {
    const CHILD: &str = "BRAIDPATH_SHUTDOWN_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::tunnel::shutdown_tests::interrupt_between_waits_remains_pending",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    // Isolate the actual OS signal from every other test in the parent process.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut shutdown = Shutdown::new();
            // Another select branch wins after shutdown has subscribed. Its
            // temporary wait future is cancelled while that branch runs.
            poll_fn(|cx| {
                assert!(Box::pin(shutdown.wait()).as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            let mut witness = signal(SignalKind::interrupt()).unwrap();
            assert!(
                Command::new("kill")
                    .args(["-INT", &std::process::id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            // Confirm the OS signal was processed before entering the next
            // select iteration, instead of relying on a scheduling race.
            timeout(Duration::from_secs(2), witness.recv())
                .await
                .unwrap();
            timeout(Duration::from_millis(250), shutdown.wait())
                .await
                .expect("interrupt during another branch must remain pending");
        });
}
