//! One process-lifetime interrupt subscription, retained across select branches.
use std::{future::Future, pin::Pin};

/// Dropping a temporary wait must not drop the underlying signal subscription.
/// In particular, a signal arriving while a UDP branch is running must still
/// be observed when the next iteration resumes the wait.
pub(super) struct Shutdown(Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>);

impl Shutdown {
    pub(super) fn new() -> Self {
        Self(Box::pin(tokio::signal::ctrl_c()))
    }

    pub(super) async fn wait(&mut self) {
        let _ = self.0.as_mut().await;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{future::poll_fn, process::Command, task::Poll, time::Duration};
    use tokio::{
        signal::unix::{SignalKind, signal},
        time::timeout,
    };

    #[test]
    fn retained_subscription_survives_a_signal_between_select_iterations() {
        const CHILD: &str = "BRAIDPATH_RELAY_INTERRUPT_REPRO_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "runtime::shutdown::tests::retained_subscription_survives_a_signal_between_select_iterations", "--nocapture"])
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
        // Only the isolated child receives SIGINT; no signal reaches the suite.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut retained = Shutdown::new();
                poll_fn(|cx| {
                    assert!(Box::pin(retained.wait()).as_mut().poll(cx).is_pending());
                    // Negative control: the relay's former per-iteration future.
                    assert!(
                        Box::pin(tokio::signal::ctrl_c())
                            .as_mut()
                            .poll(cx)
                            .is_pending()
                    );
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
                timeout(Duration::from_secs(2), witness.recv())
                    .await
                    .unwrap();
                // The signal has been dispatched while another branch was active.
                // Re-subscribing cannot recover it; the retained listener can.
                assert!(
                    timeout(Duration::from_millis(50), tokio::signal::ctrl_c())
                        .await
                        .is_err()
                );
                timeout(Duration::from_millis(250), retained.wait())
                    .await
                    .expect("one SIGINT must survive a cancelled select wait");
                eprintln!("single SIGINT: recreated listener missed; retained listener delivered");
            });
    }
}
