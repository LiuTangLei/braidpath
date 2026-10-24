//! v0.3 TCP wire support for clients during rolling server upgrades.
use super::*;
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) async fn bridge(
    tcp: TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    rate: Option<&Rate>,
) -> Result<()> {
    let (mut read, mut write) = tcp.into_split();
    let active = Mutex::new(Instant::now());
    let copy = async {
        tokio::try_join!(
            pump(&mut read, &mut send, &active, rate),
            pump(&mut recv, &mut write, &active, rate),
        )?;
        Ok(())
    };
    let idle = async {
        loop {
            let deadline = *active.lock().expect("proxy activity") + IDLE_TIMEOUT;
            tokio::time::sleep_until(deadline).await;
            if active.lock().expect("proxy activity").elapsed() >= IDLE_TIMEOUT {
                break;
            }
        }
    };
    tokio::select! { result = copy => result, _ = idle => anyhow::bail!("proxy TCP idle timeout") }
}
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    active: &Mutex<Instant>,
    rate: Option<&Rate>,
) -> Result<()> {
    let mut buf = [0; 16 * 1024];
    loop {
        let n = read.read(&mut buf).await?;
        if n == 0 {
            write.shutdown().await?;
            return Ok(());
        }
        if let Some(rate) = rate {
            rate.acquire(n).await;
        }
        write.write_all(&buf[..n]).await?;
        *active.lock().expect("proxy activity") = Instant::now();
    }
}
