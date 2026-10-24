#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // quinn-udp drops datagrams the OS refuses to send (for
                // example ENOBUFS) and warns at most once a minute.
                .unwrap_or_else(|_| "braidpath=info,quinn_udp=warn".into()),
        )
        .init();
    braidpath::runtime::cli::run().await
}
