use demodel::{certificate::create_or_load_certificate_authority, proxy::setup_proxy};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_target(true)
        .init();

    let ca = create_or_load_certificate_authority()?;
    let proxy = setup_proxy(ca).await?;

    info!("Starting proxy server...");
    proxy.start().await.expect("Failed to start proxy");

    Ok(())
}
