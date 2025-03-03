mod cache;
mod config;
mod handler;

use hudsucker::{
    certificate_authority::OpensslAuthority, rustls::crypto::aws_lc_rs, NoopHandler, Proxy,
};
use hyper_util::client::legacy::connect::Connect;
use std::{future::Future, net::SocketAddr};

pub use cache::CacheHandler;
pub use config::ProxyConfig;
pub use handler::LogHandler;

// Log proxy configuration from environment variables
fn log_proxy_environment() {
    use std::env;
    use tracing::info;

    if let Ok(http_proxy) = env::var("HTTP_PROXY") {
        info!("Using HTTP_PROXY: {}", http_proxy);
    }
    if let Ok(https_proxy) = env::var("HTTPS_PROXY") {
        info!("Using HTTPS_PROXY: {}", https_proxy);
    }
    if let Ok(no_proxy) = env::var("NO_PROXY") {
        info!("Using NO_PROXY: {}", no_proxy);
    }
}

// Function to set up the proxy with the given certificate authority
pub async fn setup_proxy(
    ca: OpensslAuthority,
) -> Result<
    Proxy<
        impl Connect + Clone,
        OpensslAuthority,
        CacheHandler,
        NoopHandler,
        impl Future<Output = ()>,
    >,
    Box<dyn std::error::Error>,
> {
    // Create cache handler
    let cache_dir = std::env::current_dir()?.join(".cache");
    let cache_handler = CacheHandler::new(cache_dir);

    // Log proxy environment variables
    log_proxy_environment();

    // Build and return the proxy
    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 3128)))
        .with_ca(ca)
        .with_rustls_client(aws_lc_rs::default_provider())
        .with_http_handler(cache_handler)
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .expect("Failed to create proxy");

    Ok(proxy)
}

// Signal handler for graceful shutdown
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}
