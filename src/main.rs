use bytes::Bytes;
use http_body_util::Full;
use hudsucker::Proxy;
use hudsucker::{
    certificate_authority::OpensslAuthority,
    hyper::{Request, Response},
    openssl::{hash::MessageDigest, pkey::PKey, x509::X509},
    rustls::crypto::aws_lc_rs,
    Body, HttpContext, HttpHandler, RequestOrResponse,
};
use hyper::{StatusCode, Uri};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::create_dir_all;
use std::future::Future;
use std::path::{Path, PathBuf};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "macos")]
use security_framework::{
    certificate::SecCertificate,
    os::macos::keychain::SecKeychain,
    trust_settings::{Domain, TrustSettings},
};

#[derive(Clone)]
struct LogHandler;

impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        println!("{:?}", req.uri());
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        println!("{:?}", res.status());
        res
    }
}

#[derive(Clone)]
struct CacheHandler {
    cache_dir: PathBuf,
    inner: LogHandler,
}

#[derive(Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CacheHandler {
    fn new<P: AsRef<Path>>(cache_dir: P) -> Self {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        // Create cache directory if it doesn't exist
        if !cache_dir.exists() {
            create_dir_all(&cache_dir).expect("Failed to create cache directory");
        }

        Self {
            cache_dir,
            inner: LogHandler,
        }
    }

    fn cache_path(&self, uri: &Uri) -> PathBuf {
        // Extract the host from the URI
        let host = uri.host().unwrap_or("unknown_host").to_string();

        // Create a hash of the URI to use as the filename
        let mut hasher = Sha256::new();
        hasher.update(uri.to_string().as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        // Create host directory and subdirectories based on the first few characters of the hash
        let host_dir = self.cache_dir.join(host);
        let subdir = &hash[0..2];
        let path = host_dir.join(subdir);

        if !path.exists() {
            create_dir_all(&path).expect("Failed to create cache subdirectory");
        }

        path.join(hash)
    }

    async fn is_cached(&self, uri: &Uri) -> bool {
        let path = self.cache_path(uri);
        path.exists()
    }

    async fn get_from_cache(&self, uri: &Uri) -> Option<Response<Body>> {
        let path = self.cache_path(uri);

        match tokio::fs::read(path).await {
            Ok(data) => {
                match bincode::deserialize::<CachedResponse>(&data) {
                    Ok(cached) => {
                        let mut response = Response::builder().status(cached.status);

                        // Add headers
                        for (name, value) in &cached.headers {
                            response = response.header(name, value);
                        }

                        // Create response with body and convert to the expected type
                        match response.body(Full::new(Bytes::from(cached.body))) {
                            Ok(full_response) => {
                                // Convert from Response<Full<Bytes>> to Response<Body>
                                let (parts, full_body) = full_response.into_parts();
                                let body = Body::from(full_body);
                                let res = Response::from_parts(parts, body);

                                info!("Cache hit for {}", uri);
                                Some(res)
                            }
                            Err(_) => None,
                        }
                    }
                    Err(e) => {
                        info!("Failed to deserialize cached response: {}", e);
                        None
                    }
                }
            }
            Err(_) => None,
        }
    }

    async fn save_to_cache(
        &self,
        uri: &Uri,
        res: &Response<Body>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = self.cache_path(uri);

        // Clone the response parts
        let status = res.status().as_u16();

        // Convert headers to a serializable format
        let headers: Vec<(String, String)> = res
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                if let Ok(value_str) = value.to_str() {
                    Some((name.to_string(), value_str.to_string()))
                } else {
                    None
                }
            })
            .collect();

        // We need to get the body bytes, but we can't consume the body
        // This is a limitation - we can only cache responses we can read without consuming
        // For now, we'll create an empty body placeholder
        let body_bytes: Vec<u8> = Vec::new();

        // Create our serializable structure
        let cached = CachedResponse {
            status,
            headers,
            body: body_bytes,
        };

        // Serialize the response
        let serialized = bincode::serialize(&cached)?;

        // Write to file
        tokio::fs::write(path, serialized).await?;
        info!("Cached response for {} (headers only)", uri);

        Ok(())
    }
}

impl HttpHandler for CacheHandler {
    fn handle_request(
        &mut self,
        ctx: &HttpContext,
        req: Request<Body>,
    ) -> impl Future<Output = RequestOrResponse> + Send {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let inner = self.inner.clone();
        let cache_dir = self.cache_dir.clone();

        async move {
            if method == hyper::Method::GET {
                let cache_handler = CacheHandler {
                    cache_dir,
                    inner: inner.clone(),
                };

                if cache_handler.is_cached(&uri).await {
                    if let Some(cached_response) = cache_handler.get_from_cache(&uri).await {
                        return RequestOrResponse::Response(cached_response);
                    }
                }
            }

            let mut inner_handler = inner.clone();
            inner_handler.handle_request(ctx, req).await
        }
    }

    fn handle_response(
        &mut self,
        ctx: &HttpContext,
        res: Response<Body>,
    ) -> impl Future<Output = Response<Body>> + Send {
        // Extract what we need before moving the response
        let status = res.status();
        let inner = self.inner.clone();
        let cache_dir = self.cache_dir.clone();

        // Try to get URI from context or other sources
        // For now, we'll use a placeholder approach
        let uri = Uri::builder()
            .scheme("http")
            .authority(ctx.client_addr.to_string())
            .path_and_query("/")
            .build()
            .unwrap_or_default();

        async move {
            // We can't clone the response, so we need to process it directly
            let mut inner_handler = inner.clone();
            let response = inner_handler.handle_response(ctx, res).await;

            // Only cache successful responses
            if status.is_success() {
                let cache_handler = CacheHandler {
                    cache_dir,
                    inner: inner.clone(),
                };

                if let Err(e) = cache_handler.save_to_cache(&uri, &response).await {
                    error!("Failed to cache response: {:?}", e);
                }
            }

            response
        }
    }

    // Implement the new handle_error method
    fn handle_error(
        &mut self,
        _: &HttpContext,
        err: hyper_util::client::legacy::Error,
    ) -> impl Future<Output = Response<Body>> + Send {
        async move {
            error!("Failed to forward request: {}", err);
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .expect("Failed to build response")
        }
    }

    // Implement the should_intercept method
    fn should_intercept(
        &mut self,
        _ctx: &HttpContext,
        _req: &Request<Body>,
    ) -> impl Future<Output = bool> + Send {
        async { true }
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_target(true)
        .init();

    let ca_private_key_pair = KeyPair::generate()?;
    let mut ca_cert_params =
        CertificateParams::new(vec![]).expect("Failed to create certificate parameters");

    ca_cert_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    ca_cert_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);

    ca_cert_params.distinguished_name = DistinguishedName::new();
    ca_cert_params.distinguished_name.push(
        DnType::CountryName,
        DnValue::PrintableString("US".try_into().unwrap()),
    );
    ca_cert_params.distinguished_name.push(
        DnType::OrganizationName,
        DnValue::PrintableString("Demodel".try_into().unwrap()),
    );
    ca_cert_params.distinguished_name.push(
        DnType::CommonName,
        DnValue::PrintableString("Demodel Proxy CA".try_into().unwrap()),
    );

    ca_cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    // Add key usage extensions
    ca_cert_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // Add extended key usage
    ca_cert_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    let ca_cert = ca_cert_params
        .self_signed(&ca_private_key_pair)
        .expect("Failed to self-sign certificate");

    let ca_private_key_pair_pem = ca_private_key_pair.serialize_pem();
    let ca_private_key_pair_pem_bytes = ca_private_key_pair_pem.as_bytes();
    let ca_cert_pem = ca_cert.pem();
    let ca_cert_pem_bytes = ca_cert_pem.as_bytes();

    let private_key = PKey::private_key_from_pem(ca_private_key_pair_pem_bytes)
        .expect("Failed to parse private key");
    let ca_cert_x509 = X509::from_pem(ca_cert_pem_bytes).expect("Failed to parse CA certificate");

    if cfg!(target_os = "macos") {
        info!("Adding CA certificate to keychain");

        let system_keychain = SecKeychain::default().expect("Failed to open system keychain");
        let ca = SecCertificate::from_der(ca_cert.der()).expect("Failed to parse CA certificate");

        ca.add_to_keychain(Some(system_keychain))
            .expect("Failed to add CA certificate to keychain");

        TrustSettings::new(Domain::Admin)
            .set_trust_settings_always(&ca)
            .expect("Failed to set trust settings");

        info!("Successfully installed self-signed root CA into the system keychain!");
    }

    let ca = OpensslAuthority::new(
        private_key,
        ca_cert_x509,
        MessageDigest::sha256(),
        1_000,
        aws_lc_rs::default_provider(),
    );

    let cache_dir = std::env::current_dir()?.join(".cache");
    let cache_handler = CacheHandler::new(cache_dir);

    let proxy = Proxy::builder()
        .with_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 3128)))
        .with_ca(ca)
        .with_rustls_client(aws_lc_rs::default_provider())
        .with_http_handler(LogHandler)
        .with_http_handler(cache_handler)
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .expect("Failed to create proxy");

    info!("Starting proxy server...");
    proxy.start().await.expect("Failed to start proxy");
    Ok(())
}
