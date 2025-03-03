use bytes::Bytes;
use directories::ProjectDirs;
use http_body_util::Full;
use hudsucker::Proxy;
use hudsucker::{
    certificate_authority::OpensslAuthority,
    hyper::{Request, Response},
    openssl::{hash::MessageDigest, pkey::PKey, pkey::Private, x509::X509},
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
use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::{env, fs};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct LogHandler;

impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        info!("{:?}", req.uri());
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        info!("{:?}", res.status());
        res
    }
}

#[derive(Clone)]
struct ProxyConfig {
    mirrors: HashMap<String, String>,
}

impl ProxyConfig {
    fn new() -> Self {
        let mut mirrors = HashMap::new();

        if let Ok(mirror_url) = env::var("HF_MIRROR_URL") {
            mirrors.insert("huggingface.co".to_string(), mirror_url);
        } else {
            if env::var("USE_HF_MIRROR").is_ok() {
                mirrors.insert(
                    "huggingface.co".to_string(),
                    "https://hf-mirror.com".to_string(),
                );
            }
        }

        Self { mirrors }
    }

    fn get_mirror_for_host(&self, host: &str) -> Option<String> {
        self.mirrors.get(host).cloned()
    }
}

#[derive(Clone)]
struct CacheHandler {
    cache_dir: PathBuf,
    inner: LogHandler,
    proxy_config: ProxyConfig,
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
            proxy_config: ProxyConfig::new(),
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
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let method = req.method().clone();
        let uri = req.uri().clone();

        // Check cache first using original URI
        if method == hyper::Method::GET {
            if self.is_cached(&uri).await {
                if let Some(cached_response) = self.get_from_cache(&uri).await {
                    return RequestOrResponse::Response(cached_response);
                }
            }
        }

        // If we need to rewrite the request, we'll need to convert it to parts,
        // modify the URI, and rebuild it
        if let Some(host) = uri.host() {
            if let Some(mirror_url) = self.proxy_config.get_mirror_for_host(host) {
                // Convert request to parts
                let (mut parts, body) = req.into_parts();

                // Try to create a new URI with the mirror
                if let Ok(mirror_uri) = mirror_url.parse::<Uri>() {
                    if let Ok(new_uri) = Uri::builder()
                        .scheme(mirror_uri.scheme_str().unwrap_or("https"))
                        .authority(mirror_uri.authority().unwrap().clone())
                        .path_and_query(uri.path_and_query().unwrap().clone())
                        .build()
                    {
                        // Update URI in parts
                        parts.uri = new_uri;

                        // Add original host header
                        if let Ok(host_value) = hyper::header::HeaderValue::from_str(host) {
                            parts.headers.insert(hyper::header::HOST, host_value);
                        }

                        // Rebuild request
                        let modified_req = Request::from_parts(parts, body);
                        info!(
                            "Rewritten request to mirror: {} -> {}",
                            uri,
                            modified_req.uri()
                        );
                        return RequestOrResponse::Request(modified_req);
                    }
                }

                // If we got here, something went wrong with rewriting
                // Rebuild the original request and continue
                let original_req = Request::from_parts(parts, body);
                return RequestOrResponse::Request(original_req);
            }
        }

        // No rewriting needed, return the original request
        RequestOrResponse::Request(req)
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
                    proxy_config: self.proxy_config.clone(),
                };

                if let Err(e) = cache_handler.save_to_cache(&uri, &response).await {
                    error!("Failed to cache response: {:?}", e);
                }
            }

            response
        }
    }

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

#[cfg(target_os = "macos")]
fn has_ca_certificate() -> Result<bool, security_framework::base::Error> {
    use security_framework::item::{ItemClass, ItemSearchOptions, Reference, SearchResult};
    use security_framework::os::macos::certificate::SecCertificateExt;
    use security_framework::os::macos::{item::ItemSearchOptionsExt, keychain::SecKeychain};

    let system_keychain = match SecKeychain::default() {
        Ok(keychain) => keychain,
        Err(e) => {
            error!("Failed to open system keychain: {}", e);
            return Err(e);
        }
    };

    // Create search options for certificates
    let mut options = ItemSearchOptions::new();
    options.keychains(&[system_keychain]);
    options.limit(100); // Limit to avoid too many results
    options.class(ItemClass::certificate());

    let search_results = options.search().expect("Failed to search for certificates");

    for item in search_results {
        if let SearchResult::Ref(cert_ref) = item {
            if let Reference::Certificate(cert) = cert_ref {
                if cert.common_name().unwrap_or_default() == "Demodel Proxy CA" {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

// Function to get the config directory path
fn get_config_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Try to get XDG_CONFIG_HOME first (Linux/macOS)
    if let Ok(config_home) = env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(config_home).join("demodel"));
    }

    // Fall back to platform-specific directories
    if let Some(proj_dirs) = ProjectDirs::from("com.github", "moeru-ai", "demodel") {
        return Ok(proj_dirs.config_dir().to_path_buf());
    }

    Err("Could not determine config directory".into())
}

// Function to save certificate and private key
fn save_ca_certificate_and_key(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let config_dir = get_config_dir()?;
    let pki_dir = config_dir.join("pki");

    // Create directories if they don't exist
    fs::create_dir_all(&pki_dir)?;

    // Save certificate
    let cert_path = pki_dir.join("ca.crt");
    let mut cert_file = File::create(&cert_path)?;
    cert_file.write_all(cert_pem)?;
    info!("Saved CA certificate to {}", cert_path.display());

    // Save private key
    let key_path = pki_dir.join("ca.pem");
    let mut key_file = File::create(&key_path)?;
    key_file.write_all(key_pem)?;
    info!("Saved CA private key to {}", key_path.display());

    // Set appropriate permissions for private key on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600); // Read/write for owner only
        fs::set_permissions(&key_path, perms)?;
    }

    Ok(pki_dir)
}

#[cfg(target_os = "macos")]
fn install_ca_certificate(ca_cert: &X509) -> Result<(), Box<dyn std::error::Error>> {
    use security_framework::{
        certificate::SecCertificate,
        os::macos::keychain::SecKeychain,
        trust_settings::{Domain, TrustSettings},
    };
    info!("Adding CA certificate to keychain");

    let system_keychain = SecKeychain::default().expect("Failed to open system keychain");
    let ca = SecCertificate::from_der(&ca_cert.to_der().expect("Failed to encode into DER"))
        .expect("Failed to parse CA certificate");

    ca.add_to_keychain(Some(system_keychain))
        .expect("Failed to add CA certificate to keychain");

    TrustSettings::new(Domain::Admin)
        .set_trust_settings_always(&ca)
        .expect("Failed to set trust settings");

    info!("Successfully installed self-signed Root CA into the system keychain!");

    Ok(())
}

// Function to check if certificate files exist
fn certificate_files_exist() -> bool {
    if let Ok(config_dir) = get_config_dir() {
        let cert_path = config_dir.join("pki").join("ca.crt");
        let key_path = config_dir.join("pki").join("ca.pem");

        return cert_path.exists() && key_path.exists();
    }

    false
}

// Function to load existing certificate and key
fn load_ca_certificate_and_key() -> Result<(X509, PKey<Private>), Box<dyn std::error::Error>> {
    let config_dir = get_config_dir()?;
    let cert_path = config_dir.join("pki").join("ca.crt");
    let key_path = config_dir.join("pki").join("ca.pem");

    // Read certificate file
    let mut cert_file = File::open(cert_path)?;
    let mut cert_pem = Vec::new();
    cert_file.read_to_end(&mut cert_pem)?;

    // Read key file
    let mut key_file = File::open(key_path)?;
    let mut key_pem = Vec::new();
    key_file.read_to_end(&mut key_pem)?;

    // Parse certificate and key
    let cert = X509::from_pem(&cert_pem)?;
    let key = PKey::private_key_from_pem(&key_pem)?;

    Ok((cert, key))
}

// Function to generate and save CA certificate and key
fn generate_ca_certificate_and_key(
) -> Result<(X509, PKey<Private>, PathBuf), Box<dyn std::error::Error>> {
    // Generate a new key pair
    let ca_private_key_pair = KeyPair::generate()?;
    let mut ca_cert_params = CertificateParams::new(vec![])?;

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

    let ca_cert = ca_cert_params.self_signed(&ca_private_key_pair)?;

    let ca_private_key_pair_pem = ca_private_key_pair.serialize_pem();
    let ca_private_key_pair_pem_bytes = ca_private_key_pair_pem.as_bytes();
    let ca_cert_pem = ca_cert.pem();
    let ca_cert_pem_bytes = ca_cert_pem.as_bytes();

    // Parse with OpenSSL for compatibility
    let private_key = PKey::private_key_from_pem(ca_private_key_pair_pem_bytes)?;
    let ca_cert_x509 = X509::from_pem(ca_cert_pem_bytes)?;

    // Save certificate and key
    let pki_dir = save_ca_certificate_and_key(ca_cert_pem_bytes, ca_private_key_pair_pem_bytes)?;

    Ok((ca_cert_x509, private_key, pki_dir))
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

    // Check if we need to generate a new certificate
    let need_new_certificate = {
        #[cfg(target_os = "macos")]
        {
            !(has_ca_certificate().unwrap_or_default()) && !certificate_files_exist()
        }

        #[cfg(not(target_os = "macos"))]
        {
            !certificate_files_exist()
        }
    };

    // Get or generate certificate and key
    let (ca_cert_x509, private_key, pki_dir) = if need_new_certificate {
        info!("Generating new CA certificate and key...");
        generate_ca_certificate_and_key()?
    } else {
        info!("Using existing CA certificate and key...");
        let (cert, key) = load_ca_certificate_and_key()?;
        let config_dir = get_config_dir()?;
        (cert, key, config_dir.join("pki"))
    };

    // On macOS, install the certificate to the keychain if needed
    #[cfg(target_os = "macos")]
    {
        if need_new_certificate {
            install_ca_certificate(&ca_cert_x509)
                .expect("Failed to install CA certificate to keychain");

            info!(
                "Successfully installed CA certificate to keychain, stored in {}",
                pki_dir.display()
            );
        }
    }

    #[cfg(target_os = "windows")]
    {
        info!("On Windows, you may need to manually import the certificate.");
        info!("Certificate saved to: {}", pki_dir.join("ca.crt").display());
        info!(
            "You can import it using: certutil -addstore -f \"ROOT\" {}",
            pki_dir.join("ca.crt").display()
        );
    }

    #[cfg(target_os = "linux")]
    {
        info!("On Linux, you may need to manually import the certificate.");
        info!("Certificate saved to: {}", pki_dir.join("ca.crt").display());
        info!("You can import it using your distribution's certificate manager.");
        info!("For example, on Ubuntu/Debian: sudo cp {} /usr/local/share/ca-certificates/ && sudo update-ca-certificates",
              pki_dir.join("ca.crt").display());
    }

    let ca = OpensslAuthority::new(
        private_key,
        ca_cert_x509,
        MessageDigest::sha256(),
        1_000,
        aws_lc_rs::default_provider(),
    );

    // Log proxy configuration
    if let Ok(http_proxy) = env::var("HTTP_PROXY") {
        info!("Using HTTP_PROXY: {}", http_proxy);
    }
    if let Ok(https_proxy) = env::var("HTTPS_PROXY") {
        info!("Using HTTPS_PROXY: {}", https_proxy);
    }
    if let Ok(no_proxy) = env::var("NO_PROXY") {
        info!("Using NO_PROXY: {}", no_proxy);
    }

    let cache_dir = std::env::current_dir()?.join(".cache");
    let cache_handler = CacheHandler::new(cache_dir);

    let proxy = Proxy::builder()
        .with_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 3128)))
        .with_ca(ca)
        .with_rustls_client(aws_lc_rs::default_provider())
        .with_http_handler(cache_handler)
        .with_http_handler(LogHandler)
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .expect("Failed to create proxy");

    info!("Starting proxy server...");
    proxy.start().await.expect("Failed to start proxy");
    Ok(())
}
