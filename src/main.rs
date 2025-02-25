use hudsucker::Proxy;
use hudsucker::{
    certificate_authority::OpensslAuthority,
    hyper::{Request, Response},
    openssl::{hash::MessageDigest, pkey::PKey, x509::X509},
    rustls::crypto::aws_lc_rs,
    Body, HttpContext, HttpHandler, RequestOrResponse,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, DnValue, KeyPair};
#[cfg(target_os = "macos")]
use security_framework::{
    certificate::SecCertificate,
    os::macos::keychain::SecKeychain,
    trust_settings::{Domain, TrustSettings},
};
use tracing::info;
use tracing_subscriber::EnvFilter;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Clone)]
struct LogHandler;

impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        println!("{:?}", req);
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        println!("{:?}", res);
        res
    }
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

    let subject_alt_names = vec!["localhost".to_string()];
    let key_pair = KeyPair::generate()?;
    let mut cert_params =
        CertificateParams::new(subject_alt_names).expect("Failed to create certificate parameters");

    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        DnValue::PrintableString("demodel certificate".try_into().unwrap()),
    );
    cert_params.distinguished_name = dn;

    let cert = cert_params
        .self_signed(&key_pair)
        .expect("Failed to self-sign certificate");

    let generated_private_key = key_pair.serialize_pem();
    let private_key_bytes = generated_private_key.as_bytes();
    let generated_ca_cert = cert.pem();
    let ca_cert_bytes = generated_ca_cert.as_bytes();

    let private_key =
        PKey::private_key_from_pem(private_key_bytes).expect("Failed to parse private key");
    let ca_cert = X509::from_pem(ca_cert_bytes).expect("Failed to parse CA certificate");

    if cfg!(target_os = "macos") {
        info!("Adding CA certificate to keychain");

        let system_keychain = SecKeychain::default().expect("Failed to open system keychain");
        let ca = SecCertificate::from_der(cert.der()).expect("Failed to parse CA certificate");
        ca.add_to_keychain(Some(system_keychain))
            .expect("Failed to add CA certificate to keychain");
        TrustSettings::new(Domain::Admin)
            .set_trust_settings_always(&ca)
            .expect("Failed to set trust settings");

        info!("Successfully installed self-signed root CA into the system keychain!");
    }

    let ca = OpensslAuthority::new(
        private_key,
        ca_cert,
        MessageDigest::sha256(),
        1_000,
        aws_lc_rs::default_provider(),
    );

    let proxy = Proxy::builder()
        .with_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 3128)))
        .with_ca(ca)
        .with_rustls_client(aws_lc_rs::default_provider())
        .with_http_handler(LogHandler)
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .expect("Failed to create proxy");

    info!("Starting proxy server...");
    proxy.start().await.expect("Failed to start proxy");
    Ok(())
}
