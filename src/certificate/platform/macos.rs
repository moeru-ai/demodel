use hudsucker::openssl::x509::X509;
use security_framework::{
    certificate::SecCertificate,
    item::{ItemClass, ItemSearchOptions, Reference, SearchResult},
    os::macos::{
        certificate::SecCertificateExt, item::ItemSearchOptionsExt, keychain::SecKeychain,
    },
    trust_settings::{Domain, TrustSettings},
};
use tracing::error;

// Check if CA certificate is already installed in keychain
pub fn has_ca_certificate() -> Result<bool, security_framework::base::Error> {
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

// Install CA certificate to keychain
pub fn install_ca_certificate(ca_cert: &X509) -> Result<(), Box<dyn std::error::Error>> {
    use tracing::info;
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
