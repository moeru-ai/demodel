use hudsucker::openssl::{pkey::PKey, pkey::Private, x509::X509};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use tracing::info;

use crate::utils::paths::get_config_dir;

// Function to check if certificate files exist
pub fn certificate_files_exist() -> bool {
    if let Ok(config_dir) = get_config_dir() {
        let cert_path = config_dir.join("pki").join("ca.crt");
        let key_path = config_dir.join("pki").join("ca.pem");

        return cert_path.exists() && key_path.exists();
    }

    false
}

// Function to load existing certificate and key
pub fn load_ca_certificate_and_key() -> Result<(X509, PKey<Private>), Box<dyn std::error::Error>> {
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

// Function to save certificate and private key
pub fn save_ca_certificate_and_key(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let config_dir = get_config_dir()?;
    let pki_dir = config_dir.join("pki");

    // Create directories if they don't exist
    create_dir_all(&pki_dir)?;

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
        let mut perms = std::fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600); // Read/write for owner only
        std::fs::set_permissions(&key_path, perms)?;
    }

    Ok(pki_dir)
}

// Function to generate and save CA certificate and key
pub fn generate_ca_certificate_and_key(
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
