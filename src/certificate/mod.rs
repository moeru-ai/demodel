mod authority;
mod platform;

use hudsucker::{
    certificate_authority::OpensslAuthority, openssl::hash::MessageDigest,
    rustls::crypto::aws_lc_rs,
};
use tracing::info;

pub use authority::{
    certificate_files_exist, generate_ca_certificate_and_key, load_ca_certificate_and_key,
    save_ca_certificate_and_key,
};
pub use platform::install_ca_certificate;

// Create or load certificate authority
pub fn create_or_load_certificate_authority() -> Result<OpensslAuthority, Box<dyn std::error::Error>>
{
    // Check if we need to generate a new certificate
    let need_new_certificate = {
        #[cfg(target_os = "macos")]
        {
            !(platform::macos::has_ca_certificate().unwrap_or_default())
                && !certificate_files_exist()
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
        let config_dir = crate::utils::paths::get_config_dir()?;
        (cert, key, config_dir.join("pki"))
    };

    // On macOS, install the certificate to the keychain if needed
    #[cfg(target_os = "macos")]
    {
        if need_new_certificate {
            platform::macos::install_ca_certificate(&ca_cert_x509)
                .expect("Failed to install CA certificate to keychain");

            info!(
                "Successfully installed CA certificate to keychain, stored in {}",
                pki_dir.display()
            );
        }
    }

    // Display platform-specific instructions
    platform::display_certificate_instructions(&pki_dir);

    // Create and return the certificate authority
    let ca = OpensslAuthority::new(
        private_key,
        ca_cert_x509,
        MessageDigest::sha256(),
        1_000,
        aws_lc_rs::default_provider(),
    );

    Ok(ca)
}
