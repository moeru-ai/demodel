use std::path::Path;
use tracing::info;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

// Display platform-specific certificate installation instructions
pub fn display_certificate_instructions(pki_dir: &Path) {
    #[cfg(target_os = "macos")]
    {
        info!(
            "Successfully installed CA certificate to keychain, physical files were stored in {}",
            pki_dir.display()
        );
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
}

// Platform-specific certificate installation
pub fn install_ca_certificate(
    _: &hudsucker::openssl::x509::X509,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        info!("Certificate installation not implemented for this platform.");
        info!("You may need to manually install the certificate.");
    }

    Ok(())
}
