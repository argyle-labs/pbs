//! TLS policy for the PBS API. PBS serves a self-signed `proxy.pem` by
//! default, so a caller either pins its SHA-256 fingerprint (what
//! `proxmox-backup-manager cert info` and the PBS dashboard print) or opts in
//! to `insecure` explicitly. Verification is never dropped implicitly.

use std::fmt;
use std::sync::Arc;

use plugin_toolkit::prelude::*;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;

/// SHA-256 of the server's end-entity certificate (DER).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Accepts `AA:BB:…` (any case) or 64 bare hex digits.
    pub fn parse(s: &str) -> Result<Self> {
        let hex: String = s.trim().chars().filter(|c| *c != ':').collect();
        if hex.len() != 64 {
            bail!(
                "TLS fingerprint must be a SHA-256 (32 bytes, `AA:BB:…`), got {} hex digits",
                hex.len()
            );
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow!("TLS fingerprint contains a non-hex digit"))?;
        }
        Ok(Self(out))
    }

    pub fn of_der(der: &[u8]) -> Self {
        Self(plugin_toolkit::hash::sha256(der))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsPolicy {
    /// System trust roots and hostname checks.
    Verify,
    /// Accept exactly the certificate with this fingerprint.
    Pinned(Fingerprint),
    /// No verification. Only from an explicit `insecure` on the endpoint.
    Insecure,
}

impl TlsPolicy {
    /// A pin wins over `insecure`: having both means the operator knows the
    /// certificate, so there is no reason to accept any other.
    pub fn from_config(fingerprint: Option<Fingerprint>, insecure: bool) -> Self {
        match (fingerprint, insecure) {
            (Some(fp), _) => Self::Pinned(fp),
            (None, true) => Self::Insecure,
            (None, false) => Self::Verify,
        }
    }

    /// Whether the unauthenticated reachability probe must skip CA checks.
    /// A pinned endpoint is still self-signed; the pin is enforced on the
    /// authenticated client, not the probe.
    pub fn probe_insecure(&self) -> bool {
        !matches!(self, Self::Verify)
    }
}

/// Accepts the one certificate whose SHA-256 matches the pin, ignoring CA chain
/// and hostname, but still verifies handshake signatures so the peer must hold
/// that certificate's private key.
#[derive(Debug)]
pub struct PinVerifier {
    pin: Fingerprint,
    algs: WebPkiSupportedAlgorithms,
}

impl PinVerifier {
    pub fn new(pin: Fingerprint, provider: &CryptoProvider) -> Self {
        Self {
            pin,
            algs: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let seen = Fingerprint::of_der(end_entity.as_ref());
        if seen == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "PBS certificate fingerprint {seen} does not match the pinned {}",
                self.pin
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// rustls client config that trusts only `pin`.
pub fn pinned_client_config(pin: Fingerprint) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinVerifier::new(pin, &provider));
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("rustls protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str =
        "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";

    #[test]
    fn parses_colon_and_bare_hex_and_prints_canonical() {
        let a = Fingerprint::parse(FP).unwrap();
        let b = Fingerprint::parse(&FP.replace(':', "")).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_string(), FP.to_uppercase());
    }

    #[test]
    fn rejects_short_or_non_hex() {
        assert!(Fingerprint::parse("aa:bb").is_err());
        assert!(Fingerprint::parse(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn pin_beats_insecure_and_nothing_means_verify() {
        let fp = Fingerprint::parse(FP).unwrap();
        assert_eq!(
            TlsPolicy::from_config(Some(fp), true),
            TlsPolicy::Pinned(fp)
        );
        assert_eq!(TlsPolicy::from_config(None, true), TlsPolicy::Insecure);
        assert_eq!(TlsPolicy::from_config(None, false), TlsPolicy::Verify);
        assert!(!TlsPolicy::Verify.probe_insecure());
    }

    fn verify(v: &PinVerifier, der: &[u8]) -> Result<ServerCertVerified, rustls::Error> {
        v.verify_server_cert(
            &CertificateDer::from(der.to_vec()),
            &[],
            &ServerName::try_from("pbs.test").unwrap(),
            &[],
            UnixTime::now(),
        )
    }

    #[test]
    fn verifier_accepts_only_the_pinned_certificate() {
        let der = b"pretend-der-certificate";
        let provider = rustls::crypto::ring::default_provider();
        let v = PinVerifier::new(Fingerprint::of_der(der), &provider);
        assert!(verify(&v, der).is_ok());
        let err = verify(&v, b"some-other-certificate").unwrap_err();
        assert!(err.to_string().contains("does not match the pinned"));
    }

    #[test]
    fn pinned_config_builds() {
        pinned_client_config(Fingerprint::parse(FP).unwrap()).unwrap();
    }
}
