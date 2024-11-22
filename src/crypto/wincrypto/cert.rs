use crate::crypto::dtls::DTLS_CERT_IDENTITY;
use crate::crypto::Fingerprint;
use std::sync::Arc;
use str0m_wincrypto::{Certificate, WinCryptoError};

#[derive(Clone, Debug)]
pub struct WinCryptoDtlsCert {
    pub(crate) certificate: Arc<Certificate>,
}

impl WinCryptoDtlsCert {
    pub fn new() -> Self {
        let certificate = Arc::new(
            Certificate::new_self_signed(&format!("CN={}", DTLS_CERT_IDENTITY))
                .expect("Failed to create self-signed certificate"),
        );
        Self { certificate }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        create_fingerprint(&self.certificate).expect("Failed to calculate fingerprint")
    }
}

pub(super) fn create_fingerprint(
    certificate: &str0m_wincrypto::Certificate,
) -> Result<Fingerprint, WinCryptoError> {
    certificate.sha256_fingerprint().map(|bytes| Fingerprint {
        hash_func: "sha-256".into(),
        bytes: bytes.to_vec(),
    })
}
