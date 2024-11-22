use super::{from_ntstatus_result, from_win_err, CryptoError, WinCryptoError};
use crate::crypto::dtls::DTLS_CERT_IDENTITY;
use crate::crypto::Fingerprint;
use windows::{core::HSTRING, Win32::Security::Cryptography::*};
use windows_strings::PSTR;

#[derive(Debug, Clone)]
pub struct WinCryptoDtlsCert {
    pub(crate) cert_context: *mut CERT_CONTEXT,
}

unsafe impl Send for WinCryptoDtlsCert {}
unsafe impl Sync for WinCryptoDtlsCert {}

impl WinCryptoDtlsCert {
    pub fn new() -> Self {
        Self::self_signed().expect("create dtls cert")
    }

    fn self_signed() -> Result<Self, CryptoError> {
        unsafe {
            let subject = HSTRING::from(format!("CN={}", DTLS_CERT_IDENTITY));
            let mut name_blob = CRYPT_INTEGER_BLOB::default();
            CertStrToNameW(
                X509_ASN_ENCODING,
                &subject,
                CERT_OID_NAME_STR,
                None,
                None,
                &mut name_blob.cbData,
                None,
            )
            .map_err(from_win_err)?;

            let mut name_buffer = vec![0u8; name_blob.cbData as usize];
            name_blob.pbData = name_buffer.as_mut_ptr();
            CertStrToNameW(
                X509_ASN_ENCODING,
                &subject,
                CERT_OID_NAME_STR,
                None,
                Some(name_blob.pbData),
                &mut name_blob.cbData,
                None,
            )
            .map_err(from_win_err)?;

            // Use RSA-SHA256 for the signature, since SHA1 is deprecated.
            let sig_alg = CRYPT_ALGORITHM_IDENTIFIER {
                pszObjId: PSTR::from_raw(szOID_RSA_SHA256RSA.as_ptr() as *mut u8),
                Parameters: CRYPT_INTEGER_BLOB::default(),
            };

            // Generate the self-signed cert.
            let cert_context = CertCreateSelfSignCertificate(
                HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(0),
                &name_blob,
                CERT_CREATE_SELFSIGN_FLAGS(0),
                None,
                Some(&sig_alg),
                None,
                None,
                None,
            );

            if cert_context.is_null() {
                Err(WinCryptoError("Failed to generate self-signed certificate".to_string()).into())
            } else {
                Ok(Self { cert_context })
            }
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        cert_fingerprint(self.cert_context)
    }
}

/// Generates a SHA256 Fingerprint for the given certificate.
pub fn cert_fingerprint(cert_context: *const CERT_CONTEXT) -> Fingerprint {
    unsafe {
        // Determine the size of the scratch space needed to compute a SHA-256 Hash.
        let mut hash_object_size = [0u8; 4];
        let mut hash_object_size_size: u32 = 4;
        if let Err(e) = from_ntstatus_result(BCryptGetProperty(
            BCRYPT_SHA256_ALG_HANDLE,
            BCRYPT_OBJECT_LENGTH,
            Some(&mut hash_object_size),
            &mut hash_object_size_size,
            0,
        )) {
            panic!("Failed to get crypt poperty: {e}");
        }
        let hash_object_len = std::mem::transmute::<[u8; 4], u32>(hash_object_size);
        let mut hash_object = vec![0u8; hash_object_len as usize];

        let mut hash_handle = BCRYPT_HASH_HANDLE::default();
        if let Err(e) = from_ntstatus_result(BCryptCreateHash(
            BCRYPT_SHA256_ALG_HANDLE,
            &mut hash_handle,
            Some(&mut hash_object),
            None,
            0,
        )) {
            panic!("Failed to create hash: {e}");
        }

        if let Err(e) = from_ntstatus_result(BCryptHashData(
            hash_handle,
            std::slice::from_raw_parts(
                (*cert_context).pbCertEncoded,
                (*cert_context).cbCertEncoded as usize,
            ),
            0,
        )) {
            panic!("Failed to hash data: {e}");
        }

        let mut hash = [0u8; 32];
        match from_ntstatus_result(BCryptFinishHash(hash_handle, &mut hash, 0)) {
            Ok(()) => Fingerprint {
                hash_func: "sha-256".into(),
                bytes: hash.to_vec(),
            },
            Err(e) => panic!("Failed to finish hash: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn verify_self_signed() {
        unsafe {
            let cert = super::WinCryptoDtlsCert::new();

            // Verify it is self-signed.
            let subject = (*(*cert.cert_context).pCertInfo).Subject;
            let subject = std::slice::from_raw_parts(subject.pbData, subject.cbData as usize);
            let issuer = (*(*cert.cert_context).pCertInfo).Issuer;
            let issuer = std::slice::from_raw_parts(issuer.pbData, issuer.cbData as usize);
            assert_eq!(issuer, subject);
        }
    }

    #[test]
    fn verify_fingerprint() {
        let cert = super::WinCryptoDtlsCert::new();
        let fingerprint = cert.fingerprint();
        assert_eq!(fingerprint.hash_func, "sha-256");
        assert_eq!(fingerprint.bytes.len(), 32);
    }
}
