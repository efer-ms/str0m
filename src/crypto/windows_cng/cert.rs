use super::{from_ntstatus_result, from_win_err, CngError, CryptoError};
use crate::crypto::dtls::DTLS_CERT_IDENTITY;
use crate::crypto::Fingerprint;
use windows::{core::HSTRING, Win32::Security::Cryptography::*};
use windows_strings::PSTR;

#[derive(Debug, Clone)]
pub struct CngDtlsCert {
    pub(crate) cert_context: *mut CERT_CONTEXT,
}

unsafe impl Send for CngDtlsCert {}
unsafe impl Sync for CngDtlsCert {}

impl CngDtlsCert {
    pub fn new() -> Self {
        Self::self_signed().expect("create dtls cert")
    }

    fn self_signed() -> Result<Self, CryptoError> {
        unsafe {
            let dn = HSTRING::from(format!("CN={}", DTLS_CERT_IDENTITY));
            let mut name_blob = CRYPT_INTEGER_BLOB::default();
            CertStrToNameW(
                X509_ASN_ENCODING,
                &dn,
                CERT_OID_NAME_STR,
                None,
                None,
                &mut name_blob.cbData,
                None,
            )
            .map_err(from_win_err)?;
            let mut name_vec = vec![0u8; name_blob.cbData as usize];
            name_blob.pbData = name_vec.as_mut_ptr();
            CertStrToNameW(
                X509_ASN_ENCODING,
                &dn,
                CERT_OID_NAME_STR,
                None,
                Some(name_blob.pbData),
                &mut name_blob.cbData,
                None,
            )
            .map_err(from_win_err)?;

            let sig_alg = CRYPT_ALGORITHM_IDENTIFIER {
                pszObjId: PSTR::from_raw(szOID_RSA_SHA256RSA.as_ptr() as *mut u8),
                Parameters: CRYPT_INTEGER_BLOB::default(),
            };

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
                Err(CngError("Failed to generate self-signed certificate".to_string()).into())
            } else {
                Ok(Self { cert_context })
            }
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        println!("local fingerprint: {}", cert_fingerprint(self.cert_context));
        cert_fingerprint(self.cert_context)
    }
}

pub fn cert_fingerprint(cert_context: *const CERT_CONTEXT) -> Fingerprint {
    unsafe {
        let mut hash = [0u8; 32];

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

        if let Err(e) = from_ntstatus_result(BCryptFinishHash(hash_handle, &mut hash, 0)) {
            panic!("Failed to finish hash: {e}");
        }

        Fingerprint {
            hash_func: "sha-256".into(),
            bytes: hash.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn make_cert() {
        unsafe {
            let cert = super::CngDtlsCert::new();
            let cert_contents = std::slice::from_raw_parts(
                (*cert.cert_context).pbCertEncoded,
                (*cert.cert_context).cbCertEncoded as usize,
            );
            println!("Cert: {:02X?}", cert_contents);
            println!(
                "Encoding Type: {:#?}",
                (*cert.cert_context).dwCertEncodingType
            );
            let fingerprint = cert.fingerprint();
            println!("Fingerprint: {:02X?}", fingerprint);
        }
    }
}
