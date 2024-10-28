//! OpenSSL implementation of cryptographic functions.

use super::{CryptoError, SrtpProfile};

mod cert;
pub use cert::CngDtlsCert;

mod io_buf;
mod stream;

mod dtls;
pub use dtls::CngDtlsImpl;

mod srtp;
pub use srtp::CngSrtpCryptoImpl;

impl SrtpProfile {
    /// What this profile is called in Windows CNG parlance.
    pub(crate) fn windows_cng_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "_internal_test_exports")]
            SrtpProfile::PassThrough => "NULL",
            SrtpProfile::Aes128CmSha1_80 => "SRTP_AES128_CM_SHA1_80",
            SrtpProfile::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
        }
    }
}
