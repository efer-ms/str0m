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

mod sha1;
pub use sha1::sha1_hmac;

use thiserror::Error;
use windows::Win32::Foundation::NTSTATUS;

impl SrtpProfile {
    /// What this profile is called in OpenSSL parlance.
    pub(crate) fn cng_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "_internal_test_exports")]
            SrtpProfile::PassThrough => "NULL",
            SrtpProfile::Aes128CmSha1_80 => "SRTP_AES128_CM_SHA1_80",
            SrtpProfile::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
        }
    }
}

#[derive(Error, Debug)]
#[error("{0}")]
pub struct CngError(String);

fn from_win_err(err: windows_result::Error) -> CngError {
    let code = err.code();
    CngError(format!("WindowsError({code})"))
}

fn from_ntstatus_result(status: NTSTATUS) -> Result<(), CngError> {
    if status.is_ok() {
        Ok(())
    } else {
        let status = status.0;
        Err(CngError(format!("NTSTATUS({status})")))
    }
}
