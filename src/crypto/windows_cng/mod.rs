//! Windows SChannel + CNG implementation of cryptographic functions.

use super::CryptoError;

mod cert;
pub use cert::CngDtlsCert;

mod dtls;
pub use dtls::CngDtlsImpl;

mod srtp;
pub use srtp::CngSrtpCryptoImpl;

mod sha1;
pub use sha1::sha1_hmac;

use thiserror::Error;
use windows::Win32::Foundation::NTSTATUS;

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
