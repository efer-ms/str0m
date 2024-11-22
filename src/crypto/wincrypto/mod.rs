//! Windows SChannel + CNG implementation of cryptographic functions.

use super::CryptoError;

mod cert;
pub use cert::WinCryptoDtlsCert;

mod dtls;
pub use dtls::WinCryptoDtlsImpl;

mod srtp;
pub use srtp::WinCryptoSrtpCryptoImpl;

mod sha1;
pub use sha1::sha1_hmac;

use thiserror::Error;
use windows::Win32::Foundation::NTSTATUS;

#[derive(Error, Debug)]
#[error("{0}")]
pub struct WinCryptoError(String);

fn from_win_err(err: windows_result::Error) -> WinCryptoError {
    let code = err.code();
    WinCryptoError(format!("WindowsError({code})"))
}

fn from_ntstatus_result(status: NTSTATUS) -> Result<(), WinCryptoError> {
    if status.is_ok() {
        Ok(())
    } else {
        let status = status.0;
        Err(WinCryptoError(format!("NTSTATUS({status})")))
    }
}
