#[macro_use]
extern crate tracing;

use thiserror::Error;
use windows::Win32::Foundation::NTSTATUS;

mod cert;
pub use cert::*;

mod sha1;
pub use sha1::*;

mod srtp;
pub use srtp::*;

#[derive(Error, Debug)]
#[error("{0}")]
pub struct WinCryptoError(pub String);

impl WinCryptoError {
    pub fn from_ntstatus(status: NTSTATUS) -> Result<(), Self> {
        if status.is_ok() {
            Ok(())
        } else {
            let status = status.0;
            Err(Self(format!("NTSTATUS({status})")))
        }
    }
}

impl From<windows_result::Error> for WinCryptoError {
    fn from(err: windows_result::Error) -> Self {
        let code = err.code();
        Self(format!("WindowsError({code})"))
    }
}
