use std::io;
use std::panic::UnwindSafe;
use windows::Win32::Foundation::{SEC_E_OK, SEC_I_CONTINUE_NEEDED, SEC_I_MESSAGE_FRAGMENT};
use windows::Win32::Security::{Authentication::Identity::*, Credentials::*, Cryptography::*};

use crate::change::Fingerprint;
use crate::crypto::windows_cng::CngError;
use crate::crypto::{KeyingMaterial, SrtpProfile};

use super::CryptoError;

const DTLS_KEY_LABEL: &str = "EXTRACTOR-dtls_srtp";

pub struct TlsStream<S> {
    active: Option<bool>,
    cred_handle: SecHandle,
    ctx_handle: Option<SecHandle>,
    state: HandshakeState,
    stream: S,
    keying_mat: Option<(KeyingMaterial, SrtpProfile, Fingerprint)>,
    exported: bool,
    expiry: i64,
    attrs: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HandshakeState {
    Waiting,
    Done,
    Failed,
}

/// This is okay because there is no way for a user of Rtc to interact with the Dtls subsystem
/// in a way that would allow them to observe a potentially broken invariant when catching a panic.
impl UnwindSafe for HandshakeState {}

impl<S> TlsStream<S>
where
    S: io::Read + io::Write + UnwindSafe,
{
    pub fn new(cred_handle: SecHandle, stream: S) -> Self {
        TlsStream {
            active: None,
            cred_handle,
            ctx_handle: None,
            state: HandshakeState::Waiting,
            keying_mat: None,
            exported: false,
            stream,
            expiry: 0,
            attrs: 0,
        }
    }

    pub fn is_active(&self) -> Option<bool> {
        self.active
    }

    pub fn set_active(&mut self, active: bool) {
        assert!(
            self.active.is_none(),
            "set_active should called exactly once"
        );
        self.active = Some(active);
    }

    pub fn complete_handshake_until_block(&mut self) -> Result<bool, CryptoError> {
        if let Err(e) = self.continue_handshake() {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(false)
            } else {
                Err(e.into())
            }
        } else {
            Ok(true)
        }
    }

    pub fn is_handshaking(&self) -> bool {
        matches!(self.state, HandshakeState::Waiting)
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, HandshakeState::Done)
    }

    pub fn continue_handshake(&mut self) -> Result<&mut S, io::Error> {
        self.is_active().expect("set_active must be called");
        self.do_handshake()?;

        // first time we complete the handshake, we extract the keying material for SRTP.
        if !self.exported {
            let keying_mat = self.export_srtp_keying_material()?;
            self.exported = true;
            self.keying_mat = Some(keying_mat);
        }

        Ok(&mut self.stream)
    }

    pub fn take_srtp_keying_material(
        &mut self,
    ) -> Option<(KeyingMaterial, SrtpProfile, Fingerprint)> {
        self.keying_mat.take()
    }

    pub fn inner_mut(&mut self) -> &mut S {
        match &mut self.state {
            HandshakeState::Failed => panic!("inner_mut on empty dtls state"),
            _ => &mut self.stream,
        }
    }

    fn export_srtp_keying_material(
        &self,
    ) -> Result<(KeyingMaterial, SrtpProfile, Fingerprint), io::Error> {
        // let ssl = stream.ssl();

        // // remote peer certificate fingerprint
        // let x509 = ssl
        //     .peer_certificate()
        //     .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No remote X509 cert"))?;
        // let digest: &[u8] = &x509.digest(MessageDigest::sha256())?;

        // let fp = Fingerprint {
        //     hash_func: "sha-256".into(),
        //     bytes: digest.to_vec(),
        // };

        // let srtp_profile_id = ssl
        //     .selected_srtp_profile()
        //     .map(|s| s.id())
        //     .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to negotiate SRTP profile"))?;
        // let srtp_profile: SrtpProfile = srtp_profile_id.try_into()?;

        // // extract SRTP keying material
        // let mut buf = vec![0_u8; srtp_profile.keying_material_len()];
        // ssl.export_keying_material(&mut buf, DTLS_KEY_LABEL, None)?;

        // let mat = KeyingMaterial::new(buf);

        // Ok((mat, srtp_profile, fp))
        panic!("No impl");
    }

    fn do_handshake(&mut self) -> Result<(), io::Error> {
        if self.state == HandshakeState::Done {
            return Ok(());
        }

        unsafe {
            let state = self.state;

            match state {
                HandshakeState::Failed | HandshakeState::Done => {
                    unreachable!()
                }
                HandshakeState::Waiting => {
                    let mut new_ctx_handle = SecHandle::default();
                    let mut out_buffer_desc = SecBufferDesc::default();
                    let in_buffer_desc = SecBufferDesc::default();
                    let status = if self.active == Some(true) {
                        debug!("Connect");
                        InitializeSecurityContextW(
                            Some(&self.cred_handle),
                            self.ctx_handle.as_ref().map(|r| r as *const _),
                            None,
                            ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_DATAGRAM,
                            0,
                            SECURITY_NATIVE_DREP,
                            Some(&in_buffer_desc),
                            0,
                            Some(&mut new_ctx_handle),
                            Some(&mut out_buffer_desc),
                            &mut self.attrs,
                            Some(&mut self.expiry),
                        )
                    } else {
                        debug!("Accept");
                        AcceptSecurityContext(
                            Some(&self.cred_handle),
                            self.ctx_handle.as_ref().map(|r| r as *const _),
                            Some(&in_buffer_desc),
                            ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | ASC_REQ_DATAGRAM,
                            SECURITY_NATIVE_DREP,
                            Some(&mut new_ctx_handle),
                            Some(&mut out_buffer_desc),
                            &mut self.attrs,
                            Some(&mut self.expiry),
                        )
                    };
                    return match status {
                        SEC_E_OK => {
                            // Move to Done
                            self.state = HandshakeState::Done;
                            Ok(())
                        }
                        SEC_I_CONTINUE_NEEDED => {
                            // Stay in waiting
                            Err(io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock"))
                        }
                        SEC_I_MESSAGE_FRAGMENT => {
                            // Stay in waiting
                            Err(io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock"))
                        }
                        e => {
                            // Failed
                            self.state = HandshakeState::Failed;
                            debug!("DTLS failure: {:?}", e);
                            Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                CngError(format!("DTLS failure: {:?}", e)),
                            ))
                        }
                    };
                }
            };
        }
    }
}

impl<S> io::Read for TlsStream<S>
where
    S: io::Read + io::Write + UnwindSafe,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.continue_handshake()?.read(buf)
    }
}

impl<S> io::Write for TlsStream<S>
where
    S: io::Read + io::Write + UnwindSafe,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.continue_handshake()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.continue_handshake()?.flush()
    }
}

enum SrtpProfileId {
    SRTP_AES128_CM_SHA1_80,
    SRTP_AEAD_AES_128_GCM,
}

impl TryFrom<SrtpProfileId> for SrtpProfile {
    type Error = io::Error;

    fn try_from(value: SrtpProfileId) -> Result<Self, Self::Error> {
        match value {
            SrtpProfileId::SRTP_AES128_CM_SHA1_80 => Ok(SrtpProfile::Aes128CmSha1_80),
            SrtpProfileId::SRTP_AEAD_AES_128_GCM => Ok(SrtpProfile::AeadAes128Gcm),
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unsupported SRTP profile"),
            )),
        }
    }
}
