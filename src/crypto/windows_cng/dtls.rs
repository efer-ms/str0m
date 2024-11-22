use std::collections::VecDeque;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    SEC_E_MESSAGE_ALTERED, SEC_E_OK, SEC_E_OUT_OF_SEQUENCE, SEC_I_CONTEXT_EXPIRED,
    SEC_I_CONTINUE_NEEDED, SEC_I_MESSAGE_FRAGMENT, SEC_I_RENEGOTIATE,
};
use windows::Win32::Security::{Authentication::Identity::*, Credentials::*, Cryptography::*};

use crate::crypto::dtls::DtlsInner;
use crate::crypto::windows_cng::CngError;
use crate::crypto::DtlsEvent;
use crate::crypto::{KeyingMaterial, SrtpProfile};
use crate::io::{DATAGRAM_MTU, DATAGRAM_MTU_WARN};

use super::cert::CngDtlsCert;
use super::CryptoError;

#[repr(C)]
struct SrtpProtectionProfilesBuffer {
    count: u16,
    profiles: [u16; 2], // Big-Endian Encoded values.
}
const SRTP_PROTECTION_PROFILES_BUFFER_INSTANCE: SrtpProtectionProfilesBuffer =
    SrtpProtectionProfilesBuffer {
        count: 4,
        // These are encoded as BE, since SChannel seemingly copies this buffer verbatim.
        profiles: [
            u16::to_be(0x0007), /* SRTP_AES128_GCM (RFC7714 Sec 14.2) */
            u16::to_be(0x0001), /* SRTP_AES128_CM_SHA1_80 (RFC5764 Section 4.1.2) */
        ],
    };
const SRTP_PROTECTION_PROFILES_SECBUFFER: SecBuffer = SecBuffer {
    cbBuffer: std::mem::size_of::<SrtpProtectionProfilesBuffer>() as u32,
    BufferType: SECBUFFER_SRTP_PROTECTION_PROFILES,
    pvBuffer: &SRTP_PROTECTION_PROFILES_BUFFER_INSTANCE as *const _ as *mut _,
};

const DTLS_MTU_BUFFER_INSTANCE: SEC_DTLS_MTU = SEC_DTLS_MTU {
    PathMTU: DATAGRAM_MTU as u16,
};
const DTLS_MTU_SECBUFFER: SecBuffer = SecBuffer {
    cbBuffer: std::mem::size_of::<SEC_DTLS_MTU>() as u32,
    BufferType: SECBUFFER_DTLS_MTU,
    pvBuffer: &DTLS_MTU_BUFFER_INSTANCE as *const _ as *mut _,
};

const DTLS_KEY_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp\0";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HandshakeState {
    Idle,
    Handshake,
    Completed,
    Failed,
}

pub struct CngDtlsImpl {
    cert: CngDtlsCert,
    is_client: Option<bool>,
    cred_handle: Option<SecHandle>,
    security_ctx: Option<SecHandle>,
    state: HandshakeState,
    encrypt_message_input_sizes: SecPkgContext_StreamSizes,

    output: VecDeque<Vec<u8>>,
}

impl CngDtlsImpl {
    pub fn new(cert: CngDtlsCert) -> Result<Self, super::CryptoError> {
        Ok(CngDtlsImpl {
            cert,
            is_client: None,
            cred_handle: None,
            security_ctx: None,
            state: HandshakeState::Idle,
            encrypt_message_input_sizes: SecPkgContext_StreamSizes::default(),
            output: VecDeque::default(),
        })
    }

    fn handshake(
        &mut self,
        datagram: Option<&[u8]>,
        output_events: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        let is_client = self
            .is_client
            .ok_or_else(|| CngError("handshake attempted without setting is_client".to_string()))?;
        let mut new_ctx_handle = SecHandle::default();

        let in_buffer_desc = match datagram {
            Some(datagram) => {
                let buffers = [
                    DTLS_MTU_SECBUFFER,
                    SRTP_PROTECTION_PROFILES_SECBUFFER,
                    SecBuffer {
                        cbBuffer: datagram.len() as u32,
                        BufferType: SECBUFFER_TOKEN,
                        pvBuffer: datagram.as_ptr() as *mut _,
                    },
                    SecBuffer {
                        cbBuffer: 0,
                        BufferType: SECBUFFER_EMPTY,
                        pvBuffer: std::ptr::null_mut(),
                    },
                    SecBuffer {
                        cbBuffer: 0,
                        BufferType: SECBUFFER_EXTRA,
                        pvBuffer: std::ptr::null_mut(),
                    },
                ];
                SecBufferDesc {
                    ulVersion: SECBUFFER_VERSION,
                    cBuffers: buffers.len() as u32,
                    pBuffers: &buffers[0] as *const _ as *mut _,
                }
            }
            None => SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 2,
                pBuffers: &[DTLS_MTU_SECBUFFER, SRTP_PROTECTION_PROFILES_SECBUFFER] as *const _
                    as *mut _,
            },
        };

        let token_buffer = [0u8; DATAGRAM_MTU];
        let alert_buffer = [0u8; DATAGRAM_MTU];
        let out_buffers = [
            SecBuffer {
                cbBuffer: token_buffer.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: &token_buffer as *const _ as *mut _,
            },
            SecBuffer {
                cbBuffer: alert_buffer.len() as u32,
                BufferType: SECBUFFER_ALERT,
                pvBuffer: &alert_buffer as *const _ as *mut _,
            },
        ];
        let mut out_buffer_desc = SecBufferDesc {
            cBuffers: out_buffers.len() as u32,
            pBuffers: &out_buffers[0] as *const _ as *mut _,
            ulVersion: SECBUFFER_VERSION,
        };

        unsafe {
            let mut attrs = 0;
            let status = if is_client {
                // Client
                debug!("InitializeSecurityContextW {:?}", in_buffer_desc);
                InitializeSecurityContextW(
                    self.cred_handle.as_ref().map(|r| r as *const _),
                    self.security_ctx.as_ref().map(|r| r as *const _),
                    None,
                    ISC_REQ_CONFIDENTIALITY
                        | ISC_REQ_EXTENDED_ERROR
                        | ISC_REQ_INTEGRITY
                        | ISC_REQ_DATAGRAM
                        | ISC_REQ_MANUAL_CRED_VALIDATION
                        | ISC_REQ_USE_SUPPLIED_CREDS,
                    0,
                    SECURITY_NATIVE_DREP,
                    Some(&in_buffer_desc),
                    0,
                    Some(&mut new_ctx_handle),
                    Some(&mut out_buffer_desc),
                    &mut attrs,
                    None,
                )
            } else {
                // Server
                debug!("AcceptSecurityContext {:?}", in_buffer_desc);
                AcceptSecurityContext(
                    self.cred_handle.as_ref().map(|r| r as *const _),
                    self.security_ctx.as_ref().map(|r| r as *const _),
                    Some(&in_buffer_desc),
                    ASC_REQ_CONFIDENTIALITY
                        | ASC_REQ_EXTENDED_ERROR
                        | ASC_REQ_INTEGRITY
                        | ASC_REQ_DATAGRAM
                        | ASC_REQ_MUTUAL_AUTH,
                    SECURITY_NATIVE_DREP,
                    Some(&mut new_ctx_handle),
                    Some(&mut out_buffer_desc),
                    &mut attrs,
                    None,
                )
            };
            debug!("DTLS Handshake status: {status}");
            self.security_ctx = Some(new_ctx_handle);
            if out_buffers[0].cbBuffer > 0 {
                let len = out_buffers[0].cbBuffer;
                self.output.push_back(token_buffer[..len as usize].to_vec());
            }
            return match status {
                SEC_E_OK => {
                    // Move to Done
                    self.transition_to_completed(output_events)
                }
                SEC_I_CONTINUE_NEEDED => {
                    // Stay in handshake while we wait for the other side to respond.
                    debug!("Wait for peer");
                    Ok(())
                }
                SEC_I_MESSAGE_FRAGMENT => {
                    // Fragment was sent, we need to call again to send the next fragment.
                    debug!("Sent handshake fragment");
                    self.handshake(None, output_events)
                }
                e => {
                    // Failed
                    self.state = HandshakeState::Failed;
                    Err(CngError(format!("DTLS handshake failure: {:?}", e)).into())
                }
            };
        }
    }

    fn transition_to_completed(
        &mut self,
        output_events: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        self.state = HandshakeState::Completed;
        output_events.push_back(DtlsEvent::Connected);

        unsafe {
            QueryContextAttributesW(
                self.security_ctx.as_ref().unwrap() as *const _,
                SECPKG_ATTR_STREAM_SIZES,
                &mut self.encrypt_message_input_sizes as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| CngError(format!("SECPKG_ATTR_STREAM_SIZES: {:?}", e)))?;

            let mut srtp_parameters = SecPkgContext_SrtpParameters::default();
            QueryContextAttributesA(
                self.security_ctx.as_ref().unwrap() as *const _,
                SECPKG_ATTR(SECPKG_ATTR_SRTP_PARAMETERS),
                &mut srtp_parameters as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| CngError(format!("QueryContextAttributesA Keying Material: {:?}", e)))?;

            let srtp_profile =
                srtp_profile_from_network_endian_id(srtp_parameters.ProtectionProfile);
            let keying_material_info = SecPkgContext_KeyingMaterialInfo {
                cbLabel: DTLS_KEY_LABEL.len() as u16,
                pszLabel: windows_strings::PSTR(DTLS_KEY_LABEL.as_ptr() as *mut u8),
                cbKeyingMaterial: srtp_profile.keying_material_len() as u32,
                cbContextValue: 0,
                pbContextValue: std::ptr::null_mut(),
            };
            SetContextAttributesW(
                self.security_ctx.as_ref().unwrap() as *const _,
                SECPKG_ATTR_KEYING_MATERIAL_INFO,
                &keying_material_info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<SecPkgContext_KeyingMaterialInfo>() as u32,
            )
            .map_err(|e| CngError(format!("SetContextAttributesA Keying Material: {:?}", e)))?;

            let mut keying_material = SecPkgContext_KeyingMaterial::default();
            QueryContextAttributesExW(
                self.security_ctx.as_ref().unwrap() as *const _,
                SECPKG_ATTR(SECPKG_ATTR_KEYING_MATERIAL),
                &mut keying_material as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<SecPkgContext_KeyingMaterial>() as u32,
            )
            .map_err(|e| CngError(format!("QueryContextAttributesA Keying Material: {:?}", e)))?;

            output_events.push_back(DtlsEvent::SrtpKeyingMaterial(
                KeyingMaterial::new(
                    std::slice::from_raw_parts(
                        keying_material.pbKeyingMaterial,
                        keying_material.cbKeyingMaterial as usize,
                    )
                    .to_vec(),
                ),
                srtp_profile,
            ));

            FreeContextBuffer(keying_material.pbKeyingMaterial as *mut _ as *mut std::ffi::c_void)
                .map_err(|e| CngError(format!("FreeContextBuffer Keying Material: {:?}", e)))?;

            let mut remote_cert_context_ptr = std::ptr::null_mut();
            QueryContextAttributesA(
                self.security_ctx.as_ref().unwrap() as *const _,
                SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                &mut remote_cert_context_ptr as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| CngError(format!("QueryContextAttributesA: {:?}", e)))?;
            let remote_cert_context = *(remote_cert_context_ptr as *const CERT_CONTEXT);

            let fingerprint = super::cert::cert_fingerprint(&remote_cert_context);
            output_events.push_back(DtlsEvent::RemoteFingerprint(fingerprint));

            _ = CertFreeCertificateContext(Some(remote_cert_context_ptr));

            Ok(())
        }
    }

    fn process_packet(
        &mut self,
        datagram: &[u8],
        output_events: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        if self.state != HandshakeState::Completed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Not ready".to_string(),
            )
            .into());
        }
        let security_ctx = self.security_ctx.as_ref().expect("No ctx!?");

        unsafe {
            let header_size = self.encrypt_message_input_sizes.cbHeader as usize;
            let trailer_size = self.encrypt_message_input_sizes.cbTrailer as usize;

            let output = datagram.to_vec();
            let alert = [0u8; 512];

            let sec_buffers = [
                SecBuffer {
                    BufferType: SECBUFFER_DATA,
                    cbBuffer: output.len() as u32,
                    pvBuffer: &output[0] as *const _ as *mut _,
                },
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_EMPTY,
                    pvBuffer: std::ptr::null_mut(),
                },
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_EMPTY,
                    pvBuffer: std::ptr::null_mut(),
                },
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_EMPTY,
                    pvBuffer: std::ptr::null_mut(),
                },
                SecBuffer {
                    BufferType: SECBUFFER_ALERT,
                    cbBuffer: alert.len() as u32,
                    pvBuffer: &alert[0] as *const _ as *mut _,
                },
            ];
            let sec_buffer_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 4,
                pBuffers: &sec_buffers[0] as *const _ as *mut _,
            };

            let status = DecryptMessage(security_ctx, &sec_buffer_desc, 0, None);
            match status {
                SEC_E_OK => {
                    let data = output[header_size..output.len() - trailer_size].to_vec();
                    output_events.push_back(DtlsEvent::Data(data));
                    Ok(())
                }
                SEC_E_MESSAGE_ALTERED => {
                    warn!("Packet alteration detected, packet dropped");
                    Ok(())
                }
                SEC_E_OUT_OF_SEQUENCE => {
                    warn!("Received out of sequence packet");
                    Ok(())
                }
                SEC_I_CONTEXT_EXPIRED => {
                    self.state = HandshakeState::Failed;
                    Err(CngError("Context expired".to_string()).into())
                }
                SEC_I_RENEGOTIATE => {
                    // SChannel provides a token to feed into a new handshake
                    if let Some(token_buffer) =
                        sec_buffers.iter().find(|p| p.BufferType == SECBUFFER_EXTRA)
                    {
                        self.state = HandshakeState::Handshake;
                        let data = token_buffer.pvBuffer as *mut u8;
                        let len = token_buffer.cbBuffer as usize;
                        self.handshake(Some(std::slice::from_raw_parts(data, len)), output_events)
                    } else {
                        Err(CngError("Renegotiate didn't include a token".to_string()).into())
                    }
                }
                status => Err(CngError(format!(
                    "DecryptMessage returned error, message dropped. Status: {}",
                    status
                ))
                .into()),
            }
        }
    }
}

impl Drop for CngDtlsImpl {
    fn drop(&mut self) {
        unsafe {
            if let Some(ctx_handle) = self.security_ctx {
                if let Err(e) = DeleteSecurityContext(&ctx_handle) {
                    error!("DeleteSecurityContext on Drop failed: {:?}", e);
                }
            }
            if let Some(cred_handle) = self.cred_handle {
                if let Err(e) = FreeCredentialsHandle(&cred_handle) {
                    error!("FreeCredentialsHandle on Drop failed: {:?}", e);
                }
            }
        }
    }
}

impl DtlsInner for CngDtlsImpl {
    fn set_active(&mut self, active: bool) {
        self.is_client = Some(active);

        // OpenSSL is configured with "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"
        // EECDH - Ephemeral Elliptic Curve Diffie-Hellman -> CALG_ECDH_EPHEM
        // EDH - Ephemeral Diffie-Hellman -> CALG_DH_EPHEM
        // AESGCM - AES in Galois/Counter Mode -> CALG_AES (TODO(efer): Not sure about GCM)
        // AES256 - AES with 256-bit key -> CALG_AES_256
        let mut algs = [CALG_ECDH_EPHEM, CALG_DH_EPHEM]; //, CALG_AES, CALG_AES_256]; <-- AES IDs aren't supported in the API?!
        let mut cert_contexts = [self.cert.cert_context];

        let schannel_cred = SCHANNEL_CRED {
            dwVersion: SCHANNEL_CRED_VERSION,
            hRootStore: windows::Win32::Security::Cryptography::HCERTSTORE(std::ptr::null_mut()),

            grbitEnabledProtocols: if active {
                SP_PROT_DTLS1_2_CLIENT
            } else {
                SP_PROT_DTLS1_2_SERVER
            },

            cCreds: cert_contexts.len() as u32,
            paCred: cert_contexts.as_mut_ptr() as *mut *mut CERT_CONTEXT,

            cMappers: 0,
            aphMappers: std::ptr::null_mut(),

            cSupportedAlgs: algs.len() as u32,
            palgSupportedAlgs: &mut algs[0],

            dwMinimumCipherStrength: 128,
            dwMaximumCipherStrength: 256,
            dwSessionLifespan: 0,
            dwFlags: SCH_CRED_MANUAL_CRED_VALIDATION,
            dwCredFormat: 0,
        };

        unsafe {
            // These are the outputs of AcquireCredentialsHandleA
            let mut cred_handle = SecHandle::default();
            let mut creds_expiry: i64 = 0;
            AcquireCredentialsHandleW(
                None,
                UNISP_NAME_W,
                if active {
                    SECPKG_CRED_OUTBOUND
                } else {
                    SECPKG_CRED_INBOUND
                },
                None,
                Some(&schannel_cred as *const _ as *const std::ffi::c_void),
                None,
                None,
                &mut cred_handle,
                Some(&mut creds_expiry),
            )
            .expect("Failed to generate creds");

            self.cred_handle = Some(cred_handle);
        }

        self.state = HandshakeState::Handshake;
    }

    fn is_active(&self) -> Option<bool> {
        self.is_client
    }

    fn handle_receive(
        &mut self,
        datagram: &[u8],
        output_events: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        let state = self.state;
        match state {
            HandshakeState::Completed => self.process_packet(datagram, output_events),
            HandshakeState::Handshake => self.handshake(Some(datagram), output_events),
            HandshakeState::Failed => Err(CngError("Handshake failed".to_string()).into()),
            HandshakeState::Idle => Err(CngError("Handshake not initialized".to_string()).into()),
        }
    }

    fn poll_datagram(&mut self) -> Option<crate::net::DatagramSend> {
        let x: Option<crate::io::DatagramSend> = self.output.pop_front().map(|v| v.into());
        if let Some(x) = &x {
            if x.len() > DATAGRAM_MTU_WARN {
                warn!("DTLS above MTU {}: {}", DATAGRAM_MTU_WARN, x.len());
            }
            trace!("Poll datagram: {}", x.len());
        }
        x
    }

    fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        match self.state {
            HandshakeState::Idle | HandshakeState::Handshake => {
                Some(now + Duration::from_millis(500))
            }
            _ => None,
        }
    }

    // This is DATA sent from client over SCTP/DTLS
    fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.state != HandshakeState::Completed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Not ready".to_string(),
            )
            .into());
        }
        let ctx_handle = self.security_ctx.as_ref().expect("No ctx!?");

        unsafe {
            let header_size = self.encrypt_message_input_sizes.cbHeader as usize;
            let trailer_size = self.encrypt_message_input_sizes.cbTrailer as usize;
            let message_size = data.len();

            let mut output = vec![0u8; header_size + trailer_size + message_size];
            output[header_size..header_size + message_size].copy_from_slice(data);

            let sec_buffers = [
                SecBuffer {
                    BufferType: SECBUFFER_STREAM_HEADER,
                    cbBuffer: header_size as u32,
                    pvBuffer: &output[0] as *const _ as *mut _,
                },
                SecBuffer {
                    BufferType: SECBUFFER_DATA,
                    cbBuffer: message_size as u32,
                    pvBuffer: &output[header_size] as *const _ as *mut _,
                },
                SecBuffer {
                    BufferType: SECBUFFER_STREAM_TRAILER,
                    cbBuffer: trailer_size as u32,
                    pvBuffer: &output[header_size + message_size] as *const _ as *mut _,
                },
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_EMPTY,
                    pvBuffer: std::ptr::null_mut(),
                },
            ];
            let sec_buffer_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 4,
                pBuffers: &sec_buffers[0] as *const _ as *mut _,
            };

            let status = EncryptMessage(ctx_handle, 0, &sec_buffer_desc, 0);
            match status {
                SEC_E_OK => {
                    self.output.push_back(output);
                    Ok(())
                }
                status => Err(CngError(format!(
                    "EncryptMessage returned error, message dropped. Status: {}",
                    status
                ))
                .into()),
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.state == HandshakeState::Completed
    }

    fn handle_handshake(&mut self, output: &mut VecDeque<DtlsEvent>) -> Result<bool, CryptoError> {
        if self.state == HandshakeState::Handshake && self.is_client == Some(true) {
            self.handshake(None, output)?;
        }
        Ok(false)
    }
}

fn srtp_profile_from_network_endian_id(network_endian_id: u16) -> SrtpProfile {
    let native_endian_id = u16::from_be(network_endian_id);
    match native_endian_id {
        0x0001 => SrtpProfile::Aes128CmSha1_80,
        0x0007 => SrtpProfile::AeadAes128Gcm,
        _ => panic!("Unknown SRTP profile ID: {:04x}", native_endian_id),
    }
}
