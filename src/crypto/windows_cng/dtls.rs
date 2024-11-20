use std::collections::VecDeque;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{SEC_E_OK, SEC_I_CONTINUE_NEEDED, SEC_I_MESSAGE_FRAGMENT};
use windows::Win32::Security::{Authentication::Identity::*, Credentials::*, Cryptography::*};

use crate::crypto::dtls::DtlsInner;
use crate::crypto::windows_cng::CngError;
use crate::crypto::DtlsEvent;
use crate::crypto::{KeyingMaterial, SrtpProfile};
use crate::io::{DATAGRAM_MTU, DATAGRAM_MTU_WARN};

use super::cert::CngDtlsCert;
use super::CryptoError;

// const DTLS_CIPHERS: &str = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
// const DTLS_EC_CURVE: Nid = Nid::X9_62_PRIME256V1;

#[repr(C)]
struct SrtpProtectionProfilesBuffer {
    count: u16,
    profiles: [u8; 4], // Big-Endian Encoded values.
}
const SRTP_PROTECTION_PROFILES_BUFFER_INSTANCE: SrtpProtectionProfilesBuffer =
    SrtpProtectionProfilesBuffer {
        count: 4,
        profiles: [
            0x00, 0x07, /* SRTP_AES128_GCM (RFC7714 Sec 14.2) */
            0x00, 0x01, /* SRTP_AES128_CM_SHA1_80 (RFC5764 Section 4.1.2) */
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HandshakeState {
    Idle,
    ClientHandshake,
    ServerHandshake,
    Completed,
    Failed,
}

pub struct CngDtlsImpl {
    cert: CngDtlsCert,
    cred_handle: Option<SecHandle>,
    active: Option<bool>,
    ctx_handle: Option<SecHandle>,
    state: HandshakeState,
    expiry: i64,
    attrs: u32,

    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
}

impl CngDtlsImpl {
    pub fn new(cert: CngDtlsCert) -> Result<Self, super::CryptoError> {
        Ok(CngDtlsImpl {
            cert,
            cred_handle: None,
            active: None,
            ctx_handle: None,
            state: HandshakeState::Idle,
            expiry: 0,
            attrs: 0,
            input: VecDeque::default(),
            output: VecDeque::default(),
        })
    }

    fn client_handshake(
        &mut self,
        datagram: Option<&[u8]>,
        output_events: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
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
                ];
                SecBufferDesc {
                    cBuffers: 4,
                    pBuffers: &buffers[0] as *const _ as *mut _,
                    ulVersion: SECBUFFER_VERSION,
                }
            }
            None => SecBufferDesc {
                cBuffers: 2,
                pBuffers: &[DTLS_MTU_SECBUFFER, SRTP_PROTECTION_PROFILES_SECBUFFER] as *const _
                    as *mut _,
                ulVersion: SECBUFFER_VERSION,
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
            cBuffers: 2,
            pBuffers: &out_buffers[0] as *const _ as *mut _,
            ulVersion: SECBUFFER_VERSION,
        };

        unsafe {
            debug!("Connect");
            let status = InitializeSecurityContextW(
                self.cred_handle.as_ref().map(|r| r as *const _),
                self.ctx_handle.as_ref().map(|r| r as *const _),
                None,
                ISC_REQ_CONFIDENTIALITY
                    | ISC_REQ_EXTENDED_ERROR
                    | ISC_REQ_DATAGRAM
                    | ISC_REQ_MANUAL_CRED_VALIDATION
                    | ISC_REQ_USE_SUPPLIED_CREDS,
                0,
                SECURITY_NATIVE_DREP,
                Some(&in_buffer_desc),
                0,
                Some(&mut new_ctx_handle),
                Some(&mut out_buffer_desc),
                &mut self.attrs,
                Some(&mut self.expiry),
            );
            println!("Connect {status}");
            self.ctx_handle = Some(new_ctx_handle);
            if out_buffers[0].cbBuffer > 0 {
                let len = out_buffers[0].cbBuffer;
                self.output.push_back(token_buffer[..len as usize].to_vec());
                println!(
                    "Client Outbound Datagram {:02x?}",
                    &token_buffer[..len as usize]
                );
            }
            return match status {
                SEC_E_OK => {
                    // Move to Done
                    self.state = HandshakeState::Completed;
                    self.export_srtp_keying_material(output_events)?;
                    println!("Client DONE!");
                    Ok(())
                }
                SEC_I_MESSAGE_FRAGMENT => self.client_handshake(None, output_events),
                SEC_I_CONTINUE_NEEDED => {
                    // Stay in waiting
                    debug!("Continue needed or fragment?");
                    Ok(())
                }
                e => {
                    // Failed
                    self.state = HandshakeState::Failed;
                    debug!("DTLS failure: {:?}", e);
                    Err(CngError(format!("DTLS failure: {:?}", e)).into())
                }
            };
        }
    }

    fn server_handshake(
        &mut self,
        datagram: Option<&[u8]>,
        output_events: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
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
                        BufferType: SECBUFFER_EXTRA,
                        pvBuffer: std::ptr::null_mut(),
                    },
                    SecBuffer {
                        cbBuffer: 0,
                        BufferType: SECBUFFER_EMPTY,
                        pvBuffer: std::ptr::null_mut(),
                    },
                ];
                Some(&SecBufferDesc {
                    cBuffers: 5, //if self.ctx_handle.is_none() { 5 } else { 3 },
                    pBuffers: &buffers[0] as *const _ as *mut _,
                    ulVersion: SECBUFFER_VERSION,
                } as *const _)
            }
            None => {
                let buffers = [
                    DTLS_MTU_SECBUFFER,
                    SRTP_PROTECTION_PROFILES_SECBUFFER,
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
                        BufferType: SECBUFFER_EXTRA,
                        pvBuffer: std::ptr::null_mut(),
                    },
                ];
                Some(&SecBufferDesc {
                    cBuffers: 5,
                    pBuffers: &buffers[0] as *const _ as *mut _,
                    ulVersion: SECBUFFER_VERSION,
                } as *const _)
            }
        };

        let token_buffer = [0u8; 1280];
        let alert_buffer = [0u8; 1280];
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
            let status = AcceptSecurityContext(
                self.cred_handle.as_ref().map(|r| r as *const _),
                self.ctx_handle.as_ref().map(|r| r as *const _),
                in_buffer_desc,
                ASC_REQ_CONFIDENTIALITY
                    | ASC_REQ_EXTENDED_ERROR
                    | ASC_REQ_DATAGRAM // Datagram mode
                    | ASC_REQ_MUTUAL_AUTH, // Make sure we ask for the client cert
                SECURITY_NATIVE_DREP,
                Some(&mut new_ctx_handle),
                Some(&mut out_buffer_desc),
                &mut self.attrs,
                Some(&mut self.expiry),
            );

            println!("Accept {status}");
            self.ctx_handle = Some(new_ctx_handle);
            if out_buffers[0].cbBuffer > 0 {
                let len = out_buffers[0].cbBuffer;
                self.output.push_back(token_buffer[..len as usize].to_vec());
                println!(
                    "Server Outbound Datagram {:02x?}",
                    &token_buffer[..len as usize]
                );
            }

            return match status {
                SEC_E_OK => {
                    // Move to Done
                    self.state = HandshakeState::Completed;
                    self.export_srtp_keying_material(output_events)?;
                    println!("Server DONE!");
                    Ok(())
                }
                SEC_I_MESSAGE_FRAGMENT => self.server_handshake(None, output_events),
                SEC_I_CONTINUE_NEEDED => {
                    // Stay in waiting
                    Ok(())
                }
                e => {
                    // Failed
                    self.state = HandshakeState::Failed;
                    debug!("DTLS failure: {:?}", e);
                    Err(CngError(format!("DTLS failure: {:?}", e)).into())
                }
            };
        }
    }

    fn export_srtp_keying_material(
        &mut self,
        output_events: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        output_events.push_back(DtlsEvent::Connected);
        println!("Exporting SRTP keying material {}", self.attrs);
        unsafe {
            let mut srtp_parameters = SecPkgContext_SrtpParameters::default();
            QueryContextAttributesA(
                self.ctx_handle.as_ref().unwrap() as *const _,
                SECPKG_ATTR(SECPKG_ATTR_SRTP_PARAMETERS),
                &mut srtp_parameters as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| CngError(format!("QueryContextAttributesA Keying Material: {:?}", e)))?;
            println!("got srtp params: {:?}", srtp_parameters);

            let label = b"EXTRACTOR-dtls_srtp\0";
            let keying_material_info = SecPkgContext_KeyingMaterialInfo {
                cbLabel: label.len() as u16,
                pszLabel: windows_strings::PSTR(label.as_ptr() as *mut u8),
                cbKeyingMaterial: 56,
                cbContextValue: 0,
                pbContextValue: std::ptr::null_mut(),
            };
            SetContextAttributesW(
                self.ctx_handle.as_ref().unwrap() as *const _,
                SECPKG_ATTR_KEYING_MATERIAL_INFO,
                &keying_material_info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<SecPkgContext_KeyingMaterialInfo>() as u32,
            )
            .map_err(|e| CngError(format!("SetContextAttributesA Keying Material: {:?}", e)))?;

            let mut keying_material = SecPkgContext_KeyingMaterial::default();
            QueryContextAttributesExW(
                self.ctx_handle.as_ref().unwrap() as *const _,
                SECPKG_ATTR(SECPKG_ATTR_KEYING_MATERIAL),
                &mut keying_material as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<SecPkgContext_KeyingMaterial>() as u32,
            )
            .map_err(|e| CngError(format!("QueryContextAttributesA Keying Material: {:?}", e)))?;
            println!("got keying_material params: {:?}", keying_material);

            output_events.push_back(DtlsEvent::SrtpKeyingMaterial(
                KeyingMaterial::new(
                    std::slice::from_raw_parts(
                        keying_material.pbKeyingMaterial,
                        keying_material.cbKeyingMaterial as usize,
                    )
                    .to_vec(),
                ),
                srtp_profile_from_id(srtp_parameters.ProtectionProfile),
            ));

            let mut remote_cert_context_ptr = std::ptr::null_mut();
            QueryContextAttributesA(
                self.ctx_handle.as_ref().unwrap() as *const _,
                SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                &mut remote_cert_context_ptr as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| CngError(format!("QueryContextAttributesA: {:?}", e)))?;
            let remote_cert_context = *(remote_cert_context_ptr as *const CERT_CONTEXT);

            let fingerprint = super::cert::cert_fingerprint(&remote_cert_context);
            println!("fingerprint: {}", fingerprint);
            output_events.push_back(DtlsEvent::RemoteFingerprint(fingerprint));

            _ = CertFreeCertificateContext(Some(remote_cert_context_ptr));

            Ok(())
        }
    }
}

impl DtlsInner for CngDtlsImpl {
    fn set_active(&mut self, active: bool) {
        self.active = Some(active);

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
        println!("schannel_cred: {:?}", schannel_cred);
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
            println!(
                "AcquireCredentialsHandleA {} {} {creds_expiry}",
                cred_handle.dwLower, cred_handle.dwUpper
            );
        }

        if active {
            self.state = HandshakeState::ClientHandshake;
        } else {
            self.state = HandshakeState::ServerHandshake;
        }
    }

    fn is_active(&self) -> Option<bool> {
        self.active
    }

    fn handle_receive(
        &mut self,
        datagram: &[u8],
        o: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        let state = self.state;
        match state {
            HandshakeState::Completed => {
                todo!("Needs to decrypt packet and add Data event");
                // let mut buf = vec![0; 2000];
                // let n = match self.tls.read(&mut buf) {
                //     Ok(v) => v,
                //     Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                //         return Ok(());
                //     }
                //     Err(e) => return Err(e.into()),
                // };
                // buf.truncate(n);

                // o.push_back(DtlsEvent::Data(buf));
            }
            HandshakeState::ClientHandshake => self.client_handshake(Some(datagram), o),
            HandshakeState::ServerHandshake => self.server_handshake(Some(datagram), o),
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
        // OpenSSL has a built-in timeout of 1 second that is doubled for
        // each retry. There is a way to get direct control over the
        // timeout (using DTLS_set_timer_cb), but that function doesn't
        // appear to be exposed in openssl crate yet.
        // TODO(martin): Write PR for openssl crate to be able to use this
        // callback to make a tighter timeout handling here.
        match self.state {
            HandshakeState::ClientHandshake | HandshakeState::ServerHandshake => {
                Some(now + Duration::from_millis(500))
            }
            _ => None,
        }
    }

    // This is DATA sent from client over SCTP/DTLS
    fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.input.push_back(data.to_vec());
        // } else if self.tls.complete_handshake_until_block()? {
        //     output.push_back(DtlsEvent::Connected);

        //     let (keying_material, srtp_profile, fingerprint) = self
        //         .tls
        //         .take_srtp_keying_material()
        //         .expect("Exported keying material");

        //     output.push_back(DtlsEvent::RemoteFingerprint(fingerprint));

        //     output.push_back(DtlsEvent::SrtpKeyingMaterial(keying_material, srtp_profile));
        //     Ok(false)
        // } else {
        //     Ok(true)
        // }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.state == HandshakeState::Completed
    }

    fn handle_handshake(&mut self, output: &mut VecDeque<DtlsEvent>) -> Result<bool, CryptoError> {
        if self.state == HandshakeState::ClientHandshake {
            self.client_handshake(None, output)?;
        }
        Ok(false)
    }
}

fn srtp_profile_from_id(id: u16) -> SrtpProfile {
    match id {
        0x0007 => SrtpProfile::AeadAes128Gcm,
        0x0700 => SrtpProfile::AeadAes128Gcm,
        0x0001 => SrtpProfile::Aes128CmSha1_80,
        0x0100 => SrtpProfile::Aes128CmSha1_80,
        _ => panic!("Unknown SRTP profile ID: {:04x}", id),
    }
}
// pub fn dtls_create_ctx(cert: &CngDtlsCert) -> Result<SslContext, CryptoError> {
// // TODO: Technically we want to disallow DTLS < 1.2, but that requires
// // us to use this commented out unsafe. We depend on browsers disallowing
// // it instead.
// // let method = unsafe { SslMethod::from_ptr(DTLSv1_2_method()) };
// let mut ctx = SslContextBuilder::new(SslMethod::dtls())?;

// ctx.set_cipher_list(DTLS_CIPHERS)?;
// let srtp_profiles = {
//     // Rust can't join directly to a string, need to allocate a vec first :(
//     // This happens very rarely so the extra allocations don't matter
//     let all: Vec<_> = SrtpProfile::ALL
//         .iter()
//         .map(SrtpProfile::windows_cng_name)
//         .collect();

//     all.join(":")
// };
// ctx.set_tlsext_use_srtp(&srtp_profiles)?;

// let mut mode = SslVerifyMode::empty();
// mode.insert(SslVerifyMode::PEER);
// mode.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
// ctx.set_verify_callback(mode, |_ok, _ctx| true);

// ctx.set_private_key(&cert.pkey)?;
// ctx.set_certificate(&cert.x509)?;

// let mut options = SslOptions::empty();
// options.insert(SslOptions::SINGLE_ECDH_USE);
// options.insert(SslOptions::NO_DTLSV1);
// ctx.set_options(options);

// let ctx = ctx.build();

// Ok(ctx)
// }

// pub fn dtls_ssl_create(ctx: &SslContext) -> Result<Ssl, CryptoError> {
// panic!("Not impl!");
// let mut ssl = Ssl::new(ctx)?;
// ssl.set_mtu(DATAGRAM_MTU as u32)?;

// let eckey = EcKey::from_curve_name(DTLS_EC_CURVE)?;
// ssl.set_tmp_ecdh(&eckey)?;

// Ok(ssl)
// }
