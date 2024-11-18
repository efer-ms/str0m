use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use windows::Win32::Security::{Authentication::Identity::*, Credentials::*, Cryptography::*};

use crate::crypto::dtls::DtlsInner;
use crate::crypto::DtlsEvent;
use crate::io::DATAGRAM_MTU_WARN;

use super::cert::CngDtlsCert;
use super::io_buf::IoBuffer;
use super::stream::TlsStream;
use super::{CngError, CryptoError};

// const DTLS_CIPHERS: &str = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
// const DTLS_EC_CURVE: Nid = Nid::X9_62_PRIME256V1;

pub struct CngDtlsImpl {
    /// The TLS stream.
    tls: TlsStream<IoBuffer>,
}

impl CngDtlsImpl {
    pub fn new(cert: CngDtlsCert) -> Result<Self, super::CryptoError> {
        unsafe {
            // OpenSSL is configured with "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"
            // EECDH - Ephemeral Elliptic Curve Diffie-Hellman -> CALG_ECDH_EPHEM
            // EDH - Ephemeral Diffie-Hellman -> CALG_DH_EPHEM
            // AESGCM - AES in Galois/Counter Mode -> CALG_AES (TODO(efer): Not sure about GCM)
            // AES256 - AES with 256-bit key -> CALG_AES_256
            let mut algs = [CALG_ECDH_EPHEM, CALG_DH_EPHEM, CALG_AES, CALG_AES_256];
            let mut cert_contexts = [cert.cert_context];

            let schannel_cred = SCHANNEL_CRED {
                dwVersion: SCHANNEL_CRED_VERSION,
                hRootStore: windows::Win32::Security::Cryptography::HCERTSTORE(std::ptr::null_mut()),

                grbitEnabledProtocols: 0, //SP_PROT_DTLS1_2_SERVER,

                cCreds: cert_contexts.len() as u32,
                paCred: cert_contexts.as_mut_ptr() as *mut *mut CERT_CONTEXT,

                cMappers: 0,
                aphMappers: std::ptr::null_mut(),

                cSupportedAlgs: 0, //algs.len() as u32,
                palgSupportedAlgs: &mut algs[0],

                dwMinimumCipherStrength: 0,
                dwMaximumCipherStrength: 0,
                dwSessionLifespan: 0,
                dwFlags: SCH_CRED_MANUAL_CRED_VALIDATION,
                dwCredFormat: 0,
            };
            println!("schannel_cred: {:?}", schannel_cred);

            // These are the outputs of AcquireCredentialsHandleA
            let mut cred_handle = SecHandle::default();
            let mut creds_expiry: i64 = 0;

            AcquireCredentialsHandleW(
                None,
                UNISP_NAME_W,
                SECPKG_CRED_OUTBOUND,
                None,
                Some(&schannel_cred as *const _ as *const std::ffi::c_void),
                None,
                None,
                &mut cred_handle,
                Some(&mut creds_expiry),
            )
            .map_err(|e| CryptoError::WindowsCng(CngError(format!("failed to make cred: {e}"))))?;
            println!(
                "AcquireCredentialsHandleA {} {} {creds_expiry}",
                cred_handle.dwLower, cred_handle.dwUpper
            );

            Ok(CngDtlsImpl {
                tls: TlsStream::new(cred_handle, IoBuffer::default()),
            })
        }
    }
}

impl DtlsInner for CngDtlsImpl {
    fn set_active(&mut self, active: bool) {
        self.tls.set_active(active);
    }

    fn is_active(&self) -> Option<bool> {
        self.tls.is_active()
    }

    fn handle_receive(&mut self, m: &[u8], o: &mut VecDeque<DtlsEvent>) -> Result<(), CryptoError> {
        self.tls.inner_mut().set_incoming(m);

        if self.handle_handshake(o)? {
            // early return as long as we're handshaking
            return Ok(());
        }

        let mut buf = vec![0; 2000];
        let n = match self.tls.read(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        buf.truncate(n);

        o.push_back(DtlsEvent::Data(buf));

        Ok(())
    }

    fn poll_datagram(&mut self) -> Option<crate::net::DatagramSend> {
        let x = self.tls.inner_mut().pop_outgoing();
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
        self.tls
            .is_handshaking()
            .then(|| now + Duration::from_millis(500))
    }

    fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        Ok(self.tls.write_all(data)?)
    }

    fn is_connected(&self) -> bool {
        self.tls.is_connected()
    }

    fn handle_handshake(&mut self, output: &mut VecDeque<DtlsEvent>) -> Result<bool, CryptoError> {
        if self.tls.is_connected() {
            // Nice. Nothing to do.
            Ok(false)
        } else if self.tls.complete_handshake_until_block()? {
            output.push_back(DtlsEvent::Connected);

            let (keying_material, srtp_profile, fingerprint) = self
                .tls
                .take_srtp_keying_material()
                .expect("Exported keying material");

            output.push_back(DtlsEvent::RemoteFingerprint(fingerprint));

            output.push_back(DtlsEvent::SrtpKeyingMaterial(keying_material, srtp_profile));
            Ok(false)
        } else {
            Ok(true)
        }
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
