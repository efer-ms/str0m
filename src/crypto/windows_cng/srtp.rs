use std::ptr::addr_of;

use crate::crypto::srtp::SrtpCryptoImpl;
use crate::crypto::srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80};
use crate::crypto::windows_cng::from_ntstatus_result;
use crate::crypto::CryptoError;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    BCryptDecrypt, BCryptEncrypt, BCryptGenerateSymmetricKey, BCryptOpenAlgorithmProvider,
    BCryptSetProperty, BCRYPT_AES_ALGORITHM, BCRYPT_AES_ECB_ALG_HANDLE, BCRYPT_AES_GCM_ALG_HANDLE,
    BCRYPT_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, BCRYPT_BLOCK_PADDING, BCRYPT_CHAINING_MODE,
    BCRYPT_CHAIN_MODE_ECB, BCRYPT_FLAGS, BCRYPT_KEY_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
};

pub struct CngSrtpCryptoImpl;

impl SrtpCryptoImpl for CngSrtpCryptoImpl {
    type Aes128CmSha1_80 = CngAes128CmSha1_80;
    type AeadAes128Gcm = CngAeadAes128Gcm;

    fn srtp_aes_128_ecb_round(key: &[u8], input: &[u8], output: &mut [u8]) {
        unsafe {
            let mut key_handle = BCRYPT_KEY_HANDLE::default();
            from_ntstatus_result(BCryptGenerateSymmetricKey(
                BCRYPT_AES_ECB_ALG_HANDLE,
                &mut key_handle,
                None,
                key,
                0,
            ))
            .expect("AES key");

            // Run AES
            let mut count = 0;
            from_ntstatus_result(BCryptEncrypt(
                key_handle,
                Some(input),
                None,
                None,
                Some(output),
                &mut count,
                BCRYPT_BLOCK_PADDING,
            ))
            .expect("AES encrypt");

            assert_eq!(count, 16 + 16); // block size
        }
    }
}

pub struct CngAes128CmSha1_80 {
    _alg_handle: BCRYPT_ALG_HANDLE,
    key_handle: BCRYPT_KEY_HANDLE,
    _encrypt: bool,
}

unsafe impl Send for CngAes128CmSha1_80 {}
unsafe impl Sync for CngAes128CmSha1_80 {}

impl aes_128_cm_sha1_80::CipherCtx for CngAes128CmSha1_80 {
    fn new(key: aes_128_cm_sha1_80::AesKey, encrypt: bool) -> Self
    where
        Self: Sized,
    {
        unsafe {
            // let t = cipher::Cipher::aes_128_ctr();
            // let mut ctx = CipherCtx::new().expect("a reusable cipher context");
            let mut alg_handle = BCRYPT_ALG_HANDLE::default();
            from_ntstatus_result(BCryptOpenAlgorithmProvider(
                &mut alg_handle,
                PCWSTR(BCRYPT_AES_ALGORITHM.as_ptr()),
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            ))
            .expect("alg provider");
            // TODO(efer): CTR mode doesn't exist in CNG need to understand how to configure it
            let chain_mode = BCRYPT_CHAIN_MODE_ECB.as_wide();
            let chain_mode =
                std::slice::from_raw_parts(chain_mode.as_ptr() as *const u8, chain_mode.len() * 2);
            from_ntstatus_result(BCryptSetProperty(
                alg_handle.into(),
                BCRYPT_CHAINING_MODE,
                chain_mode,
                0,
            ))
            .expect("set chain mode");
            // if encrypt {
            //     ctx.encrypt_init(Some(t), Some(&key[..]), None)
            //         .expect("enc init");
            // } else {
            //     ctx.decrypt_init(Some(t), Some(&key[..]), None)
            //         .expect("enc init");
            // }
            let mut key_handle = BCRYPT_KEY_HANDLE::default();
            from_ntstatus_result(BCryptGenerateSymmetricKey(
                alg_handle,
                &mut key_handle,
                None,
                &key,
                0,
            ))
            .expect("generate sym key");

            // CngAes128CmSha1_80(ctx)
            CngAes128CmSha1_80 {
                _alg_handle: alg_handle,
                key_handle,
                _encrypt: encrypt,
            }
        }
    }

    fn encrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        unsafe {
            let mut iv = iv.clone();
            // self.0.encrypt_init(None, None, Some(iv)).unwrap();
            // let count = self.0.cipher_update(input, Some(output)).unwrap();
            // self.0.cipher_final(&mut output[count..]).unwrap();
            let mut count = 0;
            from_ntstatus_result(BCryptEncrypt(
                self.key_handle,
                Some(input),
                None,
                Some(&mut iv),
                Some(output),
                &mut count,
                BCRYPT_BLOCK_PADDING,
            ))?;

            Ok(())
        }
    }

    fn decrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        unsafe {
            let mut iv = iv.clone();
            // self.0.decrypt_init(None, None, Some(iv)).unwrap();
            // let count = self.0.cipher_update(input, Some(output)).unwrap();
            // self.0.cipher_final(&mut output[count..]).unwrap();
            let mut count = 0;
            from_ntstatus_result(BCryptDecrypt(
                self.key_handle,
                Some(input),
                None,
                Some(&mut iv),
                Some(output),
                &mut count,
                BCRYPT_BLOCK_PADDING,
            ))?;

            Ok(())
        }
    }
}

pub struct CngAeadAes128Gcm {
    key_handle: BCRYPT_KEY_HANDLE,
}

unsafe impl Send for CngAeadAes128Gcm {}
unsafe impl Sync for CngAeadAes128Gcm {}

impl aead_aes_128_gcm::CipherCtx for CngAeadAes128Gcm {
    fn new(key: aead_aes_128_gcm::AeadKey, _encrypt: bool) -> Self
    where
        Self: Sized,
    {
        unsafe {
            let mut key_handle = BCRYPT_KEY_HANDLE::default();
            from_ntstatus_result(BCryptGenerateSymmetricKey(
                BCRYPT_AES_GCM_ALG_HANDLE,
                &mut key_handle,
                None,
                &key,
                0,
            ))
            .expect("generate sym key");

            CngAeadAes128Gcm { key_handle }
        }
    }

    fn encrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        unsafe {
            assert!(
                aad.len() >= 12,
                "Associated data length MUST be at least 12 octets"
            );

            let aad_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                pbAuthData: aad.as_ptr() as *mut u8,
                cbAuthData: aad.len() as u32,
                dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
                cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                pbTag: output[input.len()..].as_ptr() as *mut u8,
                cbTag: aead_aes_128_gcm::TAG_LEN as u32,
                pbNonce: iv.as_ptr() as *mut u8,
                cbNonce: iv.len() as u32,
                ..Default::default()
            };

            let mut _count = 0;
            from_ntstatus_result(BCryptEncrypt(
                self.key_handle,
                Some(input),
                Some(addr_of!(aad_info) as *const std::ffi::c_void),
                None,
                Some(output),
                &mut _count,
                BCRYPT_FLAGS(0),
            ))?;

            Ok(())
        }
    }

    fn decrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        unsafe {
            // This needs to be converted to an error maybe
            assert!(input.len() >= aead_aes_128_gcm::TAG_LEN);

            let (cipher_text, tag) = input.split_at(input.len() - aead_aes_128_gcm::TAG_LEN);

            // TODO(efer): Optimize this, we shouldn't need a vec, only need it when
            // we have multiple aad slices, otherwise should just use aads[0].
            let aad = if aads.len() == 1 {
                &aads[0].to_vec()
            } else {
                &aads.concat()
            };

            let aad_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                pbAuthData: aad.as_ptr() as *mut u8,
                cbAuthData: aad.len() as u32,
                dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
                cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                pbTag: tag.as_ptr() as *mut u8,
                cbTag: aead_aes_128_gcm::TAG_LEN as u32,
                pbNonce: iv.as_ptr() as *mut u8,
                cbNonce: iv.len() as u32,
                ..Default::default()
            };

            let mut count = 0;
            from_ntstatus_result(BCryptDecrypt(
                self.key_handle,
                Some(cipher_text),
                Some(addr_of!(aad_info) as *const std::ffi::c_void),
                None,
                Some(output),
                &mut count,
                BCRYPT_FLAGS(0),
            ))?;

            Ok(count as usize)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_1() {
        let mut out = [0u8; 32];
        CngSrtpCryptoImpl::srtp_aes_128_ecb_round(
            &hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c"),
            &hex_to_vec("6bc1bee22e409f96e93d7e117393172a"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "3ad77bb40d7a3660a89ecaf32466ef97");
    }

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_2() {
        let mut out = [0u8; 32];
        CngSrtpCryptoImpl::srtp_aes_128_ecb_round(
            &hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c"),
            &hex_to_vec("ae2d8a571e03ac9c9eb76fac45af8e51"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "f5d3d58503b9699de785895a96fdbaaf");
    }

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_3() {
        let mut out = [0u8; 32];
        CngSrtpCryptoImpl::srtp_aes_128_ecb_round(
            &hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c"),
            &hex_to_vec("30c81c46a35ce411e5fbc1191a0a52ef"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "43b1cd7f598ece23881b00e3ed030688");
    }

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_4() {
        let mut out = [0u8; 32];
        CngSrtpCryptoImpl::srtp_aes_128_ecb_round(
            &hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c"),
            &hex_to_vec("f69f2445df4f9b17ad2b417be66c3710"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "7b0c785e27e8ad3f8223207104725dd4");
    }

    fn slice_to_hex(hash: &[u8]) -> String {
        let mut s = String::new();
        for byte in hash.iter() {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }

    fn hex_to_vec(hex: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..hex.len() / 2 {
            let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
            v.push(byte);
        }
        v
    }
}
