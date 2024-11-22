use std::ptr::addr_of;

use crate::crypto::srtp::SrtpCryptoImpl;
use crate::crypto::srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80};
use crate::crypto::windows_cng::from_ntstatus_result;
use crate::crypto::CryptoError;
use windows::Win32::Security::Cryptography::{
    BCryptDecrypt, BCryptEncrypt, BCryptGenerateSymmetricKey, BCRYPT_AES_ECB_ALG_HANDLE,
    BCRYPT_AES_GCM_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, BCRYPT_BLOCK_PADDING, BCRYPT_FLAGS,
    BCRYPT_KEY_HANDLE,
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
    key_handle: BCRYPT_KEY_HANDLE,
}

unsafe impl Send for CngAes128CmSha1_80 {}
unsafe impl Sync for CngAes128CmSha1_80 {}

impl CngAes128CmSha1_80 {
    /// Encrypts or decrypts the input data using AES-128 in ECB-CTR mode. CTR mode essentially
    /// amounts to encrypting the a buffer with a repeated IV, each repetition incrementing the IV
    /// value by one. The encryption is using ECB mode. Then the encrypted output is XORed with the
    /// input data. So encryption reads something like this: `ciphertext = AES(key, IV) XOR plaintext`.
    /// Since XOR is symmetric, decryption is the same operation (`plaintext = AEX(key, IV) XOR ciphertext`).
    fn transform(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        unsafe {
            // First, we'll make a copy of the IV with a countered as many times as needed into a new
            // countered_iv.
            let mut iv = iv.clone();
            let mut countered_iv = [0u8; 2048];
            let mut offset = 0;
            while offset <= input.len() {
                let mut _count = 0;
                let start = offset;
                let end = offset + 16;
                countered_iv[start..end].copy_from_slice(&iv);
                offset += 16;
                for idx in 0..16 {
                    let n = iv[15 - idx];
                    if n == 0xff {
                        iv[15 - idx] = 0;
                    } else {
                        iv[15 - idx] += 1;
                        break;
                    }
                }
            }

            // Now, we'll encrypt the countered IV. CNG can do this in-place, so we'll need a separate
            // reference to the slice, but fool the borrow-checker, otherwise it won't like us passing
            // the immutable and mutable reference to BCryptEncrypt.
            let encrypted_countered_iv =
                std::slice::from_raw_parts_mut(countered_iv.as_mut_ptr(), countered_iv.len());
            let mut _count = 0;
            from_ntstatus_result(BCryptEncrypt(
                self.key_handle,
                Some(&countered_iv[..offset]),
                None,
                None,
                Some(&mut encrypted_countered_iv[..offset]),
                &mut _count,
                BCRYPT_FLAGS(0),
            ))?;

            // XOR the intermediate_output with the input
            for i in 0..input.len() {
                output[i] = input[i] ^ encrypted_countered_iv[i];
            }
        }
        Ok(())
    }
}

impl aes_128_cm_sha1_80::CipherCtx for CngAes128CmSha1_80 {
    /// Create a new context for AES-128-CM-SHA1-80 encryption/decryption.
    ///
    /// The encrypt flag is ignored, since the same operation is used for both encryption and
    /// decryption.
    fn new(key: aes_128_cm_sha1_80::AesKey, _encrypt: bool) -> Self
    where
        Self: Sized,
    {
        unsafe {
            let mut key_handle = BCRYPT_KEY_HANDLE::default();
            from_ntstatus_result(BCryptGenerateSymmetricKey(
                BCRYPT_AES_ECB_ALG_HANDLE,
                &mut key_handle,
                None,
                &key,
                0,
            ))
            .expect("generate sym key");
            CngAes128CmSha1_80 { key_handle }
        }
    }

    fn encrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        plain_text: &[u8],
        cipher_text: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.transform(iv, plain_text, cipher_text)
    }

    fn decrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        cipher_text: &[u8],
        plain_text: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.transform(iv, cipher_text, plain_text)
    }
}

pub struct CngAeadAes128Gcm {
    key_handle: BCRYPT_KEY_HANDLE,
}

unsafe impl Send for CngAeadAes128Gcm {}
unsafe impl Sync for CngAeadAes128Gcm {}

impl aead_aes_128_gcm::CipherCtx for CngAeadAes128Gcm {
    /// Create a new context for AES-128-GCM encryption/decryption.
    ///
    /// The encrypt flag is ignored, since it is not needed and the same
    /// key can be used for both encryption and decryption.
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
        additional_auth_data: &[u8],
        plain_text: &[u8],
        cipher_text: &mut [u8],
    ) -> Result<(), CryptoError> {
        unsafe {
            assert!(
                additional_auth_data.len() >= 12,
                "Associated data length MUST be at least 12 octets"
            );

            let auth_cipher_mode_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                pbAuthData: additional_auth_data.as_ptr() as *mut u8,
                cbAuthData: additional_auth_data.len() as u32,
                dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
                cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                pbTag: cipher_text[plain_text.len()..].as_ptr() as *mut u8,
                cbTag: aead_aes_128_gcm::TAG_LEN as u32,
                pbNonce: iv.as_ptr() as *mut u8,
                cbNonce: iv.len() as u32,
                ..Default::default()
            };

            let mut _count = 0;
            from_ntstatus_result(BCryptEncrypt(
                self.key_handle,
                Some(plain_text),
                Some(addr_of!(auth_cipher_mode_info) as *const std::ffi::c_void),
                None,
                Some(cipher_text),
                &mut _count,
                BCRYPT_FLAGS(0),
            ))?;

            Ok(())
        }
    }

    fn decrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        additional_auth_data: &[&[u8]],
        cipher_text: &[u8],
        plaint_text: &mut [u8],
    ) -> Result<usize, CryptoError> {
        unsafe {
            // This needs to be converted to an error maybe
            assert!(cipher_text.len() >= aead_aes_128_gcm::TAG_LEN);

            let (cipher_text, tag) =
                cipher_text.split_at(cipher_text.len() - aead_aes_128_gcm::TAG_LEN);

            // TODO(efer): Optimize this, we shouldn't need a vec, only need it when
            // we have multiple aad slices, otherwise should just use aads[0].
            let additional_auth_data = if additional_auth_data.len() == 1 {
                &additional_auth_data[0].to_vec()
            } else {
                &additional_auth_data.concat()
            };

            let auth_cipher_mode_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                pbAuthData: additional_auth_data.as_ptr() as *mut u8,
                cbAuthData: additional_auth_data.len() as u32,
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
                Some(addr_of!(auth_cipher_mode_info) as *const std::ffi::c_void),
                None,
                Some(plaint_text),
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
