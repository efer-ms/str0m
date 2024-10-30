use std::ptr::addr_of;

use crate::crypto::srtp::SrtpCryptoImpl;
use crate::crypto::srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80};
use crate::crypto::windows_cng::from_ntstatus_result;
use crate::crypto::CryptoError;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    BCryptDecrypt, BCryptEncrypt, BCryptGenerateSymmetricKey, BCryptOpenAlgorithmProvider,
    BCryptSetProperty, BCRYPT_AES_ALGORITHM, BCRYPT_ALG_HANDLE,
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, BCRYPT_BLOCK_LENGTH, BCRYPT_BLOCK_PADDING,
    BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC, BCRYPT_CHAIN_MODE_ECB, BCRYPT_CHAIN_MODE_GCM,
    BCRYPT_FLAGS, BCRYPT_KEY_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
};

pub struct CngSrtpCryptoImpl;

impl SrtpCryptoImpl for CngSrtpCryptoImpl {
    type Aes128CmSha1_80 = CngAes128CmSha1_80;
    type AeadAes128Gcm = CngAeadAes128Gcm;

    fn srtp_aes_128_ecb_round(key: &[u8], input: &[u8], output: &mut [u8]) {
        unsafe {
            // let mut aes = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None);
            let mut alg_handle = BCRYPT_ALG_HANDLE::default();
            from_ntstatus_result(BCryptOpenAlgorithmProvider(
                &mut alg_handle,
                PCWSTR(BCRYPT_AES_ALGORITHM.as_ptr()),
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            ))
            .expect("AES provider");

            from_ntstatus_result(BCryptSetProperty(
                alg_handle.into(),
                PCWSTR(BCRYPT_CHAIN_MODE_ECB.as_ptr()),
                &[],
                0,
            ))
            .expect("AES configured");

            let mut key_handle = BCRYPT_KEY_HANDLE::default();
            from_ntstatus_result(BCryptGenerateSymmetricKey(
                alg_handle,
                &mut key_handle,
                None,
                key,
                0,
            ))
            .expect("AES key");

            // // Run AES
            // let count = aes.update(input, output).expect("AES update");
            // let rest = aes.finalize(&mut output[count..]).expect("AES finalize");
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

            // assert_eq!(count + rest, 16 + 16); // input len + block size
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
            let chain_mode = BCRYPT_CHAIN_MODE_CBC.as_wide();
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
    _alg_handle: BCRYPT_ALG_HANDLE,
    key_handle: BCRYPT_KEY_HANDLE,
    _encrypt: bool,
}

unsafe impl Send for CngAeadAes128Gcm {}
unsafe impl Sync for CngAeadAes128Gcm {}

impl aead_aes_128_gcm::CipherCtx for CngAeadAes128Gcm {
    fn new(key: aead_aes_128_gcm::AeadKey, encrypt: bool) -> Self
    where
        Self: Sized,
    {
        unsafe {
            // let t = cipher::Cipher::aes_128_gcm();
            // let mut ctx = CipherCtx::new().expect("a reusable cipher context");
            let mut alg_handle = BCRYPT_ALG_HANDLE::default();
            from_ntstatus_result(BCryptOpenAlgorithmProvider(
                &mut alg_handle,
                PCWSTR(BCRYPT_AES_ALGORITHM.as_ptr()),
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            ))
            .expect("alg provider");
            let chain_mode = BCRYPT_CHAIN_MODE_GCM.as_wide();
            let chain_mode =
                std::slice::from_raw_parts(chain_mode.as_ptr() as *const u8, chain_mode.len() * 2);
            from_ntstatus_result(BCryptSetProperty(
                alg_handle.into(),
                BCRYPT_CHAINING_MODE,
                chain_mode,
                0,
            ))
            .expect("set chain mode");
            let iv_len: u32 = aead_aes_128_gcm::IV_LEN as u32;
            let iv_len_ptr = std::slice::from_raw_parts(std::ptr::addr_of!(iv_len) as *const u8, 4);
            from_ntstatus_result(BCryptSetProperty(
                alg_handle.into(),
                BCRYPT_BLOCK_LENGTH,
                iv_len_ptr,
                0,
            ))
            .expect("set iv/block length");
            // if encrypt {
            //     ctx.encrypt_init(Some(t), Some(&key), None)
            //         .expect("enc init");
            //     ctx.set_iv_length(aead_aes_128_gcm::IV_LEN)
            //         .expect("IV length");
            //     ctx.set_padding(false);
            // } else {
            //     ctx.decrypt_init(Some(t), Some(&key), None)
            //         .expect("dec init");
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

            // CngAeadAes128Gcm(ctx)
            CngAeadAes128Gcm {
                _alg_handle: alg_handle,
                key_handle,
                _encrypt: encrypt,
            }
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

            // Set the IV
            // self.0.encrypt_init(None, None, Some(iv)).unwrap();
            let mut iv = iv.clone();

            // Add the additional authenticated data, omitting the output argument informs
            // Crypto that we are providing AAD.
            // let aad_c = self.0.cipher_update(aad, None).unwrap();
            let mut aad_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO::default();
            aad_info.pbAuthData = aad.as_ptr() as *mut u8;
            aad_info.cbAuthData = aad.len() as u32;

            let mut count = 0;
            from_ntstatus_result(BCryptEncrypt(
                self.key_handle,
                None,
                Some(addr_of!(aad_info) as *const std::ffi::c_void),
                Some(&mut iv),
                None,
                &mut count,
                BCRYPT_FLAGS(0),
            ))?;
            // TODO: This should maybe be an error
            assert!(count as usize == aad.len());

            // let count = self.0.cipher_update(input, Some(output)).unwrap();
            // let final_count = self.0.cipher_final(&mut output[count..]).unwrap();
            let mut final_count = 0;
            from_ntstatus_result(BCryptEncrypt(
                self.key_handle,
                Some(input),
                None,
                Some(&mut iv),
                Some(output),
                &mut final_count,
                BCRYPT_FLAGS(0),
            ))?;

            // Get the authentication tag and append it to the output
            // self.0
            //     .tag(&mut output[tag_offset..tag_offset + aead_aes_128_gcm::TAG_LEN])
            //     .unwrap();
            let tag_offset = count + final_count;
            let mut aad_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO::default();
            aad_info.pbTag = output[tag_offset as usize..].as_ptr() as *mut u8;
            aad_info.cbTag = aead_aes_128_gcm::TAG_LEN as u32;
            from_ntstatus_result(BCryptEncrypt(
                self.key_handle,
                None,
                Some(addr_of!(aad_info) as *const std::ffi::c_void),
                Some(&mut iv),
                None,
                &mut count,
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

            // self.0.decrypt_init(None, None, Some(iv)).unwrap();
            let mut iv = iv.clone();

            // Add the additional authenticated data, omitting the output argument informs
            // OpenSSL that we are providing AAD.
            // With this the authentication tag will be verified.
            for aad in aads {
                //self.0.cipher_update(aad, None).unwrap();
                let mut aad_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO::default();
                aad_info.pbAuthData = aad.as_ptr() as *mut u8;
                aad_info.cbAuthData = aad.len() as u32;

                let mut count = 0;
                from_ntstatus_result(BCryptDecrypt(
                    self.key_handle,
                    None,
                    Some(addr_of!(aad_info) as *const std::ffi::c_void),
                    Some(&mut iv),
                    None,
                    &mut count,
                    BCRYPT_FLAGS(0),
                ))?;
                // TODO: This should maybe be an error
                assert!(count as usize == aad.len());
            }

            // self.0.set_tag(tag).unwrap();
            let mut count = 0;
            let mut aad_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO::default();
            aad_info.pbTag = tag.as_ptr() as *mut u8;
            aad_info.cbTag = tag.len() as u32;
            from_ntstatus_result(BCryptDecrypt(
                self.key_handle,
                None,
                Some(addr_of!(aad_info) as *const std::ffi::c_void),
                Some(&mut iv),
                None,
                &mut count,
                BCRYPT_FLAGS(0),
            ))?;

            // let count = self.0.cipher_update(cipher_text, Some(output)).unwrap();
            // let final_count = self.0.cipher_final(&mut output[count..]).unwrap();
            let mut final_count = 0;
            from_ntstatus_result(BCryptDecrypt(
                self.key_handle,
                Some(cipher_text),
                None,
                Some(&mut iv),
                Some(output),
                &mut final_count,
                BCRYPT_FLAGS(0),
            ))?;

            Ok(final_count as usize)
        }
    }
}
