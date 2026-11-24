//! Signing and key loading implementations using OpenSSL.

use dimpl::crypto::Buf;
use dimpl::crypto::{HashAlgorithm, KeyProvider};
use dimpl::crypto::{SignatureAlgorithm, SignatureVerifier, SigningKey as SigningKeyTrait};
use dimpl::{CryptoError, CryptoOperation};

use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};

/// ECDSA signing key implementation using OpenSSL.
struct EcdsaSigningKey {
    pkey: PKey<openssl::pkey::Private>,
    curve: EcCurve,
}

#[derive(Clone, Copy, Debug)]
enum EcCurve {
    P256,
    P384,
}

impl std::fmt::Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.curve {
            EcCurve::P256 => f.debug_tuple("EcdsaSigningKey::P256").finish(),
            EcCurve::P384 => f.debug_tuple("EcdsaSigningKey::P384").finish(),
        }
    }
}

impl SigningKeyTrait for EcdsaSigningKey {
    fn sign(
        &mut self,
        data: &[u8],
        hash_alg: HashAlgorithm,
        out: &mut Buf,
    ) -> Result<(), CryptoError> {
        let key_hash = self.hash_algorithm();
        if hash_alg != key_hash {
            return Err(CryptoError::SigningKeyHashMismatch {
                key_hash,
                requested: hash_alg,
            });
        }

        let md = match self.curve {
            EcCurve::P256 => MessageDigest::sha256(),
            EcCurve::P384 => MessageDigest::sha384(),
        };

        let mut signer = openssl::sign::Signer::new(md, &self.pkey)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Sign))?;
        signer
            .update(data)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Sign))?;
        let signature = signer
            .sign_to_vec()
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Sign))?;

        out.clear();
        out.extend_from_slice(&signature);
        Ok(())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self.curve {
            EcCurve::P256 => HashAlgorithm::SHA256,
            EcCurve::P384 => HashAlgorithm::SHA384,
        }
    }

    fn supported_hash_algorithms(&self) -> &[HashAlgorithm] {
        // openssl ECDSA key is bound to the curve's default hash here;
        // only one is supported.
        match self.curve {
            EcCurve::P256 => &[HashAlgorithm::SHA256],
            EcCurve::P384 => &[HashAlgorithm::SHA384],
        }
    }
}

/// Key provider implementation.
#[derive(Debug)]
pub(super) struct OsslKeyProvider;

impl OsslKeyProvider {
    fn pkey_to_signing_key(
        &self,
        pkey: PKey<openssl::pkey::Private>,
    ) -> Result<Box<dyn SigningKeyTrait>, CryptoError> {
        let ec_key = pkey.ec_key().map_err(|_| CryptoError::InvalidPrivateKey)?;
        let nid = ec_key
            .group()
            .curve_name()
            .ok_or(CryptoError::MissingEcCurveParameter)?;

        let curve = match nid {
            Nid::X9_62_PRIME256V1 => EcCurve::P256,
            Nid::SECP384R1 => EcCurve::P384,
            _ => return Err(CryptoError::UnsupportedEcCurve),
        };

        Ok(Box::new(EcdsaSigningKey { pkey, curve }))
    }
}

impl KeyProvider for OsslKeyProvider {
    fn load_private_key(&self, key_der: &[u8]) -> Result<Box<dyn SigningKeyTrait>, CryptoError> {
        // Try PEM format first using OpenSSL's native parser
        if key_der.starts_with(b"-----BEGIN") {
            let pkey =
                PKey::private_key_from_pem(key_der).map_err(|_| CryptoError::InvalidPrivateKey)?;
            return self.pkey_to_signing_key(pkey);
        }

        // Try PKCS#8 format first, then raw EC key
        let pkey = PKey::private_key_from_der(key_der)
            .or_else(|_| {
                // Try as SEC1 EC private key
                let ec_key = EcKey::private_key_from_der(key_der)
                    .map_err(|_| CryptoError::InvalidPrivateKey)?;
                PKey::from_ec_key(ec_key).map_err(|_| CryptoError::InvalidPrivateKey)
            })
            .map_err(|_| CryptoError::InvalidPrivateKey)?;

        self.pkey_to_signing_key(pkey)
    }
}

/// Signature verifier implementation.
#[derive(Debug)]
pub(super) struct OsslSignatureVerifier;

impl SignatureVerifier for OsslSignatureVerifier {
    fn verify_signature(
        &self,
        cert_der: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlgorithm,
        sig_alg: SignatureAlgorithm,
    ) -> Result<(), CryptoError> {
        if !matches!(sig_alg, SignatureAlgorithm::ECDSA | SignatureAlgorithm::RSA) {
            return Err(CryptoError::UnsupportedSignatureAlgorithm(sig_alg));
        }

        let md = match hash_alg {
            HashAlgorithm::SHA256 => MessageDigest::sha256(),
            HashAlgorithm::SHA384 => MessageDigest::sha384(),
            _ => {
                return Err(CryptoError::UnsupportedSignaturePair {
                    signature: sig_alg,
                    hash: hash_alg,
                });
            }
        };

        // Use OpenSSL's native X.509 parser to extract the public key directly.
        // This avoids fragile key-length-based curve detection and manual SPKI parsing.
        let cert = openssl::x509::X509::from_der(cert_der)
            .map_err(|_| CryptoError::CertificateParseFailed)?;
        let pkey = cert
            .public_key()
            .map_err(|_| CryptoError::InvalidSubjectPublicKey)?;
        let group = match (sig_alg, pkey.id()) {
            (SignatureAlgorithm::ECDSA, Id::EC) => {
                let nid = pkey
                    .ec_key()
                    .map_err(|_| CryptoError::InvalidSubjectPublicKey)?
                    .group()
                    .curve_name()
                    .ok_or(CryptoError::MissingEcCurveParameter)?;
                Some(match nid {
                    Nid::X9_62_PRIME256V1 => dimpl::NamedGroup::Secp256r1,
                    Nid::SECP384R1 => dimpl::NamedGroup::Secp384r1,
                    _ => return Err(CryptoError::UnsupportedEcCurve),
                })
            }
            (SignatureAlgorithm::RSA, Id::RSA) => None,
            _ => return Err(CryptoError::InvalidSubjectPublicKey),
        };

        // Verify the signature
        let mut verifier = openssl::sign::Verifier::new(md, &pkey)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::VerifySignature))?;
        verifier
            .update(data)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::VerifySignature))?;
        let valid = verifier
            .verify(signature)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::VerifySignature))?;

        if valid {
            Ok(())
        } else {
            Err(match group {
                Some(group) => CryptoError::SignatureVerificationFailed {
                    signature: sig_alg,
                    hash: hash_alg,
                    group,
                },
                None => CryptoError::OperationFailed(CryptoOperation::VerifySignature),
            })
        }
    }
}

/// Static instance of the key provider.
pub(super) static KEY_PROVIDER: OsslKeyProvider = OsslKeyProvider;

/// Static instance of the signature verifier.
pub(super) static SIGNATURE_VERIFIER: OsslSignatureVerifier = OsslSignatureVerifier;

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::ec::EcGroup;
    use openssl::pkey::Private;
    use openssl::rsa::{Padding, Rsa};
    use openssl::sign::Signer;
    use openssl::x509::{X509, X509NameBuilder};

    #[test]
    fn rsa_certificate_signatures() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let cert = certificate(&key);

        for (hash, md) in [
            (HashAlgorithm::SHA256, MessageDigest::sha256()),
            (HashAlgorithm::SHA384, MessageDigest::sha384()),
        ] {
            let mut signer = Signer::new(md, &key).unwrap();
            signer.set_rsa_padding(Padding::PKCS1).unwrap();
            let signature = signer.sign_oneshot_to_vec(b"message").unwrap();

            SIGNATURE_VERIFIER
                .verify_signature(&cert, b"message", &signature, hash, SignatureAlgorithm::RSA)
                .unwrap();
            assert_eq!(
                SIGNATURE_VERIFIER.verify_signature(
                    &cert,
                    b"tampered",
                    &signature,
                    hash,
                    SignatureAlgorithm::RSA,
                ),
                Err(CryptoError::OperationFailed(
                    CryptoOperation::VerifySignature
                ))
            );
            assert_eq!(
                SIGNATURE_VERIFIER.verify_signature(
                    &cert,
                    b"message",
                    &signature,
                    hash,
                    SignatureAlgorithm::ECDSA,
                ),
                Err(CryptoError::InvalidSubjectPublicKey)
            );
        }
    }

    fn certificate(key: &PKey<Private>) -> Vec<u8> {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test").unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.set_pubkey(key).unwrap();
        cert.sign(key, MessageDigest::sha256()).unwrap();
        cert.build().to_der().unwrap()
    }

    #[test]
    fn ecdsa_certificate_signatures() {
        for (nid, group) in [
            (Nid::X9_62_PRIME256V1, dimpl::NamedGroup::Secp256r1),
            (Nid::SECP384R1, dimpl::NamedGroup::Secp384r1),
        ] {
            let ec_group = EcGroup::from_curve_name(nid).unwrap();
            let key = PKey::from_ec_key(EcKey::generate(&ec_group).unwrap()).unwrap();
            let cert = certificate(&key);

            for (hash, md) in [
                (HashAlgorithm::SHA256, MessageDigest::sha256()),
                (HashAlgorithm::SHA384, MessageDigest::sha384()),
            ] {
                let mut signer = Signer::new(md, &key).unwrap();
                let signature = signer.sign_oneshot_to_vec(b"message").unwrap();

                SIGNATURE_VERIFIER
                    .verify_signature(
                        &cert,
                        b"message",
                        &signature,
                        hash,
                        SignatureAlgorithm::ECDSA,
                    )
                    .unwrap();
                assert_eq!(
                    SIGNATURE_VERIFIER.verify_signature(
                        &cert,
                        b"tampered",
                        &signature,
                        hash,
                        SignatureAlgorithm::ECDSA,
                    ),
                    Err(CryptoError::SignatureVerificationFailed {
                        signature: SignatureAlgorithm::ECDSA,
                        hash,
                        group,
                    })
                );
                assert_eq!(
                    SIGNATURE_VERIFIER.verify_signature(
                        &cert,
                        b"message",
                        &signature,
                        hash,
                        SignatureAlgorithm::RSA,
                    ),
                    Err(CryptoError::InvalidSubjectPublicKey)
                );
            }
        }
    }

    #[test]
    fn unsupported_signature_algorithms_and_hashes() {
        assert_eq!(
            SIGNATURE_VERIFIER.verify_signature(
                &[],
                b"message",
                &[],
                HashAlgorithm::SHA256,
                SignatureAlgorithm::DSA,
            ),
            Err(CryptoError::UnsupportedSignatureAlgorithm(
                SignatureAlgorithm::DSA
            ))
        );
        for signature in [SignatureAlgorithm::RSA, SignatureAlgorithm::ECDSA] {
            assert_eq!(
                SIGNATURE_VERIFIER.verify_signature(
                    &[],
                    b"message",
                    &[],
                    HashAlgorithm::SHA512,
                    signature,
                ),
                Err(CryptoError::UnsupportedSignaturePair {
                    signature,
                    hash: HashAlgorithm::SHA512,
                })
            );
        }
    }
}
