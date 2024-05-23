use hkdf::Hkdf;
use ring::{
    aead::AES_128_GCM,
    agreement::{agree_ephemeral, EphemeralPrivateKey, PublicKey, UnparsedPublicKey, X25519},
    rand::{SecureRandom, SystemRandom},
};
use scrypt::{scrypt, Params};
use sha2::Sha256;

use crate::OblivionException;

/// Generate a Randomized Salt
///
/// `generate_random_salt` will generate a random salt using the `ring` library.
///
/// The length of the salt is 16 bytes, which is the length of the key used for AES-GCM encryption.
///
/// # Example
/// ```rust
/// # use oblivion::utils::generator::generate_random_salt;
/// let salt = salt();
/// ```
pub fn salt() -> Vec<u8> {
    let rng = SystemRandom::new();
    let mut key_bytes = vec![0; AES_128_GCM.key_len()];
    rng.fill(&mut key_bytes).unwrap();
    key_bytes
}

/// Create an ECC key
///
/// `generate_key_pair` will create an ECC key and return a (private key, public key) pair of `(EphemeralSecret, PublicKey)`.
///
/// We use `X25519` curve for ECC operations.
///
/// ```rust
/// # use oblivion::utils::generator::generate_key_pair;
/// let (private_key, public_key) = key_pair();
/// ```
pub fn key_pair() -> (EphemeralPrivateKey, PublicKey) {
    let rng = SystemRandom::new();
    let private_key = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let public_key = private_key.compute_public_key().unwrap();
    (private_key, public_key)
}

#[derive(Debug)]
pub struct SharedKey {
    shared_key: Vec<u8>,
}

impl SharedKey {
    pub fn new(
        private_key: EphemeralPrivateKey,
        public_key: &PublicKey,
    ) -> Result<Self, OblivionException> {
        let public_key = UnparsedPublicKey::new(&X25519, public_key.as_ref().to_vec());
        match agree_ephemeral(private_key, &public_key, |key| key.to_vec()) {
            Ok(shared_key) => Ok(Self { shared_key }),
            Err(e) => Err(OblivionException::SharedKeyError { e }),
        }
    }

    pub fn scrypt(&mut self, salt: &[u8]) -> Result<Vec<u8>, OblivionException> {
        let mut aes_key = [0u8; 16];

        match scrypt(
            &self.shared_key,
            &salt,
            &Params::new(12, 8, 1, 16).unwrap(),
            &mut aes_key,
        ) {
            Ok(()) => Ok(aes_key.to_vec()),
            Err(e) => Err(OblivionException::InvalidOutputLen { e }),
        }
    }

    pub fn hkdf(&mut self, salt: &[u8]) -> [u8; 16] {
        let key = Hkdf::<Sha256>::new(Some(salt), &self.shared_key);
        let mut aes_key = [0u8; 16];
        key.expand(&[], &mut aes_key).unwrap();
        aes_key
    }
}
