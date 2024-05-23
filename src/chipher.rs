use ring::{
    aead::{
        Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_128_GCM,
        NONCE_LEN,
    },
    error::Unspecified,
    rand::{SecureRandom, SystemRandom},
};

use crate::{OblivionData, OblivionException};

struct AbsoluteNonceSequence<'a> {
    nonce: &'a [u8],
}

impl<'a> AbsoluteNonceSequence<'a> {
    pub fn new(nonce: &'a [u8]) -> Self {
        Self { nonce }
    }
}

impl<'a> NonceSequence for AbsoluteNonceSequence<'a> {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Nonce::try_assume_unique_for_key(self.nonce)
    }
}

pub struct Chipher;

impl Chipher {
    /// Encrypt data
    pub fn encrypt(mut data: Vec<u8>, aes_key: &[u8]) -> Result<OblivionData, OblivionException> {
        let unbound_key = match UnboundKey::new(&AES_128_GCM, &aes_key) {
            Ok(k) => k,
            Err(e) => return Err(OblivionException::EncryptError { e }),
        };

        let mut nonce_bytes = vec![0; NONCE_LEN];
        let sys_rand = SystemRandom::new();
        sys_rand.fill(&mut nonce_bytes).unwrap();

        let nonce_seq = AbsoluteNonceSequence::new(&nonce_bytes);
        let mut sealing_key = SealingKey::new(unbound_key, nonce_seq);

        let tag = match sealing_key.seal_in_place_separate_tag(Aad::empty(), &mut data) {
            Ok(t) => t,
            Err(e) => return Err(OblivionException::EncryptError { e }),
        };

        let res = (data, tag.as_ref().to_owned(), nonce_bytes);

        Ok(res)
    }
    /// the str version
    pub fn encrypt_str(data: &str, aes_key: &[u8]) -> Result<OblivionData, OblivionException> {
        let data = data.as_bytes().to_owned();
        Chipher::encrypt(data, aes_key)
    }

    // Decrypt OblivionData
    pub fn decrypt(data: OblivionData, aes_key: &[u8]) -> Result<Vec<u8>, OblivionException> {
        let unbound_key = match UnboundKey::new(&AES_128_GCM, aes_key) {
            Ok(k) => k,
            Err(e) => return Err(OblivionException::DecryptError { e }),
        };
        let nonce_sequence = AbsoluteNonceSequence::new(&data.2);

        let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
        let mut in_out = [data.0, data.1].concat();

        let res = match opening_key.open_in_place(Aad::empty(), &mut in_out) {
            Ok(d) => d,
            Err(e) => return Err(OblivionException::DecryptError { e }),
        };

        Ok(res.to_vec())
    }

    // Decrypt OblivionData to string
    pub fn decrypt_as_str(data: OblivionData, aes_key: &[u8]) -> Result<String, OblivionException> {
        let data = Chipher::decrypt(data, aes_key)?;

        match String::from_utf8(data) {
            Ok(s) => Ok(s),
            Err(e) => return Err(OblivionException::FromUtf8Error { e }),
        }
    }
}
