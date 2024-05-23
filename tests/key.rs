use oblivion::{key, SharedKey};

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn test_salt() {
        let s = key::salt();
        println!("salt: {:?}", s);
    }

    #[test]
    fn test_key_pair() {
        let (priv_key, pub_key) = key::key_pair();
        println!("key_pair: ({:?},{:?})", priv_key, pub_key);
    }

    #[test]
    fn test_shared_key() {
        let salt = key::salt();
        let (priv_key, pub_key) = key::key_pair();
        let mut shared_key = SharedKey::new(priv_key, &pub_key).unwrap();
        let aes_key = shared_key.hkdf(&salt);
        let scrypt_res = shared_key.scrypt(&salt).unwrap();

        println!("SharedKey : {:?}", shared_key);
        println!("aes_key: {:?}", aes_key);
        println!("scrypt_res: {:?}", scrypt_res);
    }
}
