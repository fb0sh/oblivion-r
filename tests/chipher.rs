use oblivion::Chipher;

use rand::rngs::OsRng;
use rand::RngCore;

#[cfg(test)]
mod chipher_tests {
    use super::*;

    #[test]
    fn enc_dec_data() {
        let mut aes_key = [0u8; 16];
        OsRng.fill_bytes(&mut aes_key);
        println!("Generated key: {:?}", aes_key);

        let text = "hello world";
        let mut d = text.as_bytes().to_vec();
        let od = Chipher::encrypt(d, &aes_key).unwrap();
        println!("Encrypted data: {:?}", od);

        let t = Chipher::decrypt(od, &aes_key).unwrap();
        println!("Decrypted data: {:?}", t);

        assert_eq!(text.as_bytes().to_vec(), t);
    }

    #[test]
    fn enc_dec_str() {
        let mut aes_key = [0u8; 16];
        OsRng.fill_bytes(&mut aes_key);
        println!("Generated key: {:?}", aes_key);
        let text = "hello world";

        let data = Chipher::encrypt_str(&text, &aes_key).unwrap();
        println!("Encrypted data: {:?}", data);
        let r = Chipher::decrypt_as_str(data, &aes_key).unwrap();
        println!("Decrypted data: {:?}", r);
        assert_eq!(text, r);
    }
}
