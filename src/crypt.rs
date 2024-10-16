use aes::cipher::{generic_array::GenericArray, typenum::U32};
use aes_gcm_siv::aead::rand_core::RngCore;
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use bcrypt::HashParts;
use sha2::{Digest, Sha256};

struct AES256Key {
    pub cipher: Aes256GcmSiv,
    pub salt: [u8; 16],
}

use crate::error::JencError;

pub struct CryptValue {
    pub value: Vec<u8>,
    pub cost: u8,
}

fn generate_nonce() -> [u8; 12] {
    let mut nonce: [u8; 12] = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn generate_salt() -> [u8; 16] {
    let mut salt: [u8; 16] = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn get_aes256gcmsiv(pass: &str, cost: u8) -> Result<AES256Key, JencError> {
    let salt: [u8; 16] = generate_salt();
    get_aes256gcmsiv_with_salt(pass, salt, cost)
}

fn get_aes256gcmsiv_with_salt(
    pass: &str,
    salt: [u8; 16],
    cost: u8,
) -> Result<AES256Key, JencError> {
    let bcrypt: HashParts = bcrypt::hash_with_salt(pass, cost as u32, salt)?;
    let mut hasher = Sha256::new();
    hasher.update(bcrypt.to_string());
    let hash: GenericArray<u8, U32> = hasher.finalize();
    let cipher: Aes256GcmSiv = Aes256GcmSiv::new(&hash);
    Ok(AES256Key { cipher, salt })
}

/// Returns the original bytes.
pub fn aes256_decrypt(bytes: &[u8], pass: &str) -> Result<CryptValue, JencError> {
    let cost: u8 = bytes[0];
    let salt_u8: [u8; 16] = bytes[1..17].try_into().unwrap();
    let nonce_u8: [u8; 12] = bytes[17..29].try_into().unwrap();
    let ciphertext_u8: &[u8] = &bytes[29..];
    let nonce: &Nonce = &Nonce::from(nonce_u8);
    let key: AES256Key = get_aes256gcmsiv_with_salt(pass, salt_u8, cost)?;
    let value = key.cipher.decrypt(nonce, ciphertext_u8.as_ref())?;
    Ok(CryptValue { value, cost })
}

/// Turn a `Vec<u8>` into its' encrypted form using `pass`.
pub fn aes256_encrypt(plaintext: &Vec<u8>, pass: &str, cost: u8) -> Result<Vec<u8>, JencError> {
    let nonce_u8: [u8; 12] = generate_nonce();
    let nonce: &Nonce = &Nonce::from(nonce_u8);
    let key: AES256Key = get_aes256gcmsiv(pass, cost)?;
    let ciphertext: Vec<u8> = key.cipher.encrypt(nonce, plaintext.as_ref())?;
    Ok([vec![cost], key.salt.to_vec(), nonce_u8.to_vec(), ciphertext].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAINTEXT: &str = "plaintext";
    const COST: u8 = 8u8;
    const PASS: &str = "password";
    const BAD_PASS: &str = "bad_password";

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext_bytes: Vec<u8> = PLAINTEXT.into();
        let encrypted_bytes: Vec<u8> = aes256_encrypt(&plaintext_bytes, PASS, COST).unwrap();
        let decrypted_bytes: CryptValue = aes256_decrypt(&encrypted_bytes, PASS).unwrap();
        assert_eq!(decrypted_bytes.value, plaintext_bytes);
    }

    #[test]
    fn test_decrypt_bad_pass() {
        let plaintext_bytes: Vec<u8> = PLAINTEXT.into();
        let encrypted_bytes: Vec<u8> = aes256_encrypt(&plaintext_bytes, PASS, COST).unwrap();
        assert!(aes256_decrypt(&encrypted_bytes, BAD_PASS).is_err());
    }
}
