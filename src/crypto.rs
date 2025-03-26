// crypto.rs
// A guide to AES-256-CBC encryption using the new CBC crate from RustCrypto.
// We’re using aes 0.8.4, cbc 0.1.2, and cipher 0.4.4.
// Note: The new cbc crate now only takes the block cipher as a generic parameter.

use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cipher::KeyIvInit;
use cipher::block_padding::Pkcs7;
use rand::RngCore;
use rand::rngs::OsRng;
use base64::{engine::general_purpose, Engine as _};
use std::error::Error;

// Define type aliases for convenience using the new CBC API.
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub fn encrypt_password(key: &[u8], password: &str) -> Result<String, Box<dyn Error>> {
    if key.len() != 32 {
        return Err("Encryption key must be 32 bytes.".into());
    }
    
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    // Create a new encryptor instance using KeyIvInit.
    let encryptor = Aes256CbcEnc::new(key.into(), &iv.into());
    // Use the allocating convenience method.
    let ciphertext = cipher::BlockEncryptMut::encrypt_padded_vec_mut::<Pkcs7>(encryptor, password.as_bytes());

    // Prepend the IV to the ciphertext.
    let mut result = iv.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(general_purpose::STANDARD.encode(result))
}

pub fn decrypt_password(key: &[u8], encrypted_data: &str) -> Result<String, Box<dyn Error>> {
    let data = general_purpose::STANDARD.decode(encrypted_data)?;
    if data.len() < 16 {
        return Err("Ciphertext too short.".into());
    }
    
    let (iv, ciphertext) = data.split_at(16);
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    let decrypted = cipher::BlockDecryptMut::decrypt_padded_vec_mut::<Pkcs7>(decryptor, ciphertext)
        .map_err(|e| format!("Decryption error: {:?}", e))?;
    Ok(String::from_utf8(decrypted)?)
}

