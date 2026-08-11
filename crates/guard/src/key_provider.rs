//! Protected local receipt-signing provider.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use crate::{GuardError, ReceiptSigner, Result, signer_key_id};

const KEY_FORMAT: &str = "scopepact-ed25519-encrypted-key-v2";
const KDF_ALGORITHM: &str = "argon2id-v1.3";
const CIPHER_ALGORITHM: &str = "xchacha20-poly1305";
const KEY_AAD_DOMAIN: &[u8] = b"SCOPEPACT-GUARD-ENCRYPTED-KEY-V2\0";
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_ITERATIONS: u32 = 3;
const KDF_LANES: u32 = 1;
const MIN_PASSPHRASE_BYTES: usize = 16;
const MAX_PASSPHRASE_BYTES: usize = 4 * 1024;

/// Serialized protected key and its public identity.
pub struct GeneratedProtectedKey {
    pub encoded: Vec<u8>,
    pub public_key: String,
    pub key_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EncryptedKeyFile {
    format: String,
    public_key: String,
    key_id: String,
    kdf: KeyDerivation,
    cipher: EncryptedSeed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeyDerivation {
    algorithm: String,
    salt: String,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EncryptedSeed {
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct KeyAdditionalData<'a> {
    domain: &'a str,
    format: &'a str,
    public_key: &'a str,
    key_id: &'a str,
    kdf_algorithm: &'a str,
    salt: &'a str,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    cipher_algorithm: &'a str,
    nonce: &'a str,
}

struct ProtectedLocalSigner(SigningKey);

impl ReceiptSigner for ProtectedLocalSigner {
    fn sign(&self, transcript: &[u8]) -> Result<[u8; 64]> {
        Ok(ed25519_dalek::Signer::sign(&self.0, transcript).to_bytes())
    }

    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

/// Generates a new Ed25519 key encrypted with Argon2id and
/// XChaCha20-Poly1305.
///
/// # Errors
///
/// Returns an error for an unsafe passphrase or unavailable operating-system
/// randomness.
pub fn generate_protected_key(passphrase: &[u8]) -> Result<GeneratedProtectedKey> {
    validate_passphrase(passphrase)?;
    let mut seed = [0_u8; 32];
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut seed).map_err(random_error)?;
    getrandom::fill(&mut salt).map_err(random_error)?;
    getrandom::fill(&mut nonce).map_err(random_error)?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();

    let public_key = hex::encode(signing_key.verifying_key().as_bytes());
    let key_id = hex::encode(signer_key_id(&signing_key).0);
    let kdf = KeyDerivation {
        algorithm: KDF_ALGORITHM.into(),
        salt: hex::encode(salt),
        memory_kib: KDF_MEMORY_KIB,
        iterations: KDF_ITERATIONS,
        lanes: KDF_LANES,
    };
    let nonce_hex = hex::encode(nonce);
    let mut file = EncryptedKeyFile {
        format: KEY_FORMAT.into(),
        public_key: public_key.clone(),
        key_id: key_id.clone(),
        kdf,
        cipher: EncryptedSeed {
            algorithm: CIPHER_ALGORITHM.into(),
            nonce: nonce_hex,
            ciphertext: String::new(),
        },
    };
    let additional_data = additional_data(&file)?;
    let mut wrapping_key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&wrapping_key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &signing_key.to_bytes(),
                aad: &additional_data,
            },
        )
        .map_err(|_| GuardError::KeyProvider("cannot encrypt local key".into()))?;
    wrapping_key.zeroize();
    file.cipher.ciphertext = hex::encode(ciphertext);
    let mut encoded = serde_json::to_vec_pretty(&file)?;
    encoded.push(b'\n');
    Ok(GeneratedProtectedKey {
        encoded,
        public_key,
        key_id,
    })
}

/// Decrypts and validates a protected local receipt signer.
///
/// # Errors
///
/// Returns an error for unsupported parameters, malformed data, a wrong
/// passphrase, or public metadata that does not match the decrypted key.
pub fn load_protected_key(encoded: &[u8], passphrase: &[u8]) -> Result<Box<dyn ReceiptSigner>> {
    validate_passphrase(passphrase)?;
    let file: EncryptedKeyFile = serde_json::from_slice(encoded)
        .map_err(|error| GuardError::KeyProvider(format!("cannot parse protected key: {error}")))?;
    validate_parameters(&file)?;
    let salt: [u8; 16] = decode_hex(&file.kdf.salt, "KDF salt")?;
    let nonce: [u8; 24] = decode_hex(&file.cipher.nonce, "cipher nonce")?;
    let ciphertext = hex::decode(&file.cipher.ciphertext)
        .map_err(|_| GuardError::KeyProvider("ciphertext is not valid hex".into()))?;
    let additional_data = additional_data(&file)?;
    let mut wrapping_key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&wrapping_key).into());
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &additional_data,
            },
        )
        .map_err(|_| {
            GuardError::KeyProvider(
                "cannot decrypt protected key; passphrase or file is invalid".into(),
            )
        })?;
    wrapping_key.zeroize();
    let mut seed: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| GuardError::KeyProvider("decrypted key seed has the wrong length".into()))?;
    plaintext.zeroize();
    let signer = SigningKey::from_bytes(&seed);
    seed.zeroize();
    if file.public_key != hex::encode(signer.verifying_key().as_bytes())
        || file.key_id != hex::encode(signer_key_id(&signer).0)
    {
        return Err(GuardError::KeyProvider(
            "protected key metadata does not match decrypted key".into(),
        ));
    }
    Ok(Box::new(ProtectedLocalSigner(signer)))
}

fn validate_parameters(file: &EncryptedKeyFile) -> Result<()> {
    if file.format != KEY_FORMAT
        || file.kdf.algorithm != KDF_ALGORITHM
        || file.kdf.memory_kib != KDF_MEMORY_KIB
        || file.kdf.iterations != KDF_ITERATIONS
        || file.kdf.lanes != KDF_LANES
        || file.cipher.algorithm != CIPHER_ALGORITHM
    {
        return Err(GuardError::KeyProvider(
            "unsupported protected key format or cryptographic parameters".into(),
        ));
    }
    Ok(())
}

fn validate_passphrase(passphrase: &[u8]) -> Result<()> {
    if !(MIN_PASSPHRASE_BYTES..=MAX_PASSPHRASE_BYTES).contains(&passphrase.len()) {
        return Err(GuardError::KeyProvider(format!(
            "passphrase must contain {MIN_PASSPHRASE_BYTES} to {MAX_PASSPHRASE_BYTES} bytes"
        )));
    }
    Ok(())
}

fn derive_key(passphrase: &[u8], salt: &[u8; 16]) -> Result<[u8; 32]> {
    let params = Params::new(KDF_MEMORY_KIB, KDF_ITERATIONS, KDF_LANES, Some(32))
        .map_err(|_| GuardError::KeyProvider("invalid built-in Argon2 parameters".into()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|_| GuardError::KeyProvider("Argon2 key derivation failed".into()))?;
    Ok(output)
}

fn additional_data(file: &EncryptedKeyFile) -> Result<Vec<u8>> {
    let data = KeyAdditionalData {
        domain: std::str::from_utf8(KEY_AAD_DOMAIN)
            .expect("encrypted key domain must be valid UTF-8"),
        format: &file.format,
        public_key: &file.public_key,
        key_id: &file.key_id,
        kdf_algorithm: &file.kdf.algorithm,
        salt: &file.kdf.salt,
        memory_kib: file.kdf.memory_kib,
        iterations: file.kdf.iterations,
        lanes: file.kdf.lanes,
        cipher_algorithm: &file.cipher.algorithm,
        nonce: &file.cipher.nonce,
    };
    serde_json::to_vec(&data).map_err(GuardError::from)
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value)
        .map_err(|_| GuardError::KeyProvider(format!("{label} is not valid hex")))?;
    bytes
        .try_into()
        .map_err(|_| GuardError::KeyProvider(format!("{label} has the wrong length")))
}

fn random_error(error: getrandom::Error) -> GuardError {
    GuardError::KeyProvider(format!("operating-system randomness failed: {error}"))
}
