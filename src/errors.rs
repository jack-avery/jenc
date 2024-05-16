use thiserror::Error;

pub type Result<T> = core::result::Result<T, JencError>;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum JencError {
    /// BCrypt hash failed
    #[error("bcrypt error: {0}")]
    BCryptHash(#[from] bcrypt::BcryptError),

    /// AES256
    #[error("encrypt/decrypt failed (bad password?)")]
    AES256(#[from] aes_gcm_siv::Error),

    /// IOError
    #[error("io error: {0}")]
    IOError(#[from] std::io::Error),

    /// UTF8Decode failed
    #[error("utf8 decode failed: {0}")]
    UTF8Decode(#[from] std::string::FromUtf8Error),

    // general
    /// Missing parameter
    #[error("missing parameter")]
    NoParam,
}
