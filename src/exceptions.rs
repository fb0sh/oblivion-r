use ring::error::Unspecified;
use scrypt::errors::InvalidOutputLen;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum OblivionException {
    #[error("Exception while encrypting: {e:?}")]
    EncryptError { e: Unspecified },

    #[error("Exception while decrypting: {e:?}")]
    DecryptError { e: Unspecified },

    #[error("Exception while Generate SharedKey: {e:?}")]
    SharedKeyError { e: Unspecified },

    #[error("Exception while stringify the data: {e:?}")]
    FromUtf8Error { e: FromUtf8Error },

    #[error("Exceptions while using SharedKey's scrypt: {e:?}")]
    InvalidOutputLen { e: InvalidOutputLen },
}
