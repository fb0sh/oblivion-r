use std::string::FromUtf8Error;

use ring::error::Unspecified;
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum OblivionException {
    #[error("Exception while encrypting: {e:?}")]
    EncryptError { e: Unspecified },
    #[error("Exception while decrypting: {e:?}")]
    DecryptError { e: Unspecified },
    #[error("Exception while decrypting: {e:?}")]
    FromUtf8Error { e: FromUtf8Error },
}
