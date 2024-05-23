mod chipher;
mod exceptions;
pub mod key;

/// OblivionResult 0: data 1: tag 2: nonce_bytes
pub type OblivionData = (Vec<u8>, Vec<u8>, Vec<u8>);

pub use chipher::Chipher;
pub use exceptions::OblivionException;
pub use key::SharedKey;
