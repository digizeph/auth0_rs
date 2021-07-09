/// An error that can occur when encoding/decoding JWTs
#[derive(Debug)]
pub struct Auth0Error(Box<ErrorKind>);

/// A crate private constructor for `Error`.
pub(crate) fn new_error(kind: ErrorKind) -> Auth0Error {
    Auth0Error(Box::new(kind))
}

impl Auth0Error {
    /// Return the specific type of this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }

    /// Unwrap this error into its underlying type.
    pub fn into_kind(self) -> ErrorKind {
        *self.0
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    /// Invalid token
    InvalidToken,
    /// Input token does not contain key ID (`kid`) field
    TokenMissingKeyId,
    /// No matching key in the JSON web key set
    NoMatchKey,
    /// Invalid JSON web key set string
    InvalidJwksStr,
}