#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    #[error("invalid token format")]
    InvalidFormat,
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("{claim}: expected '{expected}', got '{actual}'")]
    ClaimMismatch {
        claim: &'static str,
        expected: String,
        actual: String,
    },
    #[error("missing claim: {0}")]
    MissingClaim(&'static str),
    #[error("missing payload")]
    MissingPayload,
    #[error("invalid footer")]
    InvalidFooter,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("OAuth2 {operation} failed (status={status:?}): {detail}")]
    OAuth {
        operation: &'static str,
        status: Option<u16>,
        detail: String,
    },
    #[cfg(feature = "oauth")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("token error: {0}")]
    Token(#[from] TokenError),
    #[error("Invalid ppnum: {0}")]
    InvalidPpnum(String),
    #[cfg(feature = "oauth")]
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
}
