#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("OAuth2 error: {0}")]
    OAuth(String),
    #[cfg(feature = "oauth")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Token verification error: {0}")]
    Token(String),
    #[error("Invalid ppnum: {0}")]
    InvalidPpnum(String),
    #[cfg(feature = "oauth")]
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
}
