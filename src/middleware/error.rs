use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

/// Authentication errors for the middleware layer.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// No valid session found.
    #[error("Not authenticated")]
    Unauthenticated,

    /// Session exists but is no longer valid.
    #[error("Session expired")]
    SessionExpired,

    /// OAuth2 flow error (state mismatch, token exchange failure, etc.)
    #[error("OAuth error: {0}")]
    OAuth(String),

    /// Session store operation failed.
    #[error("Session store error: {0}")]
    Store(String),

    /// Missing or invalid configuration.
    #[error("Configuration error: {0}")]
    Config(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthenticated | Self::SessionExpired => {
                (StatusCode::UNAUTHORIZED, self.to_string()).into_response()
            }
            Self::OAuth(ref msg) => {
                let encoded = urlencoding::encode(msg);
                Redirect::to(&format!("/login?error={encoded}")).into_response()
            }
            Self::Store(_) | Self::Config(_) => {
                tracing::error!(error = %self, "Auth internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
            }
        }
    }
}

impl From<crate::error::Error> for AuthError {
    fn from(e: crate::error::Error) -> Self {
        Self::OAuth(e.to_string())
    }
}
