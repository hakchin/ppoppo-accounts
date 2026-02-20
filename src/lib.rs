#![doc = include_str!("../README.md")]

pub mod error;
#[cfg(feature = "oauth")]
pub mod oauth;
#[cfg(feature = "oauth")]
pub mod pkce;
#[cfg(feature = "token")]
pub mod token;
pub mod types;
pub mod well_known;

#[cfg(feature = "axum")]
pub mod middleware;

// Re-exports for convenient access
pub use error::{Error, TokenError};
#[cfg(feature = "oauth")]
pub use oauth::{AuthClient, AuthorizationRequest, OAuthConfig, TokenResponse, UserInfo};
#[cfg(feature = "oauth")]
pub use url::Url;
#[cfg(feature = "oauth")]
pub use pkce::{generate_code_challenge, generate_code_verifier, generate_state};
pub use types::{KeyId, Ppnum, PpnumId, SessionId, UserId};
#[cfg(feature = "token")]
pub use token::{
    PublicKey, VerifiedClaims, extract_kid_from_token, parse_public_key_hex,
    verify_v4_public_access_token,
};
pub use well_known::{WellKnownKeyStatus, WellKnownPasetoDocument, WellKnownPasetoKey};
