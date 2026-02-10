#![doc = include_str!("../README.md")]

pub mod error;
#[cfg(feature = "oauth")]
pub mod oauth;
#[cfg(feature = "oauth")]
pub mod pkce;
pub mod ppnum;
#[cfg(feature = "token")]
pub mod token;
pub mod well_known;

// Re-exports for convenient access
pub use error::Error;
#[cfg(feature = "oauth")]
pub use oauth::{
    AuthClient, AuthorizationRequest, Config, ConfigBuilder, TokenResponse, UserInfo,
};
#[cfg(feature = "oauth")]
pub use pkce::{generate_code_challenge, generate_code_verifier, generate_state};
pub use ppnum::is_valid_ppnum;
#[cfg(feature = "token")]
pub use token::{
    PublicKey, VerifiedClaims, extract_kid_from_token, parse_public_key_hex,
    verify_v4_public_access_token,
};
pub use well_known::{WellKnownKeyStatus, WellKnownPasetoDocument, WellKnownPasetoKey};
