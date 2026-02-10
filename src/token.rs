use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rusty_paseto::prelude::*;
use serde_json::Value as JsonValue;

use crate::error::Error;

/// Ed25519 public key (32 bytes) for token verification.
///
/// Independent implementation from `pas-token` — only needs hex parsing
/// and PASETO verification, no PASERK key ID computation.
#[derive(Clone)]
pub struct PublicKey {
    bytes: [u8; 32],
}

impl PublicKey {
    /// Get the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Parses a hex-encoded Ed25519 public key (32 bytes) into a `PublicKey`.
///
/// # Errors
///
/// Returns `Error::Token` if the hex is invalid or the key length is not 32 bytes.
pub fn parse_public_key_hex(public_key_hex: &str) -> Result<PublicKey, Error> {
    let bytes = hex::decode(public_key_hex)
        .map_err(|e| Error::Token(format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Token(format!(
            "invalid key length: expected 32, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey { bytes: arr })
}

/// Verified claims from a PASETO token.
#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    inner: JsonValue,
}

impl VerifiedClaims {
    /// Gets a claim value by key.
    #[must_use]
    pub fn get_claim(&self, key: &str) -> Option<&JsonValue> {
        self.inner.get(key)
    }

    /// Gets the inner JSON value.
    #[must_use]
    pub fn as_json(&self) -> &JsonValue {
        &self.inner
    }
}

/// Verifies a PASETO v4.public access token.
///
/// # Errors
///
/// Returns `Error::Token` if the token format is invalid, the signature
/// verification fails, or the `iss`/`aud` claims do not match the expected values.
pub fn verify_v4_public_access_token(
    public_key: &PublicKey,
    token_str: &str,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<VerifiedClaims, Error> {
    if !token_str.starts_with("v4.public.") {
        return Err(Error::Token("invalid token format".into()));
    }

    // Build rusty_paseto public key from raw bytes
    let key = rusty_paseto::prelude::Key::<32>::from(&public_key.bytes);
    let pk = PasetoAsymmetricPublicKey::<V4, Public>::from(&key);

    // Extract footer for the parser
    let footer_bytes = extract_footer_from_token(token_str)?;
    let footer_str = std::str::from_utf8(&footer_bytes)
        .map_err(|_| Error::Token("invalid footer encoding".into()))?;

    // Parse token (PasetoParser validates exp, nbf, iat by default)
    let json_value = PasetoParser::<V4, Public>::default()
        .set_footer(Footer::from(footer_str))
        .parse(token_str, &pk)
        .map_err(|e| Error::Token(e.to_string()))?;

    // Validate issuer
    let actual_issuer = json_value
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Token("missing claim: iss".into()))?;
    if actual_issuer != expected_issuer {
        return Err(Error::Token(format!(
            "iss: expected '{expected_issuer}', got '{actual_issuer}'"
        )));
    }

    // Validate audience
    let actual_audience = json_value
        .get("aud")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Token("missing claim: aud".into()))?;
    if actual_audience != expected_audience {
        return Err(Error::Token(format!(
            "aud: expected '{expected_audience}', got '{actual_audience}'"
        )));
    }

    Ok(VerifiedClaims { inner: json_value })
}

/// Extract key ID from a PASETO token without verifying signature.
/// Validates v4.public format prefix.
///
/// # Errors
///
/// Returns `Error::Token` if the token format is invalid or the footer
/// does not contain a `kid` claim.
pub fn extract_kid_from_token(token_str: &str) -> Result<String, Error> {
    if !token_str.starts_with("v4.public.") {
        return Err(Error::Token("invalid token format".into()));
    }
    let footer_bytes = extract_footer_from_token(token_str)?;
    extract_kid_from_untrusted_footer(&footer_bytes)
}

/// Extracts the key ID (kid) from an untrusted token's footer.
pub(crate) fn extract_kid_from_untrusted_footer(footer_bytes: &[u8]) -> Result<String, Error> {
    let footer_str = std::str::from_utf8(footer_bytes)
        .map_err(|_| Error::Token("invalid footer".into()))?;

    let footer_json: JsonValue = serde_json::from_str(footer_str)
        .map_err(|_| Error::Token("invalid footer".into()))?;

    let kid = footer_json
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Token("missing footer claim: kid".into()))?
        .to_owned();

    Ok(kid)
}

/// Extracts the footer bytes from a PASETO token string.
pub(crate) fn extract_footer_from_token(token_str: &str) -> Result<Vec<u8>, Error> {
    if !token_str.starts_with("v4.public.") {
        return Err(Error::Token("invalid token format".into()));
    }

    let parts: Vec<&str> = token_str.split('.').collect();
    if parts.len() != 4 {
        return Err(Error::Token("invalid token format".into()));
    }

    let footer_b64 = parts[3];
    if footer_b64.is_empty() {
        return Ok(Vec::new());
    }

    URL_SAFE_NO_PAD
        .decode(footer_b64)
        .map_err(|_| Error::Token("invalid footer".into()))
}
