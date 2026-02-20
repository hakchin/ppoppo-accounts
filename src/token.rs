use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pasetors::claims::ClaimsValidationRules;
use pasetors::keys::AsymmetricPublicKey;
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use pasetors::{public, Public};
use serde_json::Value as JsonValue;

use crate::error::{Error, TokenError};
use crate::types::KeyId;

const TOKEN_PREFIX: &str = "v4.public.";

/// Ed25519 public key (32 bytes) for token verification.
///
/// Independent implementation from `pas-token` — only needs hex parsing
/// and PASETO verification, no PASERK key ID computation.
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[cfg(feature = "token")]
impl TryFrom<&crate::well_known::WellKnownPasetoKey> for PublicKey {
    type Error = Error;

    fn try_from(key: &crate::well_known::WellKnownPasetoKey) -> Result<Self, Error> {
        parse_public_key_hex(&key.public_key_hex)
    }
}

/// Parses a hex-encoded Ed25519 public key (32 bytes) into a `PublicKey`.
///
/// # Errors
///
/// Returns `Error::Token` if the hex is invalid or the key length is not 32 bytes.
pub fn parse_public_key_hex(public_key_hex: &str) -> Result<PublicKey, Error> {
    let bytes = hex::decode(public_key_hex)
        .map_err(|e| TokenError::VerificationFailed(format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(TokenError::VerificationFailed(format!(
            "invalid key length: expected 32, got {}",
            bytes.len()
        ))
        .into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey { bytes: arr })
}

/// Verified claims from a PASETO token.
///
/// After successful verification, `iss` and `aud` are stored as owned fields.
/// Access them via typed accessors instead of raw JSON lookup.
#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    iss: String,
    aud: String,
    inner: JsonValue,
}

impl VerifiedClaims {
    /// Issuer claim (guaranteed present after verification).
    #[must_use]
    pub fn iss(&self) -> &str {
        &self.iss
    }

    /// Audience claim (guaranteed present after verification).
    #[must_use]
    pub fn aud(&self) -> &str {
        &self.aud
    }

    /// Subject claim.
    #[must_use]
    pub fn sub(&self) -> Option<&str> {
        self.inner.get("sub").and_then(|v| v.as_str())
    }

    /// Gets a claim value by key (for dynamic/extra claims).
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
    if !token_str.starts_with(TOKEN_PREFIX) {
        return Err(TokenError::InvalidFormat.into());
    }

    let pk = AsymmetricPublicKey::<V4>::from(&public_key.bytes[..])
        .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

    let validation_rules = ClaimsValidationRules::new();

    let untrusted_token = UntrustedToken::<Public, V4>::try_from(token_str)
        .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

    let trusted_token = public::verify(&pk, &untrusted_token, &validation_rules, None, None)
        .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

    let payload = trusted_token
        .payload_claims()
        .ok_or(TokenError::MissingPayload)?;
    let payload_str = payload
        .to_string()
        .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;
    let json_value: JsonValue = serde_json::from_str(&payload_str)
        .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

    let iss = validate_claim(&json_value, "iss", expected_issuer)?;
    let aud = validate_claim(&json_value, "aud", expected_audience)?;

    Ok(VerifiedClaims {
        iss,
        aud,
        inner: json_value,
    })
}

/// Validates a JSON claim matches expected value; returns the actual value on success.
fn validate_claim(
    claims: &JsonValue,
    key: &'static str,
    expected: &str,
) -> Result<String, TokenError> {
    let actual = claims
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or(TokenError::MissingClaim(key))?;
    if actual != expected {
        return Err(TokenError::ClaimMismatch {
            claim: key,
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(actual.to_string())
}

/// Extract key ID from a PASETO token without verifying signature.
///
/// # Errors
///
/// Returns `Error::Token` if the token format is invalid or the footer
/// does not contain a `kid` claim.
pub fn extract_kid_from_token(token_str: &str) -> Result<KeyId, Error> {
    let footer_bytes = extract_footer_from_token(token_str)?;
    extract_kid_from_untrusted_footer(&footer_bytes)
}

/// Extracts the key ID (kid) from an untrusted token's footer.
pub(crate) fn extract_kid_from_untrusted_footer(footer_bytes: &[u8]) -> Result<KeyId, Error> {
    let footer_str =
        std::str::from_utf8(footer_bytes).map_err(|_| TokenError::InvalidFooter)?;

    let footer_json: JsonValue =
        serde_json::from_str(footer_str).map_err(|_| TokenError::InvalidFooter)?;

    let kid = footer_json
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or(TokenError::MissingClaim("kid"))?
        .to_owned();

    Ok(KeyId(kid))
}

/// Extracts the footer bytes from a PASETO token string.
pub(crate) fn extract_footer_from_token(token_str: &str) -> Result<Vec<u8>, Error> {
    if !token_str.starts_with(TOKEN_PREFIX) {
        return Err(TokenError::InvalidFormat.into());
    }

    let parts: Vec<&str> = token_str.split('.').collect();
    if parts.len() != 4 {
        return Err(TokenError::InvalidFormat.into());
    }

    let footer_b64 = parts[3];
    if footer_b64.is_empty() {
        return Ok(Vec::new());
    }

    URL_SAFE_NO_PAD
        .decode(footer_b64)
        .map_err(|_| TokenError::InvalidFooter.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_public_key_hex ─────────────────────────────────────

    #[test]
    fn parse_valid_hex_key() {
        // 32 bytes = 64 hex chars
        let hex = "a".repeat(64);
        let key = parse_public_key_hex(&hex).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn parse_invalid_hex() {
        let result = parse_public_key_hex("not-hex");
        assert!(result.is_err());
    }

    #[test]
    fn parse_wrong_length() {
        // 16 bytes = 32 hex chars (too short)
        let hex = "ab".repeat(16);
        let result = parse_public_key_hex(&hex);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("invalid key length"));
    }

    // ── verify_v4_public_access_token ────────────────────────────

    fn generate_test_token(
        issuer: &str,
        audience: &str,
    ) -> (PublicKey, String) {
        use pasetors::claims::Claims;
        use pasetors::footer::Footer;
        use pasetors::keys::{AsymmetricKeyPair, Generate};

        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();

        let mut claims = Claims::new().unwrap();
        claims.issuer(issuer).unwrap();
        claims.audience(audience).unwrap();
        claims.subject("test-sub").unwrap();

        let footer_json = serde_json::json!({"kid": "test-key-1"}).to_string();
        let mut footer = Footer::new();
        footer.parse_string(&footer_json).unwrap();

        let token =
            pasetors::public::sign(&kp.secret, &claims, Some(&footer), None).unwrap();

        let pk_bytes = kp.public.as_bytes();
        let hex = hex::encode(pk_bytes);
        let public_key = parse_public_key_hex(&hex).unwrap();

        (public_key, token)
    }

    #[test]
    fn verify_valid_token() {
        let (pk, token) = generate_test_token("accounts.ppoppo.com", "ppoppo/*");

        let claims =
            verify_v4_public_access_token(&pk, &token, "accounts.ppoppo.com", "ppoppo/*").unwrap();

        assert_eq!(claims.iss(), "accounts.ppoppo.com");
        assert_eq!(claims.aud(), "ppoppo/*");
        assert_eq!(claims.sub(), Some("test-sub"));
    }

    #[test]
    fn verify_wrong_issuer() {
        let (pk, token) = generate_test_token("accounts.ppoppo.com", "ppoppo/*");

        let result = verify_v4_public_access_token(&pk, &token, "wrong-issuer", "ppoppo/*");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("iss"));
    }

    #[test]
    fn verify_wrong_audience() {
        let (pk, token) = generate_test_token("accounts.ppoppo.com", "ppoppo/*");

        let result =
            verify_v4_public_access_token(&pk, &token, "accounts.ppoppo.com", "wrong-aud");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("aud"));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let (_pk, token) = generate_test_token("accounts.ppoppo.com", "ppoppo/*");

        // Generate a different key
        let different_hex = "bb".repeat(32);
        let wrong_pk = parse_public_key_hex(&different_hex).unwrap();

        let result =
            verify_v4_public_access_token(&wrong_pk, &token, "accounts.ppoppo.com", "ppoppo/*");
        assert!(result.is_err());
    }

    #[test]
    fn verify_invalid_format() {
        let hex = "aa".repeat(32);
        let pk = parse_public_key_hex(&hex).unwrap();

        let result = verify_v4_public_access_token(&pk, "not-a-token", "iss", "aud");
        assert!(matches!(
            result,
            Err(Error::Token(TokenError::InvalidFormat))
        ));
    }

    // ── extract_kid_from_token ───────────────────────────────────

    #[test]
    fn extract_kid_from_valid_token() {
        let (_pk, token) = generate_test_token("accounts.ppoppo.com", "ppoppo/*");

        let kid = extract_kid_from_token(&token).unwrap();
        assert_eq!(kid.to_string(), "test-key-1");
    }

    #[test]
    fn extract_kid_invalid_format() {
        let result = extract_kid_from_token("invalid");
        assert!(result.is_err());
    }

    // ── VerifiedClaims ───────────────────────────────────────────

    #[test]
    fn verified_claims_accessors() {
        let (pk, token) = generate_test_token("accounts.ppoppo.com", "ppoppo/*");

        let claims =
            verify_v4_public_access_token(&pk, &token, "accounts.ppoppo.com", "ppoppo/*").unwrap();

        assert!(claims.get_claim("iss").is_some());
        assert!(claims.get_claim("nonexistent").is_none());
        assert!(claims.as_json().is_object());
    }
}
