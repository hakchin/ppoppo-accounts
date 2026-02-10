use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use sha2::{Digest, Sha256};

/// Generates a cryptographically random code verifier for PKCE.
///
/// Returns a 64-character URL-safe string (RFC 7636 compliant, 43-128 chars).
#[must_use]
pub fn generate_code_verifier() -> String {
    let random_bytes: [u8; 48] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(random_bytes)
}

/// Computes the S256 code challenge from a code verifier.
///
/// `challenge = BASE64URL(SHA256(verifier))`
#[must_use]
pub fn generate_code_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

/// Generates a cryptographically random state parameter for `OAuth2`.
///
/// Returns a 22-character URL-safe string (16 random bytes → base64url).
#[must_use]
pub fn generate_state() -> String {
    let random_bytes: [u8; 16] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(random_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_verifier_length() {
        let verifier = generate_code_verifier();
        assert_eq!(verifier.len(), 64);
    }

    #[test]
    fn test_code_verifier_url_safe() {
        let verifier = generate_code_verifier();
        assert!(
            verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "verifier should be URL-safe: {}",
            verifier
        );
    }

    #[test]
    fn test_code_verifier_uniqueness() {
        let v1 = generate_code_verifier();
        let v2 = generate_code_verifier();
        assert_ne!(v1, v2, "verifiers should be unique");
    }

    #[test]
    fn test_code_challenge_deterministic() {
        let verifier = "test_verifier_string";
        let c1 = generate_code_challenge(verifier);
        let c2 = generate_code_challenge(verifier);
        assert_eq!(c1, c2, "challenge should be deterministic");
    }

    #[test]
    fn test_code_challenge_different_for_different_verifiers() {
        let c1 = generate_code_challenge("verifier_1");
        let c2 = generate_code_challenge("verifier_2");
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_state_length() {
        let state = generate_state();
        assert_eq!(state.len(), 22);
    }

    #[test]
    fn test_state_uniqueness() {
        let s1 = generate_state();
        let s2 = generate_state();
        assert_ne!(s1, s2, "states should be unique");
    }
}
