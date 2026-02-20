use serde::{Deserialize, Serialize};

use crate::types::KeyId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WellKnownPasetoDocument {
    pub issuer: String,
    pub version: String,
    pub keys: Vec<WellKnownPasetoKey>,
    pub cache_ttl_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WellKnownPasetoKey {
    pub kid: KeyId,
    pub public_key_hex: String,
    pub status: WellKnownKeyStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum WellKnownKeyStatus {
    Active,
    Retiring,
    Revoked,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_JSON: &str = r#"{
        "issuer": "accounts.ppoppo.com",
        "version": "v4.public",
        "keys": [
            {
                "kid": "key-001",
                "public_key_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "status": "active",
                "created_at": "2026-01-01T00:00:00Z"
            },
            {
                "kid": "key-002",
                "public_key_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "status": "retiring",
                "created_at": "2025-06-01T00:00:00Z"
            }
        ],
        "cache_ttl_seconds": 3600
    }"#;

    #[test]
    fn deserialize_well_known_document() {
        let doc: WellKnownPasetoDocument = serde_json::from_str(SAMPLE_JSON).unwrap();

        assert_eq!(doc.issuer, "accounts.ppoppo.com");
        assert_eq!(doc.version, "v4.public");
        assert_eq!(doc.keys.len(), 2);
        assert_eq!(doc.cache_ttl_seconds, 3600);
    }

    #[test]
    fn deserialize_key_fields() {
        let doc: WellKnownPasetoDocument = serde_json::from_str(SAMPLE_JSON).unwrap();

        let key = &doc.keys[0];
        assert_eq!(key.kid.to_string(), "key-001");
        assert_eq!(key.status, WellKnownKeyStatus::Active);

        let retiring = &doc.keys[1];
        assert_eq!(retiring.status, WellKnownKeyStatus::Retiring);
    }

    #[test]
    fn serde_roundtrip() {
        let doc: WellKnownPasetoDocument = serde_json::from_str(SAMPLE_JSON).unwrap();
        let json = serde_json::to_string(&doc).unwrap();
        let doc2: WellKnownPasetoDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, doc2);
    }

    #[test]
    fn deserialize_revoked_status() {
        let json = r#"{
            "kid": "key-003",
            "public_key_hex": "cc",
            "status": "revoked",
            "created_at": "2024-01-01T00:00:00Z"
        }"#;
        let key: WellKnownPasetoKey = serde_json::from_str(json).unwrap();
        assert_eq!(key.status, WellKnownKeyStatus::Revoked);
    }

    #[cfg(feature = "token")]
    #[test]
    fn convert_well_known_key_to_public_key() {
        use crate::token::PublicKey;

        let doc: WellKnownPasetoDocument = serde_json::from_str(SAMPLE_JSON).unwrap();
        let key = &doc.keys[0];

        let result = PublicKey::try_from(key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_bytes().len(), 32);
    }
}
