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
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum WellKnownKeyStatus {
    Active,
    Retiring,
    Revoked,
}
