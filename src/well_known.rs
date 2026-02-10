use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WellKnownPasetoDocument {
    pub issuer: String,
    pub version: String,
    pub keys: Vec<WellKnownPasetoKey>,
    pub cache_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WellKnownPasetoKey {
    pub kid: String,
    pub public_key_hex: String,
    pub status: WellKnownKeyStatus,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum WellKnownKeyStatus {
    Active,
    Retiring,
    Revoked,
}
