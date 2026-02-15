use derive_more::{Display, From, FromStr, Into};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::error::Error;

/// PAS ppnum identifier (OAuth `sub` claim, ULID format).
///
/// Immutable, unique per Ppoppo account. Returned as `sub` in OAuth tokens.
/// Consumers store this as the sole link to PAS identity.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, FromStr, From, Into,
)]
#[serde(transparent)]
pub struct PpnumId(pub Ulid);

/// Validated Ppoppo Number (11-digit, "777" prefix).
///
/// Guaranteed valid by construction: holding a `Ppnum` proves the format is correct.
/// Use `"77712345678".parse::<Ppnum>()` or `Ppnum::try_from(string)` to create.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ppnum(String);

impl Ppnum {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Ppnum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Ppnum {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl TryFrom<String> for Ppnum {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.len() == 11 && s.starts_with("777") && s.bytes().all(|b| b.is_ascii_digit()) {
            Ok(Self(s))
        } else {
            Err(Error::InvalidPpnum(s))
        }
    }
}

impl From<Ppnum> for String {
    fn from(p: Ppnum) -> Self {
        p.0
    }
}

/// Consumer-defined user identifier (opaque string).
///
/// Returned by [`PpnumStore::find_or_create`](crate::middleware::PpnumStore::find_or_create).
/// The consumer chooses the format (ULID, UUID, etc.).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, From, Into,
)]
#[serde(transparent)]
pub struct UserId(pub String);

/// Consumer-defined session identifier (opaque string).
///
/// Returned by [`SessionStore::create`](crate::middleware::SessionStore::create).
/// The consumer chooses the format (ULID, UUID, etc.).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, From, Into,
)]
#[serde(transparent)]
pub struct SessionId(pub String);

/// PASERK key identifier.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, From, Into,
)]
#[serde(transparent)]
pub struct KeyId(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ppnum() {
        assert!("77712345678".parse::<Ppnum>().is_ok());
        assert!("77700000000".parse::<Ppnum>().is_ok());
        assert!("77799999999".parse::<Ppnum>().is_ok());
    }

    #[test]
    fn invalid_ppnum_wrong_prefix() {
        assert!("12345678901".parse::<Ppnum>().is_err());
        assert!("77812345678".parse::<Ppnum>().is_err());
    }

    #[test]
    fn invalid_ppnum_wrong_length() {
        assert!("7771234567".parse::<Ppnum>().is_err());
        assert!("777123456789".parse::<Ppnum>().is_err());
        assert!("".parse::<Ppnum>().is_err());
    }

    #[test]
    fn invalid_ppnum_non_digits() {
        assert!("777abcdefgh".parse::<Ppnum>().is_err());
        assert!("7771234567a".parse::<Ppnum>().is_err());
    }

    #[test]
    fn ppnum_serde_roundtrip() {
        let ppnum: Ppnum = "77712345678".parse().unwrap();
        let json = serde_json::to_string(&ppnum).unwrap();
        assert_eq!(json, "\"77712345678\"");
        let parsed: Ppnum = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ppnum);
    }

    #[test]
    fn ppnum_id_serde_roundtrip() {
        let id = PpnumId(Ulid::nil());
        let json = serde_json::to_string(&id).unwrap();
        let parsed: PpnumId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn user_id_from_string() {
        let id = UserId::from("user-123".to_string());
        assert_eq!(id.to_string(), "user-123");
    }

    #[test]
    fn session_id_from_string() {
        let id = SessionId::from("sess-abc".to_string());
        assert_eq!(id.to_string(), "sess-abc");
    }

    #[test]
    fn newtypes_prevent_mixing() {
        fn takes_user_id(_: &UserId) {}
        fn takes_session_id(_: &SessionId) {}

        let user = UserId::from("id".to_string());
        let session = SessionId::from("id".to_string());

        takes_user_id(&user);
        takes_session_id(&session);
        // takes_user_id(&session);  // Compile error!
        // takes_session_id(&user);  // Compile error!
    }
}
