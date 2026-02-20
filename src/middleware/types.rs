use crate::oauth::UserInfo;
use crate::types::{PpnumId, UserId};

/// Session data from a successful PAS authentication.
///
/// Passed to [`SessionStore::create`](super::SessionStore::create) for the consumer to persist.
///
/// # Data ownership
///
/// `user_info` is **transient** data from PAS. It should be used for logging or
/// display at login time, but PAS-owned fields (`ppnum`, `email`) must NOT be
/// persisted in the consumer's database. Fetch via PAS userinfo API when needed.
#[derive(Debug, Clone)]
pub struct NewSession {
    /// PAS ppnum identifier (OAuth `sub` claim, ULID format).
    pub ppnum_id: PpnumId,
    /// User ID returned by [`AccountResolver::resolve`](super::AccountResolver::resolve).
    pub user_id: UserId,
    /// PAS refresh token for this OAuth session.
    ///
    /// **OAuth consumers (RCW, CTW):** PAS does NOT apply Refresh Token Rotation
    /// (RTR) for OAuth clients. Store this token as-is in the session; the same
    /// token is reused across refreshes. Lifetime: 180 days of inactivity expiry.
    ///
    /// **1st-party clients (PCS):** RTR is applied — each refresh returns a new
    /// token and invalidates the previous one (token family + replay detection).
    pub refresh_token: Option<String>,
    /// Client `User-Agent` header value.
    pub user_agent: Option<String>,
    /// Client IP address.
    pub ip_address: Option<String>,
    /// PAS UserInfo snapshot (transient — for display, NOT for DB storage).
    pub user_info: UserInfo,
}
