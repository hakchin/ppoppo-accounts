use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;

use super::traits::{AccountResolver, SessionStore};
use crate::oauth::AuthClient;

/// Shared state for auth route handlers.
///
/// Generic over `U` (AccountResolver) and `S` (SessionStore) for compile-time
/// monomorphic dispatch — no `dyn` trait objects or `Pin<Box<dyn Future>>`.
pub(super) struct AuthState<U, S> {
    pub(super) client: Arc<AuthClient>,
    pub(super) account_resolver: Arc<U>,
    pub(super) session_store: Arc<S>,
    pub(super) cookie_key: Key,
    pub(super) session_cookie_name: String,
    pub(super) session_ttl_days: i64,
    pub(super) secure_cookies: bool,
    pub(super) auth_path: String,
    pub(super) login_redirect: String,
    pub(super) logout_redirect: String,
    pub(super) error_redirect: String,
    pub(super) dev_login_enabled: bool,
}

// Manual Clone: avoid derive adding `U: Clone, S: Clone` bounds.
// Arc<T> is Clone regardless of T.
impl<U, S> Clone for AuthState<U, S> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            account_resolver: self.account_resolver.clone(),
            session_store: self.session_store.clone(),
            cookie_key: self.cookie_key.clone(),
            session_cookie_name: self.session_cookie_name.clone(),
            session_ttl_days: self.session_ttl_days,
            secure_cookies: self.secure_cookies,
            auth_path: self.auth_path.clone(),
            login_redirect: self.login_redirect.clone(),
            logout_redirect: self.logout_redirect.clone(),
            error_redirect: self.error_redirect.clone(),
            dev_login_enabled: self.dev_login_enabled,
        }
    }
}

// PrivateCookieJar requires Key to be extractable from state
impl<U: AccountResolver, S: SessionStore> FromRef<AuthState<U, S>> for Key {
    fn from_ref(state: &AuthState<U, S>) -> Self {
        state.cookie_key.clone()
    }
}
