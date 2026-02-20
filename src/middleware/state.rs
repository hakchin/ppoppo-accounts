use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;

use super::config::AuthSettings;
use super::traits::{AccountResolver, SessionStore};
use crate::oauth::AuthClient;

/// Shared state for auth route handlers.
pub(super) struct AuthState<U, S> {
    pub(super) client: Arc<AuthClient>,
    pub(super) account_resolver: Arc<U>,
    pub(super) session_store: Arc<S>,
    pub(super) settings: AuthSettings,
}

// Manual Clone: avoid derive adding `U: Clone, S: Clone` bounds.
impl<U, S> Clone for AuthState<U, S> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            account_resolver: self.account_resolver.clone(),
            session_store: self.session_store.clone(),
            settings: self.settings.clone(),
        }
    }
}

// PrivateCookieJar requires Key to be extractable from state
impl<U: AccountResolver, S: SessionStore> FromRef<AuthState<U, S>> for Key {
    fn from_ref(state: &AuthState<U, S>) -> Self {
        state.settings.cookie_key.clone()
    }
}
