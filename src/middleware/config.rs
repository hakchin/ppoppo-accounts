use axum_extra::extract::cookie::Key;

use super::error::AuthError;
use crate::oauth::{AuthClient, Config as PasConfig};

/// PAS authentication configuration.
///
/// Use [`from_env()`](PasAuthConfig::from_env) for convention-based setup,
/// or [`builder()`](PasAuthConfig::builder) for full control.
pub struct PasAuthConfig {
    /// ppoppo-accounts OAuth2 client.
    pub(super) client: AuthClient,
    /// Cookie encryption key (for PrivateCookieJar).
    pub(super) cookie_key: Key,
    /// Session cookie name.
    pub(super) session_cookie_name: String,
    /// Session cookie TTL in days.
    pub(super) session_ttl_days: i64,
    /// Use secure cookies (HTTPS only).
    pub(super) secure_cookies: bool,
    /// Auth routes base path.
    pub(super) auth_path: String,
    /// Redirect destination after successful login.
    pub(super) login_redirect: String,
    /// Redirect destination after logout.
    pub(super) logout_redirect: String,
    /// Enable `/dev-login` route.
    pub(super) dev_login_enabled: bool,
}

impl PasAuthConfig {
    /// Create config from environment variables.
    ///
    /// # Required env vars
    /// - `PAS_CLIENT_ID`: OAuth2 client ID
    /// - `PAS_REDIRECT_URI`: OAuth2 callback URI
    ///
    /// # Optional env vars
    /// - `PAS_AUTH_URL`: Override PAS authorize endpoint
    /// - `PAS_TOKEN_URL`: Override PAS token endpoint
    /// - `PAS_USERINFO_URL`: Override PAS userinfo endpoint
    /// - `PAS_SCOPES`: Comma-separated OAuth2 scopes
    /// - `DEV_AUTH`: If set, enables dev-login route and disables secure cookies
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Config`] if required env vars are missing.
    pub fn from_env() -> Result<Self, AuthError> {
        let client_id = std::env::var("PAS_CLIENT_ID")
            .map_err(|_| AuthError::Config("PAS_CLIENT_ID is required".into()))?;
        let redirect_uri = std::env::var("PAS_REDIRECT_URI")
            .map_err(|_| AuthError::Config("PAS_REDIRECT_URI is required".into()))?;

        let mut builder = PasConfig::builder()
            .client_id(client_id)
            .redirect_uri(redirect_uri);

        if let Ok(url) = std::env::var("PAS_AUTH_URL") {
            builder = builder.auth_url(url);
        }
        if let Ok(url) = std::env::var("PAS_TOKEN_URL") {
            builder = builder.token_url(url);
        }
        if let Ok(url) = std::env::var("PAS_USERINFO_URL") {
            builder = builder.userinfo_url(url);
        }
        if let Ok(scopes) = std::env::var("PAS_SCOPES") {
            builder = builder.scopes(scopes.split(',').map(|s| s.trim().to_string()).collect());
        }

        let config = builder.build().map_err(AuthError::from)?;
        let dev_auth = std::env::var("DEV_AUTH").is_ok();

        let cookie_key = std::env::var("COOKIE_KEY")
            .ok()
            .and_then(|k| {
                let bytes = k.as_bytes();
                Key::try_from(bytes).ok()
            })
            .unwrap_or_else(Key::generate);

        Ok(Self {
            client: AuthClient::new(config),
            cookie_key,
            session_cookie_name: "__ppoppo_session".into(),
            session_ttl_days: 30,
            secure_cookies: !dev_auth,
            auth_path: "/api/auth".into(),
            login_redirect: "/".into(),
            logout_redirect: "/".into(),
            dev_login_enabled: dev_auth,
        })
    }

    /// Create a builder for full control over configuration.
    #[must_use]
    pub fn builder() -> PasAuthConfigBuilder {
        PasAuthConfigBuilder::default()
    }
}

/// Builder for [`PasAuthConfig`].
pub struct PasAuthConfigBuilder {
    client: Option<AuthClient>,
    cookie_key: Option<Key>,
    session_cookie_name: Option<String>,
    session_ttl_days: Option<i64>,
    secure_cookies: Option<bool>,
    auth_path: Option<String>,
    login_redirect: Option<String>,
    logout_redirect: Option<String>,
    dev_login_enabled: Option<bool>,
}

impl Default for PasAuthConfigBuilder {
    fn default() -> Self {
        Self {
            client: None,
            cookie_key: None,
            session_cookie_name: None,
            session_ttl_days: None,
            secure_cookies: None,
            auth_path: None,
            login_redirect: None,
            logout_redirect: None,
            dev_login_enabled: None,
        }
    }
}

impl PasAuthConfigBuilder {
    /// Set the PAS OAuth2 client.
    #[must_use]
    pub fn client(mut self, client: AuthClient) -> Self {
        self.client = Some(client);
        self
    }

    /// Set the cookie encryption key. If not set, a random key is generated.
    #[must_use]
    pub fn cookie_key(mut self, key: Key) -> Self {
        self.cookie_key = Some(key);
        self
    }

    /// Set the session cookie name (default: `"__ppoppo_session"`).
    #[must_use]
    pub fn session_cookie_name(mut self, name: impl Into<String>) -> Self {
        self.session_cookie_name = Some(name.into());
        self
    }

    /// Set the session cookie TTL in days (default: 30).
    #[must_use]
    pub fn session_ttl_days(mut self, days: i64) -> Self {
        self.session_ttl_days = Some(days);
        self
    }

    /// Set whether to use secure cookies (default: true).
    #[must_use]
    pub fn secure_cookies(mut self, secure: bool) -> Self {
        self.secure_cookies = Some(secure);
        self
    }

    /// Set the auth routes base path (default: `"/api/auth"`).
    #[must_use]
    pub fn auth_path(mut self, path: impl Into<String>) -> Self {
        self.auth_path = Some(path.into());
        self
    }

    /// Set the post-login redirect path (default: `"/"`).
    #[must_use]
    pub fn login_redirect(mut self, path: impl Into<String>) -> Self {
        self.login_redirect = Some(path.into());
        self
    }

    /// Set the post-logout redirect path (default: `"/"`).
    #[must_use]
    pub fn logout_redirect(mut self, path: impl Into<String>) -> Self {
        self.logout_redirect = Some(path.into());
        self
    }

    /// Enable the dev-login route (default: false).
    #[must_use]
    pub fn dev_login_enabled(mut self, enabled: bool) -> Self {
        self.dev_login_enabled = Some(enabled);
        self
    }

    /// Build the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Config`] if `client` is not set.
    pub fn build(self) -> Result<PasAuthConfig, AuthError> {
        Ok(PasAuthConfig {
            client: self
                .client
                .ok_or_else(|| AuthError::Config("client is required".into()))?,
            cookie_key: self.cookie_key.unwrap_or_else(Key::generate),
            session_cookie_name: self
                .session_cookie_name
                .unwrap_or_else(|| "__ppoppo_session".into()),
            session_ttl_days: self.session_ttl_days.unwrap_or(30),
            secure_cookies: self.secure_cookies.unwrap_or(true),
            auth_path: self.auth_path.unwrap_or_else(|| "/api/auth".into()),
            login_redirect: self.login_redirect.unwrap_or_else(|| "/".into()),
            logout_redirect: self.logout_redirect.unwrap_or_else(|| "/".into()),
            dev_login_enabled: self.dev_login_enabled.unwrap_or(false),
        })
    }
}
