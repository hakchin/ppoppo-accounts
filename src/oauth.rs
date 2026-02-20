use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::Error;
use crate::pkce;
use crate::types::{Ppnum, PpnumId};

/// Ppoppo Accounts `OAuth2` configuration.
///
/// Required fields are constructor parameters — no runtime "missing field" errors.
///
/// ```rust,ignore
/// use ppoppo_accounts::OAuthConfig;
///
/// let config = OAuthConfig::new("my-client-id", "https://my-app.com/callback".parse()?);
/// // Optional overrides via chaining:
/// let config = config
///     .with_auth_url("https://custom.example.com/authorize".parse()?);
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OAuthConfig {
    pub(crate) client_id: String,
    pub(crate) auth_url: Url,
    pub(crate) token_url: Url,
    pub(crate) userinfo_url: Url,
    pub(crate) redirect_uri: Url,
    pub(crate) scopes: Vec<String>,
}

impl OAuthConfig {
    /// Create a new OAuth2 configuration.
    ///
    /// Required fields are parameters — compile-time enforcement, no `Result`.
    #[must_use]
    pub fn new(client_id: impl Into<String>, redirect_uri: Url) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri,
            auth_url: "https://accounts.ppoppo.com/oauth/authorize"
                .parse()
                .expect("valid default URL"),
            token_url: "https://accounts.ppoppo.com/oauth/token"
                .parse()
                .expect("valid default URL"),
            userinfo_url: "https://accounts.ppoppo.com/oauth/userinfo"
                .parse()
                .expect("valid default URL"),
            scopes: vec!["openid".into(), "profile".into()],
        }
    }

    /// Override the PAS authorization endpoint.
    #[must_use]
    pub fn with_auth_url(mut self, url: Url) -> Self {
        self.auth_url = url;
        self
    }

    /// Override the PAS token endpoint.
    #[must_use]
    pub fn with_token_url(mut self, url: Url) -> Self {
        self.token_url = url;
        self
    }

    /// Override the PAS userinfo endpoint.
    #[must_use]
    pub fn with_userinfo_url(mut self, url: Url) -> Self {
        self.userinfo_url = url;
        self
    }

    /// Override the OAuth2 scopes (default: `["openid", "profile"]`).
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// `OAuth2` client ID.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Authorization endpoint URL.
    #[must_use]
    pub fn auth_url(&self) -> &Url {
        &self.auth_url
    }

    /// Token exchange endpoint URL.
    #[must_use]
    pub fn token_url(&self) -> &Url {
        &self.token_url
    }

    /// User info endpoint URL.
    #[must_use]
    pub fn userinfo_url(&self) -> &Url {
        &self.userinfo_url
    }

    /// `OAuth2` redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }

    /// Requested `OAuth2` scopes.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
}

/// `OAuth2` authorization client for Ppoppo Accounts.
pub struct AuthClient {
    config: OAuthConfig,
    http: reqwest::Client,
}

/// Authorization URL with PKCE parameters to store in session.
#[non_exhaustive]
pub struct AuthorizationRequest {
    pub url: String,
    pub state: String,
    pub code_verifier: String,
}

/// Token response from PAS token endpoint.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// User info from Ppoppo Accounts userinfo endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UserInfo {
    pub sub: PpnumId,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub ppnum: Option<Ppnum>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub created_at: Option<time::OffsetDateTime>,
}

impl UserInfo {
    /// Create a new `UserInfo` with only the required `sub` field.
    #[must_use]
    pub fn new(sub: PpnumId) -> Self {
        Self {
            sub,
            email: None,
            ppnum: None,
            email_verified: None,
            created_at: None,
        }
    }

    /// Set the email.
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set the ppnum.
    #[must_use]
    pub fn with_ppnum(mut self, ppnum: Ppnum) -> Self {
        self.ppnum = Some(ppnum);
        self
    }

    /// Set the email_verified flag.
    #[must_use]
    pub fn with_email_verified(mut self, verified: bool) -> Self {
        self.email_verified = Some(verified);
        self
    }
}

impl AuthClient {
    /// Create a new Ppoppo Accounts auth client.
    #[must_use]
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    /// Use a custom HTTP client (for connection pool reuse or testing).
    #[must_use]
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http = client;
        self
    }

    /// Generate an authorization URL with PKCE parameters.
    #[must_use]
    pub fn authorization_url(&self) -> AuthorizationRequest {
        let state = pkce::generate_state();
        let code_verifier = pkce::generate_code_verifier();
        let code_challenge = pkce::generate_code_challenge(&code_verifier);
        let scope = self.config.scopes.join(" ");

        let mut url = self.config.auth_url.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", self.config.redirect_uri.as_str())
            .append_pair("state", &state)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("scope", &scope);

        AuthorizationRequest {
            url: url.into(),
            state,
            code_verifier,
        }
    }

    /// Exchange an authorization code for tokens using PKCE.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] on network failure, or
    /// [`Error::OAuth`] if the token endpoint returns an error.
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, Error> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("client_id", self.config.client_id.as_str()),
            ("code_verifier", code_verifier),
        ];

        let response = self
            .http
            .post(self.config.token_url.clone())
            .form(&params)
            .send()
            .await?;

        let response = Self::ensure_success(response, "token exchange").await?;
        response.json::<TokenResponse>().await.map_err(Into::into)
    }

    /// Fetch user info using an access token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] on network failure, or
    /// [`Error::OAuth`] if the userinfo endpoint returns an error.
    pub async fn get_user_info(&self, access_token: &str) -> Result<UserInfo, Error> {
        let response = self
            .http
            .get(self.config.userinfo_url.clone())
            .bearer_auth(access_token)
            .send()
            .await?;

        let response = Self::ensure_success(response, "userinfo request").await?;
        response.json::<UserInfo>().await.map_err(Into::into)
    }

    /// Checks HTTP response status; returns the response on success or an error with details.
    async fn ensure_success(
        response: reqwest::Response,
        operation: &'static str,
    ) -> Result<reqwest::Response, Error> {
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        Err(Error::OAuth {
            operation,
            status: Some(status),
            detail: body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OAuthConfig {
        OAuthConfig::new(
            "test-client",
            "https://example.com/callback".parse().unwrap(),
        )
    }

    #[test]
    fn test_authorization_url_contains_pkce() {
        let client = AuthClient::new(test_config());
        let req = client.authorization_url();

        assert!(req.url.contains("code_challenge="));
        assert!(req.url.contains("code_challenge_method=S256"));
        assert!(req.url.contains("state="));
        assert!(req.url.contains("response_type=code"));
        assert!(req.url.contains("client_id=test-client"));
        assert!(!req.code_verifier.is_empty());
        assert!(!req.state.is_empty());
    }

    #[test]
    fn test_authorization_url_unique_per_call() {
        let client = AuthClient::new(test_config());
        let req1 = client.authorization_url();
        let req2 = client.authorization_url();

        assert_ne!(req1.state, req2.state);
        assert_ne!(req1.code_verifier, req2.code_verifier);
    }

    #[test]
    fn test_config_constructor() {
        let config = OAuthConfig::new("my-app", "https://my-app.com/callback".parse().unwrap());

        assert_eq!(config.client_id(), "my-app");
        assert_eq!(config.redirect_uri().as_str(), "https://my-app.com/callback");
        assert_eq!(
            config.auth_url().as_str(),
            "https://accounts.ppoppo.com/oauth/authorize"
        );
    }

    #[test]
    fn test_config_with_overrides() {
        let config = OAuthConfig::new("my-app", "https://my-app.com/callback".parse().unwrap())
            .with_auth_url("https://custom.example.com/authorize".parse().unwrap())
            .with_scopes(vec!["openid".into()]);

        assert_eq!(
            config.auth_url().as_str(),
            "https://custom.example.com/authorize"
        );
        assert_eq!(config.scopes(), &["openid"]);
    }
}
