use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::pkce;

/// Ppoppo Accounts `OAuth2` configuration.
///
/// Use [`Config::builder()`] to construct.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    pub(crate) client_id: String,
    pub(crate) auth_url: String,
    pub(crate) token_url: String,
    pub(crate) userinfo_url: String,
    pub(crate) redirect_uri: String,
    pub(crate) scopes: Vec<String>,
}

impl Config {
    /// Create a builder for programmatic configuration.
    #[must_use]
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// `OAuth2` client ID.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Authorization endpoint URL.
    #[must_use]
    pub fn auth_url(&self) -> &str {
        &self.auth_url
    }

    /// Token exchange endpoint URL.
    #[must_use]
    pub fn token_url(&self) -> &str {
        &self.token_url
    }

    /// User info endpoint URL.
    #[must_use]
    pub fn userinfo_url(&self) -> &str {
        &self.userinfo_url
    }

    /// `OAuth2` redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Requested `OAuth2` scopes.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
}

/// Builder for [`Config`].
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    client_id: Option<String>,
    auth_url: Option<String>,
    token_url: Option<String>,
    userinfo_url: Option<String>,
    redirect_uri: Option<String>,
    scopes: Option<Vec<String>>,
}

impl ConfigBuilder {
    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    #[must_use]
    pub fn auth_url(mut self, auth_url: impl Into<String>) -> Self {
        self.auth_url = Some(auth_url.into());
        self
    }

    #[must_use]
    pub fn token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = Some(token_url.into());
        self
    }

    #[must_use]
    pub fn userinfo_url(mut self, userinfo_url: impl Into<String>) -> Self {
        self.userinfo_url = Some(userinfo_url.into());
        self
    }

    #[must_use]
    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }

    #[must_use]
    pub fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = Some(scopes);
        self
    }

    /// Build the [`Config`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuth`] if `client_id` or `redirect_uri` is not set.
    pub fn build(self) -> Result<Config, Error> {
        Ok(Config {
            client_id: self
                .client_id
                .ok_or_else(|| Error::OAuth("client_id is required".into()))?,
            auth_url: self
                .auth_url
                .unwrap_or_else(|| "https://accounts.ppoppo.com/oauth/authorize".into()),
            token_url: self
                .token_url
                .unwrap_or_else(|| "https://accounts.ppoppo.com/oauth/token".into()),
            userinfo_url: self
                .userinfo_url
                .unwrap_or_else(|| "https://accounts.ppoppo.com/oauth/userinfo".into()),
            redirect_uri: self
                .redirect_uri
                .ok_or_else(|| Error::OAuth("redirect_uri is required".into()))?,
            scopes: self
                .scopes
                .unwrap_or_else(|| vec!["openid".into(), "profile".into()]),
        })
    }
}

/// `OAuth2` authorization client for Ppoppo Accounts.
pub struct AuthClient {
    config: Config,
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
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub ppnum: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub created_at: Option<String>,
}

impl AuthClient {
    /// Create a new Ppoppo Accounts auth client.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    /// Generate an authorization URL with PKCE parameters.
    #[must_use]
    pub fn authorization_url(&self) -> AuthorizationRequest {
        let state = pkce::generate_state();
        let code_verifier = pkce::generate_code_verifier();
        let code_challenge = pkce::generate_code_challenge(&code_verifier);

        let scope = self.config.scopes.join(" ");

        let url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256&scope={}",
            self.config.auth_url,
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.redirect_uri),
            urlencoding::encode(&state),
            urlencoding::encode(&code_challenge),
            urlencoding::encode(&scope),
        );

        AuthorizationRequest {
            url,
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
            ("redirect_uri", &self.config.redirect_uri),
            ("client_id", &self.config.client_id),
            ("code_verifier", code_verifier),
        ];

        let response = self
            .http
            .post(&self.config.token_url)
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
            .get(&self.config.userinfo_url)
            .bearer_auth(access_token)
            .send()
            .await?;

        let response = Self::ensure_success(response, "userinfo request").await?;
        response.json::<UserInfo>().await.map_err(Into::into)
    }

    /// Checks HTTP response status; returns the response on success or an error with details.
    async fn ensure_success(
        response: reqwest::Response,
        operation: &str,
    ) -> Result<reqwest::Response, Error> {
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(Error::OAuth(format!(
            "{operation} failed: {status} - {body}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            client_id: "test-client".into(),
            auth_url: "https://accounts.ppoppo.com/oauth/authorize".into(),
            token_url: "https://accounts.ppoppo.com/oauth/token".into(),
            userinfo_url: "https://accounts.ppoppo.com/oauth/userinfo".into(),
            redirect_uri: "https://example.com/callback".into(),
            scopes: vec!["openid".into(), "profile".into()],
        }
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
    fn test_config_builder() {
        let config = Config::builder()
            .client_id("my-app")
            .redirect_uri("https://my-app.com/callback")
            .build()
            .unwrap();

        assert_eq!(config.client_id(), "my-app");
        assert_eq!(config.redirect_uri(), "https://my-app.com/callback");
        assert_eq!(
            config.auth_url(),
            "https://accounts.ppoppo.com/oauth/authorize"
        );
    }

    #[test]
    fn test_config_builder_missing_client_id() {
        let result = Config::builder()
            .redirect_uri("https://example.com/callback")
            .build();

        assert!(result.is_err());
    }
}
