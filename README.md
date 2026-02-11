# ppoppo-accounts

`OAuth2` PKCE client, PASETO v4.public token verification, and plug-and-play Axum auth middleware for [Ppoppo Accounts System (PAS)](https://accounts.ppoppo.com).

## What it does

- **`OAuth2` PKCE S256** flow: authorization URL generation, code exchange, user info retrieval
- **PASETO v4.public** token verification with issuer/audience validation and key ID extraction
- **Axum middleware**: plug-and-play login/logout/callback routes with session management
- **ppnum validation**: 11-digit Ppoppo user identifier format (`777XXXXXXXX`)
- **Well-known document** types for `/.well-known/paseto.json` endpoint

## Design principles

- **Feature-gated modules** -- use only what you need; `oauth`, `token`, and `axum` are independent features
- **No env-var coupling** -- the core library never reads environment variables; apps pass configuration via the builder pattern (the `axum` middleware offers an optional `from_env()` convenience)
- **TLS via rustls** -- no OpenSSL dependency; pure-Rust TLS for the HTTP client

## Quick start (Axum middleware)

Add "Login with Ppoppo" to an Axum app:

```rust,ignore
use ppoppo_accounts::middleware::{
    auth_routes, AuthUser, PasAuthConfig, SessionStore, UserStore, NewSession,
};

// 1. Implement two traits for your app
impl UserStore for MyAppState {
    async fn find_or_create(&self, ppnum_id: &str, user_info: &UserInfo)
        -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Find or create user, return your app's user ID
    }
}

impl SessionStore for MyAppState {
    async fn create(&self, session: NewSession) -> Result<String, ...> { /* ... */ }
    async fn find(&self, id: &str) -> Result<Option<AuthUser>, ...> { /* ... */ }
    async fn delete(&self, id: &str) -> Result<(), ...> { /* ... */ }
}

// 2. Configure and mount
let config = PasAuthConfig::from_env()?;
let app = Router::new()
    .merge(auth_routes(config, user_store, session_store))
    .route("/dashboard", get(dashboard));

// 3. Use AuthUser extractor in protected routes
async fn dashboard(user: AuthUser) -> impl IntoResponse {
    format!("Hello, {}", user.ppnum_id)
}
```

## Low-level usage (OAuth2 client)

For custom OAuth2 integration without the Axum middleware:

```rust,ignore
use ppoppo_accounts::{Config, AuthClient};

let config = Config::builder()
    .client_id("my-app")
    .redirect_uri("https://my-app.com/callback")
    .build()?;

let client = AuthClient::new(config);

// Generate authorization URL with PKCE
let auth_req = client.authorization_url();
// auth_req.url        -- redirect user here
// auth_req.code_verifier -- store in session
// auth_req.state      -- store for CSRF validation

// After callback: exchange code for tokens
let tokens = client.exchange_code(&code, &auth_req.code_verifier).await?;

// Fetch user info
let user = client.get_user_info(&tokens.access_token).await?;
println!("ppnum: {:?}", user.ppnum);
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `oauth` | Yes | `OAuth2` PKCE client (`AuthClient`, `Config`, PKCE helpers) |
| `token` | Yes | PASETO v4.public token verification (`verify_v4_public_access_token`) |
| `axum`  | No  | Plug-and-play Axum middleware (`auth_routes`, `AuthUser`, `PasAuthConfig`) |

Use only what you need:

```toml
# Axum middleware (recommended for Axum apps)
ppoppo-accounts = { version = "0.2", features = ["axum"] }

# OAuth2 only (no token verification, no middleware)
ppoppo-accounts = { version = "0.2", default-features = false, features = ["oauth"] }

# Token verification only (no HTTP client)
ppoppo-accounts = { version = "0.2", default-features = false, features = ["token"] }

# Everything
ppoppo-accounts = { version = "0.2", features = ["axum"] }

# ppnum validation + well-known types only (minimal)
ppoppo-accounts = { version = "0.2", default-features = false }
```

## Known constraints

### `ring` transitive dependency (`token` feature)

The `token` feature pulls in `pasetors`, which transitively depends on [`ring`](https://github.com/briansmith/ring). This means:

- **C compiler required** at build time (ring includes C/assembly sources)
- **WASM targets not supported** by ring (wasm32-unknown-unknown will fail to compile)
- **Cross-compilation** may require additional toolchain setup for the target platform

If you only need the `OAuth2` flow or Axum middleware, use `default-features = false, features = ["axum"]` to avoid ring entirely.

## License

Licensed under either of

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
