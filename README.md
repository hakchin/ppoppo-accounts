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
- **Generic auth context** -- `SessionStore::AuthContext` lets consumers return their own auth type from `find()`, eliminating parallel auth middleware

## Quick start (Axum middleware)

Add "Login with Ppoppo" to an Axum app:

```rust,ignore
use ppoppo_accounts::middleware::{
    auth_routes, resolve_session, PasAuthConfig, SessionStore, AccountResolver, NewSession,
};

// 1. Implement two traits for your app
impl AccountResolver for MyAdapter {
    async fn resolve(&self, ppnum_id: &PpnumId, user_info: &UserInfo)
        -> Result<UserId, MyError> {
        // Find or create user by ppnum_id, return your app's user ID
    }
}

impl SessionStore for MyAdapter {
    type AuthContext = MyAuthUser; // your handler's auth type

    async fn create(&self, session: NewSession) -> Result<SessionId, MyError> { /* ... */ }
    async fn find(&self, id: &SessionId) -> Result<Option<MyAuthUser>, MyError> { /* ... */ }
    async fn delete(&self, id: &SessionId) -> Result<(), MyError> { /* ... */ }
}

// 2. Configure and mount
let config = PasAuthConfig::from_env()?;
let app = Router::new()
    .merge(auth_routes(config, account_resolver, session_store))
    .route("/dashboard", get(dashboard));

// 3. Use resolve_session() in your middleware
async fn auth_middleware(
    State(state): State<MyState>,
    jar: PrivateCookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = resolve_session(&*state.session_store, &jar, "session_cookie")
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    request.extensions_mut().insert(auth);
    Ok(next.run(request).await)
}
```

## Low-level usage (OAuth2 client)

For custom OAuth2 integration without the Axum middleware:

```rust,ignore
use ppoppo_accounts::{OAuthConfig, AuthClient};

let config = OAuthConfig::new("my-app", "https://my-app.com/callback".parse()?);

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
| `oauth` | Yes | `OAuth2` PKCE client (`AuthClient`, `OAuthConfig`, PKCE helpers) |
| `token` | Yes | PASETO v4.public token verification (`verify_v4_public_access_token`) |
| `axum`  | No  | Plug-and-play Axum middleware (`auth_routes`, `resolve_session`, `PasAuthConfig`) |

Use only what you need:

```toml
# Axum middleware (recommended for Axum apps)
ppoppo-accounts = { version = "0.5", features = ["axum"] }

# OAuth2 only (no token verification, no middleware)
ppoppo-accounts = { version = "0.5", default-features = false, features = ["oauth"] }

# Token verification only (no HTTP client)
ppoppo-accounts = { version = "0.5", default-features = false, features = ["token"] }

# Everything
ppoppo-accounts = { version = "0.5", features = ["axum"] }

# ppnum validation + well-known types only (minimal)
ppoppo-accounts = { version = "0.5", default-features = false }
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
