# ppoppo-accounts

`OAuth2` PKCE client and PASETO v4.public token verification for [Ppoppo Accounts System (PAS)](https://accounts.ppoppo.com).

## What it does

- **`OAuth2` PKCE S256** flow: authorization URL generation, code exchange, user info retrieval
- **PASETO v4.public** token verification with issuer/audience validation and key ID extraction
- **ppnum validation**: 11-digit Ppoppo user identifier format (`777XXXXXXXX`)
- **Well-known document** types for `/.well-known/paseto.json` endpoint

## Design principles

- **No env-var coupling** -- the library never reads environment variables; apps pass configuration via the builder pattern
- **Feature-gated modules** -- use only what you need; `oauth` and `token` are independent features
- **TLS via rustls** -- no OpenSSL dependency; pure-Rust TLS for the HTTP client

## Usage

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

Use only what you need:

```toml
# OAuth2 only (no token verification)
ppoppo-accounts = { version = "0.1", default-features = false, features = ["oauth"] }

# Token verification only (no HTTP client)
ppoppo-accounts = { version = "0.1", default-features = false, features = ["token"] }

# ppnum validation + well-known types only (minimal)
ppoppo-accounts = { version = "0.1", default-features = false }
```

## Known constraints

### `ring` transitive dependency (`token` feature)

The `token` feature pulls in `rusty_paseto`, which transitively depends on [`ring`](https://github.com/briansmith/ring). This means:

- **C compiler required** at build time (ring includes C/assembly sources)
- **WASM targets not supported** by ring (wasm32-unknown-unknown will fail to compile)
- **Cross-compilation** may require additional toolchain setup for the target platform

This is an upstream constraint in `rusty_paseto` and cannot be resolved at the ppoppo-accounts level. If you only need the `OAuth2` flow, use `default-features = false, features = ["oauth"]` to avoid ring entirely.

## License

MIT
