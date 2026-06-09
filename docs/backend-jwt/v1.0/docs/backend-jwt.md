# Backend JWT

Generates a signed JWT containing authenticated user information and injects it into the upstream request header. Run this policy **after** an authentication policy (e.g. `jwt-auth`, `basic-auth`, `api-key-auth`) to forward a gateway-signed assertion to backend services.

Backend services can verify the generated JWT using the gateway's corresponding public key — they do not need access to the original client credential (API key, OAuth token, etc.).

## How It Works

1. After an auth policy authenticates the request, the gateway's `AuthContext` is populated with the subject, auth type, issuer, audience, and any custom properties.
2. The Backend JWT policy reads this context, builds a JWT with the configured claims, and signs it with the configured RSA or ECDSA private key.
3. The signed JWT is set as the value of the configured upstream header (default: `x-jwt-assertion`).
4. The upstream service verifies the JWT using the matching public key.

If no authentication context is present:
- With `requireAuthentication: false` (default) — the request is forwarded without a backend JWT.
- With `requireAuthentication: true` — the request is rejected with `401 Unauthorized`.

## Claims in the Generated Token

| Claim | Source |
|---|---|
| `sub` | `AuthContext.Subject` (JWT sub, basic-auth username, API key owner) |
| `iss` | `system.issuer` parameter |
| `iat` | Current time |
| `exp` | Current time + `system.tokenExpiry` |
| `auth_type` | `AuthContext.AuthType` (e.g. `jwt`, `basic`, `apikey`) |
| `original_iss` | `AuthContext.Issuer` — the original token issuer (JWT auth only) |
| `aud` | `AuthContext.Audience` (JWT auth only) |
| `credential_id` | `AuthContext.CredentialID` (API key application ID, OAuth client_id) |
| _mapped_ | Selected `AuthContext.Properties` keys via `claimMappings` |
| _custom_ | Static values from `customClaims` |

## Configuration

### System Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `signingKey.inline` | string | — | PEM-encoded RSA or ECDSA private key (mutually exclusive with `path`) |
| `signingKey.path` | string | — | Path to a PEM private key file (mutually exclusive with `inline`) |
| `algorithm` | string | `RS256` | Signing algorithm: `RS256`, `RS384`, `RS512` (RSA) or `ES256`, `ES384`, `ES512` (ECDSA) |
| `issuer` | string | `""` | Value of the `iss` claim in generated tokens |
| `tokenExpiry` | string | `15m` | Token validity as a Go duration string (e.g. `"15m"`, `"1h"`) |

### User Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `header` | string | `x-jwt-assertion` | Upstream request header to set the generated JWT on |
| `requireAuthentication` | boolean | `false` | Reject unauthenticated requests with 401 when true |
| `claimMappings` | object | `{}` | Map `AuthContext.Properties` keys to JWT claim names |
| `customClaims` | object | `{}` | Static claim name→value pairs added to every generated token |

## Example

```yaml
# System-level (gateway config)
system:
  signingKey:
    path: /etc/certs/backend-jwt.key
  algorithm: RS256
  issuer: https://gateway.example.com
  tokenExpiry: 15m

# Per-route policy attachment
policies:
  - name: backend-jwt
    parameters:
      header: x-jwt-assertion
      requireAuthentication: true
      claimMappings:
        app_id: application_id
        org:    organization
      customClaims:
        env: production
```

The upstream service then validates the `x-jwt-assertion` header using the public key matching the gateway's private key.

## Related Policies

- [`jwt-auth`](../../jwt-auth/v1.0/docs/jwt-authentication.md) — validates incoming JWTs from clients
- [`basic-auth`](../../basic-auth/) — authenticates clients with username/password; pairs well with Backend JWT to forward user identity
- [`api-key-auth`](../../api-key-auth/) — authenticates clients with API keys; pairs well with Backend JWT to forward application identity
