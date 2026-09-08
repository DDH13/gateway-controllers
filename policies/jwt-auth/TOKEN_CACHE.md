# JWT Auth token verdict cache — design notes

- **Origin:** [PR #297 — \[APIP GC\] Refactor JWT cache](https://github.com/wso2/gateway-controllers/pull/297) (`DDH13`), merged to `main` as `e58a251` (improve perf) + `b32eee0` (refactor cache), with a small follow-up doc fix in `8001ce9`.
- **Tracking issue:** `wso2-enterprise/wso2-apim-internal#18931`
- **Scope:** `policies/jwt-auth` — `jwtauth.go`, `jwtauth_tokencache_test.go`, `jwtauth_hardening_test.go`, `policy-definition.yaml`
- **Policy version:** `v1.3.1`

---

## Part 1 — How the cache works

### 1.1 What is cached, and why

The expensive part of `OnRequestHeaders` is not header parsing — it is everything below what the
code calls the *cache boundary* (`jwtauth.go:2334`):

1. unverified parse of the JWT,
2. walking every configured key manager and building `KeyManager` structs,
3. loading and parsing certificates / TLS configs (`os.ReadFile`, x509, ASN.1),
4. JWKS resolution, and
5. the actual signature verification plus `exp`/`nbf`/issuer checks.

The **token verdict cache** exists to skip all five on a repeat presentation of the same token
under the same verification configuration. It stores a `cachedVerdict` (`jwtauth.go:165`):

```go
type cachedVerdict struct {
    ok        bool          // true = verified, false = deterministically invalid
    claims    jwt.MapClaims // the verified claim set (positive verdicts only)
    scopes    []string      // scopes resolved via the matched key manager's scopeClaim
    reason    string        // failure reason (negative verdicts only)
    expiresAt time.Time     // enforced on read, not by the cache
}
```

Backing store is the SDK's `cache.InMemoryCache[cachedVerdict]`, one instance per process
(`ins`), created with **LRU eviction and `ttl=0`** — the SDK never expires anything on its own.
Expiry is enforced per entry in `getCachedVerdict`, which deletes and reports a miss once
`expiresAt` has passed (`jwtauth.go:277`). Size is a single global bound (`cacheMaxSize`, default
100 000) covering all APIs; changing it rebuilds and therefore flushes the cache
(`ensureTokenCache`, `jwtauth.go:242`), which is why the rebuild is guarded by a
`tokenCacheSize` comparison and only ever happens at deploy time.

### 1.2 Two kinds of verdict

**Positive** (`ok: true`) — written after a successful verification. Its `expiresAt` is the
*sooner* of `now + tokenCacheTtl` and the token's own `exp − leeway` (`jwtauth.go:2609`):

```go
expiresAt := time.Now().Add(tokenCacheTtl)
if expFloat, ok := claims["exp"].(float64); ok {
    if tokenExpiry := time.Unix(int64(expFloat), 0).Add(-leeway); tokenExpiry.Before(expiresAt) {
        expiresAt = tokenExpiry
    }
}
```

This is the invariant that makes a cache hit safe with **no crypto and no `exp`/`nbf` re-check**:
a live entry is always still inside the token's own validity window. `tokenCacheTtl` is then
purely a bound on the revocation/staleness exposure window. (If the computed `expiresAt` is
already in the past — a token whose remaining validity is shorter than the time the request took
— the positive write is skipped entirely rather than caching an already-dead entry.)

**Negative** (`ok: false`) — written only for failures that can never become successes:
a malformed token (`invalid token format`) and an expired token (`errTokenExpired`, matched with
`errors.Is`). Everything else — a JWKS fetch error, an `nbf` that has not yet arrived, an unknown
`kid` — is deliberately *not* cached, because it can flip to success later. Negative entries live
for `negativeCacheTtl` (default 30s) and exist to absorb retry storms, not to make security
decisions.

### 1.3 The cache key

The key is a complete function of the verdict: everything that determines the outcome but is not
part of the token goes into a **fingerprint**; the token supplies the rest.

```
kmDigest    = SHA256( canonical-encode(keyManagersRaw) )                       // keyManagersConfigDigest
fingerprint = SHA256( kmDigest ‖ validateIssuer ‖ issuers ‖ leeway
                              ‖ tokenCacheTtl ‖ negativeCacheTtl )             // tokenConfigFingerprintFromDigest
cacheKey    = hex( SHA256( fingerprint ‖ 0x00 ‖ rawToken ) )                   // buildTokenCacheKey
```

Two properties matter:

- **The token is hashed, never stored or logged raw.** It only exists in the hasher's pooled
  buffer for the duration of `buildTokenCacheKey`, and `release()` zeroes what it wrote before
  the buffer returns to the pool.
- **The encoding is unambiguous.** Every variable-length part is length-prefixed and every value
  carries a type tag, so `"ab"+"c"` cannot hash the same as `"a"+"bc"`, and the string `"1"`
  cannot hash the same as the number `1`. Map keys are sorted, because Go randomises map
  iteration and the digest would otherwise differ between two requests under an unchanged config.

Because `keyManagersRaw` is hashed **as configured** rather than in its parsed form, computing
the fingerprint never touches a certificate or a TLS handshake — that work stays behind the cache
boundary and happens only on a miss.

### 1.4 What is *not* in the key — and why that is safe

`finishAuthentication` (`jwtauth.go:2644`) is shared by both the hit and the miss path, and it
re-runs, on every single request, the checks that depend on per-route config held out of the key:

| Check | Where enforced |
|---|---|
| `audiences` | `finishAuthentication` — `aud` intersection |
| `scopes` / `requiredScopes` | `evaluateScopeConstraints` against the cached `scopes` |
| `claims` / `requiredClaims` | `evaluateClaimConstraints` against the cached `claims` |
| claim mappings, `userIdClaim`, token forwarding, `AuthContext` construction | `handleAuthSuccessHeaders` |

So a cached entry answers exactly one question — *"is this token's signature valid, and what does
it contain?"* — and never *"is this token allowed here?"*.

### 1.5 The three config-lifetime memoization caches

Separate from the verdict cache, three unbounded `sync.Map`s memoize pure functions of
configuration. Each is keyed by a digest of its own inputs, so a redeploy that changes the input
is automatically a miss, and each caches its error case too (a bad deploy should not re-parse on
every request):

| Cache | Keyed by | Replaces |
|---|---|---|
| `parsedPublicKeys` | the PEM string itself | re-running x509/ASN.1 parsing per key manager per miss |
| `resolveScopeConstraintsCache` | digest of `scopes` + `requiredScopes` | re-parsing scope constraints per request |
| `resolveClaimConstraintsCache` | digest of `claims` + `requiredClaims` | re-parsing claim constraints per request |

These grow only with operator config churn — nothing a request can vary reaches a key — and
`resetJWTAuthSingletonCache` clears all three for test isolation. Neither `ScopeConstraints` nor
`ClaimConstraints` carries the same "shared, do not mutate" warning that `cachedVerdict.claims`
does (see §1.6) — worth adding for symmetry, since the slice/matcher fields they hand out are
just as shared (see Part 3, finding 4).

### 1.6 Sharing across APIs, and the resulting copy-on-read rule

The cache key carries **no API identity** (see Part 2, §2.1): one verified entry serves every API
and route that presents the same token under the same verification config. That means
`cachedVerdict.claims` and `.scopes` are handed out **by reference** and read concurrently by
every API sharing the entry — nothing downstream may mutate them in place. `buildProperties`,
`parseAudience`, and `buildScopesMap` all allocate fresh output, so they're fine. `buildTypedProperties`
(`jwtauth.go:1807`) is the one place that used to place container-valued claims
(`[]interface{}`, `map[string]interface{}`) straight into `AuthContext.TypedProperties`, where a
downstream policy could mutate them in place — a corruption that would now be visible to every
other API sharing the entry, not just the one that mutated it. `deepCopyClaimValue`
(`jwtauth.go:1830`) fixes this by recursively copying those two mutable container types before
handing them out; scalars (`string`, `float64`, `bool`, `nil`) are immutable in Go and safe to
alias as-is.

---

## Part 2 — What changed in this refactor (PR #297)

Four distinct changes, in rough order of importance. All are merged.

### 2.1 Cache entries are now shared across APIs

**Before:** `tokenConfigFingerprint(apiId, apiName, keyManagersRaw, validateIssuer, issuers, leeway)`.
API identity was part of the key, so a token presented to 20 APIs occupied 20 entries and paid
for 20 full verifications.

**After:** `apiId`/`apiName` are gone. The justification is that API identity determines nothing
about the verdict — the same key material and the same issuer-selection rules verify a token
identically no matter which API presented it — so one verification now serves every API the token
reaches, and the 100 000-entry budget stretches proportionally further.

The safety argument rests entirely on §1.4/§1.6, and the PR added
`TestTokenCache_SharedAcrossAPIs_ConstraintsStillEnforcedPerAPI` to pin it: API X (no audience
constraint) verifies and caches; API Y, with identical verification config but its own
`audiences`, reuses the entry with **no new JWKS fetch** and is still denied 401 by its own
audience check; API X is then still allowed. The test deliberately leaves the JWKS server up and
instead clears the unrelated JWKS-fetch cache, so a regression that reintroduces API identity
shows up as an extra fetch rather than hiding behind a coincidental 401.

### 2.2 A real bug fix: TTL bleed between routes

`tokenCacheTtl` and `negativeCacheTtl` are folded into the fingerprint. They play no part in
the verdict, but a cached entry's `expiresAt` is computed from the **writing** route's TTLs. Before
this change, route A with `tokenCacheTtl: 1h` and route B with `tokenCacheTtl: 200ms` computed the
*same* key, so whichever route wrote first silently dictated how long the other trusted the
verdict — B could skip verification for up to an hour, defeating the one knob that bounds its
revocation exposure. `TestTokenCache_DifferentTokenCacheTtl_DoesNotShareCacheEntry` locks in the
fix end to end.

Note that this bug predates the PR and is independent of §2.1 — removing `apiId` widens the
sharing that exposes it, so fixing it in the same change was the right call.

### 2.3 The hot-path allocation work

`tokenConfigFingerprint` used to `json.Marshal` the entire key-manager config and build a
`bytes.Buffer` string **on every request, including cache hits**. It is replaced by a pooled
`configHasher` (`jwtauth.go:315`) that appends a canonical encoding into a reusable `[]byte` and
hashes it in one pass. The comment on `configHasher` explains why it writes into a plain slice
rather than straight into a `hash.Hash`: `hash.Hash` is an interface, so every small `Write` forces
its argument to escape.

Measured on the exact key-derivation path (M4 Pro, ~1.5 KB token, one key manager with an
800-byte inline cert):

| | ns/op | B/op | allocs/op |
|---|---|---|---|
| before | ~4 100–5 600 | 7 190 | 35 |
| after | ~1 700–1 800 | 218 | 5 |

Roughly **2.5× faster and 33× less garbage per request** on that path alone, before counting the
verifications avoided by §2.1 or the parsing avoided by §1.5.

The second half of this work is `debugEnabled()` (`jwtauth.go:97`) — `slog` boxes every variadic
argument at the call site, which allocates even when the record is dropped for being below the
active level, so every multi-argument `slog.Debug` on the request path is wrapped in
`if debugEnabled() { … }`.

### 2.4 Docs and version

`policy-definition.yaml` is at `v1.3.1`. The `cacheMaxSize` description spells out exactly which
config fields must match for a verdict entry to be shared — key managers, issuer validation,
issuers, leeway, `tokenCacheTtl`, and `negativeCacheTtl` — matching `tokenConfigFingerprintFromDigest`
(`jwtauth.go:463`) field for field; this was tightened after PR #297 landed, in a follow-up
docs commit (`8001ce9`) once the original description was found to omit the two TTL fields.

---

## Part 3 — Known issues / follow-ups

Findings from reviewing the merged refactor. None are blocking; most are informational.

**1. `configHasher.release()` can leave token bytes on the heap after buffer growth (low, open).**
`release()` (`jwtauth.go:337`) zeroes `c.buf[:len(c.buf)]`, but `buildTokenCacheKey`
(`jwtauth.go:432`) stages the token with `append`. When the pooled buffer is too small, `append`
allocates a new array and copies — the old array, holding the fingerprint and a prefix of the
token, is orphaned unzeroed. The comment there claims the token "does not persist in that pooled
heap memory for a future caller (or a heap/core dump) to read", which is true of the retained
buffer but not of the ones dropped during growth. Steady state is fine (buffers reach token size
and stop growing); the window is the first requests after a pool refill. Cheap fix — size the
buffer once before staging:

```go
if n := len(fingerprint) + 1 + len(token); cap(c.buf) < n {
    c.buf = make([]byte, 0, n)
}
```

**2. ~~Dangling doc comment on `parsePublicKeyFromString`~~ (fixed in `8001ce9`).** The
`parsedPublicKeys` block had landed between the doc comment and the function it documented,
leaving `parsePublicKeyFromString` undocumented in effect and `parsePublicKeyFromStringUncached`
with no doc line at all. The follow-up commit moved the sentence back onto
`parsePublicKeyFromString` (`jwtauth.go:2045`) and added a line for `parsePublicKeyFromStringUncached`
(`jwtauth.go:2059`).

**3. Comments reference a `benchmark.sh` that isn't in the tree (low, still open).** The doc
comment on `expectedCacheKey` in `jwtauth_tokencache_test.go:31` still explains that this file and
`jwtauth_scopeclaim_test.go` are in `benchmark.sh`'s `BASELINE_EXCLUDE`, and that
`createMockRequestHeaderContextWithAPI` / `clearJWKSFetchCache` were moved to
`jwtauth_hardening_test.go` specifically to keep other tests baseline-buildable.
`find . -iname benchmark.sh` still returns nothing anywhere in the repo. Either land the script or
drop the reference — as it stands the comment explains a constraint no reader can verify, and the
file move it justifies looks arbitrary.

**4. The shared-immutable invariant is documented for `cachedVerdict.claims` but not for the
constraint caches (low, still open).** `resolveScopeConstraintsCached` / `resolveClaimConstraintsCached`
(`jwtauth.go:1624`, `1653`) hand out `ScopeConstraints` / `ClaimConstraints` whose `[]string` and
`[]ClaimMatcher` fields are shared across every request and route with a matching digest. Today's
evaluators are read-only so this is correct, but it is the same convention-only invariant that
`cachedVerdict` got a paragraph of warning about (§1.6) — worth one sentence on each cache for
symmetry.

**5. `tokenConfigFingerprint`'s doc claims more than the code does (informational, still open).**
It states the fingerprint "folds in everything that determines the signature-verification verdict
and nothing that does not" (`jwtauth.go:442`), but `jwksCacheTtl`, `jwksFetchTimeout`,
`jwksFetchRetryCount`, and `jwksFetchRetryInterval` are excluded. That's defensible and
pre-existing — they shape fetch behaviour, not the verdict — but `jwksCacheTtl` does bound how
stale the verifying key may be, so the comment would read more honestly with a clause saying so
and why it's still excluded.

**6. `configHasher.value` collapses `int`, `int64`, and `float64` into one tag (informational,
still open).** `int64` values above 2⁵³ lose precision on conversion to `float64`, so two distinct
configs could in principle digest identically. Irrelevant for anything the config decoder actually
produces (JSON numbers are already `float64`), and `int(1)` colliding with `float64(1.0)` is
deliberate. Worth knowing that the `default:` safety net leans on `fmt.Sprintf("%T:%v")` being
deterministic — which it is for maps only because Go has printed them in sorted key order since
1.12.

**7. Key-manager selection order is nondeterministic, and sharing widens the blast radius
(informational, pre-existing, still open).** `validateTokenWithSignature` iterates `keyManagers`, a
`map[string]*KeyManager`, so if two key managers can both verify the same token — plausible with
`validateIssuer: false` — which one "matches" varies per request, and its `scopeClaim` decides the
cached `scopes`. This PR didn't introduce that, but it does mean one arbitrary winner is now
frozen into a single entry shared by every API rather than per-API. Deterministic ordering (or an
explicit "first match wins by config order" rule) would be worth a follow-up.

**8. `deepCopyClaimValue` adds a per-request cost to the success path (informational, still open,
by design).** Every successful request now deep-copies each container-valued non-standard claim.
That is the right trade — copying at write time wouldn't help, since the copy would still be
shared — but it is a new allocation on the hot path, and it scales with claim payload size. Worth
keeping in mind for tokens with large structured claims.

**9. `v1.3.0 → v1.3.1` (decided).** The observable behaviour changed — a token verified for API A
is now trusted for API B without re-verification, and routes with differing `tokenCacheTtl` stop
sharing entries — but neither changes the config surface, so this landed as a patch bump.

### Verification performed (at merge time)

- `go vet ./...` — clean.
- `gofmt -l .` — flags only `jwtauth_test.go`, which this refactor doesn't touch and which was
  already unformatted on the base commit.
- `go test -race -count=1 ./...` — passes.
- Current cache-specific tests (`jwtauth_tokencache_test.go`): `TestTokenCache_PositiveHit_SkipsVerification`,
  `TestTokenCache_SharedAcrossAPIs_ConstraintsStillEnforcedPerAPI`, `TestTokenCache_NegativeHit_Expired`,
  `TestTokenCache_NegativeHit_Malformed`, `TestTokenCache_SignatureMismatch_NotCached`,
  `TestTokenCache_JWKSFetchFailure_NotCached`, `TestTokenCache_NotYetValid_NotCached`,
  `TestTokenCache_Disabled_NoCacheEntries`, `TestTokenCache_PositiveTTL_CappedByTokenCacheTtl`,
  `TestTokenCache_PositiveTTL_NeverExceedsTokenExpiry`, `TestTokenCache_NegativeTTL_ExpiresAfterWindow`,
  `TestTokenConfigFingerprint_ChangesInvalidateCache`, `TestGetPolicy_TokenCacheMaxSizeApplied`,
  `TestCacheMaxSize_GloballyBounded_TokenCache`, `TestTokenCache_DifferentTokenCacheTtl_DoesNotShareCacheEntry`,
  `TestConfigMemoizationCaches_ClearedByReset`.
- Traced every consumer of `cachedVerdict.claims` and `.scopes` for in-place mutation:
  `buildProperties`, `buildTypedProperties`, `parseAudience`, `buildScopesMap`,
  `evaluateScopeConstraints`, `evaluateClaimConstraints`, `handleAuthSuccessHeaders` are all
  read-only. `deepCopyClaimValue` closes the one real gap (§1.6).
- Cross-checked every input to `validateTokenWithSignature` against the fingerprint: key material,
  `km.Issuer`, `km.ScopeClaim`/`ScopeClaimSeparator` (all inside `kmDigest`), `userIssuers`,
  `validateIssuer`, `leeway` are covered. `supportedAlgorithms` is a package-level constant.
- Confirmed the encoding is injective for realistic config: fixed-size type tags, length-prefixed
  strings, sorted map keys, and a fixed-length 32-byte fingerprint before the `0x00` separator in
  `buildTokenCacheKey` (so the split point is positional, not delimiter-dependent).
- Confirmed `parsePublicKeyFromString` is only ever reached from config-supplied data (an inline
  cert or a `certificatePath` read), never from a token or a JWKS response — so the unbounded
  `parsedPublicKeys` map is not request-driven.

**Overall: the design is sound.** The cross-API sharing argument holds, and §2.2 is a genuine
security-relevant fix that happened to be found by doing this refactor. Everything in Part 3 is
minor and mostly informational.
