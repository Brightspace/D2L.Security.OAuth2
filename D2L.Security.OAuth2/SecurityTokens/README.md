D2L.Security.OAuth2.SecurityTokens
==================================

This code defines interfaces to manage `D2LSecurityToken` objects and provides default implementations.

This functionality is used, for example, by the auth service to sign access tokens and by services to sign assertions, and both expose their public keys via a JWKS route.

Intended use
------------
Services will need to sign assertions for the JWT bearer token grant using the output of `ISecurityTokenManager.GetLatestTokenAsync()` and they need to broadcast the public keys they get from `ISecurityTokenManager.GetAllTokens()` via a JWKS route.

Steps:

1. Implemenent an `ISecurityTokenManager` that persists keys.
   - You can *prototype* with the `InMemorySecurityTokenManager` provided by this library.
2. Dependency inject `ISecurityTokenManager` using the `RollingSecurityTokenManager` implementation (defined in this library) passing your `ISecurityTokenManager` as its inner implementation.

Consider using the `LocalPrivateKeySecurityTokenManager` provided by this library.
When paired with an `ISecurityTokenManager` that only persists public keys (a requirement) `LocalPrivateKeySecurityTokenManager` keeps a single private key in-memory but is still able to return all public keys via the `GetAllTokens()` function.
This protects the system from read-only access to the database (but not write-access: the attacker could install their own public keys.)
Note: `LocalPrivateKeySecurityTokenManager` should still be wrapped in `RollingSecurityTokenmanager`.

Theory of key rotation
----------------------
We want to avoid non-expiring keys on Brightspace.
Doing automatic key rotation ensures:

1. The system doesn't depend on keys lasting forever.
2. We can bound the consequences of an immediate key switch (vs. a gradual rotation.)
3. We ensure that keys are not being manually configured by humans.
4. If there is a transient attack, recovery is potentially automatic (however the attacker may be able to escalate a one-time access to a key into a longer term position.)

In a distributed system we can't immediately revoke a key and have no consequences.
To cope with this we do a gradual rotation where we keep "expiring" keys around for some window but stop actively using them in favour of a newer key.

If an attack were to be noticed and fixed, the impact of revoking a key immediately can be understood better due to the rotation window: it bounds the number of access tokens/assertions/etc. which become invalidated early (effectively) to a finite number. 