D2L.Security.OAuth2.SecurityTokens
==================================

This code defines interfaces to manage `D2LSecurityToken` objects and provides default implementations.

This functionality is used, for example, by the auth service to sign access tokens and by services to sign assertions, and both expose their public keys via a JWKS route.

Intended use
------------
Services will need to sign assertions for the JWT bearer token grant using the output of `ISecurityTokenProvider.GetLatestTokenAsync()` and they need to broadcast the public keys they get from `ISecurityTokenProvider.GetAllTokens()` via a JWKS route.

Steps:

1. Implemenent an `ISecurityTokenProvider` that persists keys.
    - You can *prototype* with the `InMemorySecurityTokenProvider` provided by this library.
2. Dependency inject `ISecurityTokenProvider` using the `RollingSecurityTokenProvider` implementation (defined in this library) passing your `ISecurityTokenProvider` as its inner implementation.

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