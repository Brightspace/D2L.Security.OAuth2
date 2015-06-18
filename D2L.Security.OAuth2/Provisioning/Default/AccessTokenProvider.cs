using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Keys.Local;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning.Default {

	internal sealed class AccessTokenProvider : IAccessTokenProvider {
		private readonly IAuthServiceClient m_client;
		private readonly IKeyManager m_keyManager;
		private readonly bool m_disposeOfClient;

		public AccessTokenProvider(
			IKeyManager keyManager,
			IAuthServiceClient authServiceClient,
			bool disposeOfClient = true
		) {
			m_keyManager = keyManager;
			m_client = authServiceClient;
			m_disposeOfClient = disposeOfClient;
		}

		Task<IAccessToken> IAccessTokenProvider.ProvisionAccessTokenAsync(
			ClaimSet claimSet,	
			IEnumerable<Scope> scopes,
			ICache cache
		) {
			var @this = this as IAccessTokenProvider;
			return @this.ProvisionAccessTokenAsync( claimSet.ToClaims(), scopes );
		}

		async Task<IAccessToken> IAccessTokenProvider.ProvisionAccessTokenAsync(
			IEnumerable<Claim> claimSet,
			IEnumerable<Scope> scopes,
			ICache cache
		) {
			List<Claim> claims = claimSet.ToList();

			scopes = scopes ?? Enumerable.Empty<Scope>();

			DateTime now = DateTime.UtcNow;

			string issuer;
			if( !claims.TryGetClaim( Constants.Claims.ISSUER, out issuer ) ) {
				throw new InvalidOperationException( "missing issuer claim" );
			}

			var unsignedToken = new UnsignedToken(
				issuer: issuer,
				audience: ProvisioningConstants.AssertionGrant.AUDIENCE,
				claims: claims,
				notBefore: now,
				expiresAt: now + ProvisioningConstants.AssertionGrant.ASSERTION_TOKEN_LIFETIME );

			string assertion = await m_keyManager
				.SignAsync( unsignedToken )
				.SafeAsync();

			return await m_client
				.ProvisionAccessTokenAsync( assertion, scopes )
				.SafeAsync();
		}

		public void Dispose() {
			if( m_disposeOfClient ) {
				m_client.Dispose();
			}
		}
	}
}