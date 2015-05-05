using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Keys.Local;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning.Default {
	public sealed class AccessTokenProvider : IAccessTokenProvider {
		private readonly string m_issuer;
		private readonly IAuthServiceClient m_client;
		private readonly IKeyManager m_keyManager;
		private readonly bool m_disposeOfClient;

		public AccessTokenProvider(
			string issuer,
			IKeyManager keyManager,
			IAuthServiceClient authServiceClient,
			bool disposeOfClient = true
		) {
			m_issuer = issuer;
			m_keyManager = keyManager;
			m_client = authServiceClient;
			m_disposeOfClient = disposeOfClient;
		}

		async Task<IAccessToken> IAccessTokenProvider.ProvisionAccessTokenAsync(
			IEnumerable<Claim> claimSet,
			IEnumerable<Scope> scopes
		) {
			scopes = scopes ?? Enumerable.Empty<Scope>();

			DateTime now = DateTime.UtcNow;

			var unsignedToken = new UnsignedToken(
				issuer: m_issuer,
				audience: ProvisioningConstants.AssertionGrant.AUDIENCE,
				claims: claimSet.ToList(),
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