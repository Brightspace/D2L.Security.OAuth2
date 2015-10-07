using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning.Default {

	internal sealed class AccessTokenProvider : INonCachingAccessTokenProvider {

		private readonly IAuthServiceClient m_client;
		private readonly ITokenSigner m_tokenSigner;

		public AccessTokenProvider(
			ITokenSigner tokenSigner,
			IAuthServiceClient authServiceClient
		) {
			m_tokenSigner = tokenSigner;
			m_client = authServiceClient;
		}

		Task<IAccessToken> INonCachingAccessTokenProvider.ProvisionAccessTokenAsync(
			ClaimSet claimSet,	
			IEnumerable<Scope> scopes
		) {
			var @this = this as INonCachingAccessTokenProvider;
			return @this.ProvisionAccessTokenAsync( claimSet.ToClaims(), scopes );
		}

		async Task<IAccessToken> INonCachingAccessTokenProvider.ProvisionAccessTokenAsync(
			IEnumerable<Claim> claimSet,
			IEnumerable<Scope> scopes
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
				audience: Constants.ASSERTION_AUDIENCE,
				claims: claims,
				notBefore: now,
				expiresAt: now + Constants.ASSERTION_TOKEN_LIFETIME );

			string assertion = await m_tokenSigner
				.SignAsync( unsignedToken )
				.SafeAsync();

			return await m_client
				.ProvisionAccessTokenAsync( assertion, scopes )
				.SafeAsync();
		}
	}
}