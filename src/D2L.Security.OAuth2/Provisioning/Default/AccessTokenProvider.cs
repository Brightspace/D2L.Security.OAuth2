using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning.Default {

	internal sealed partial class AccessTokenProvider : INonCachingAccessTokenProvider {

		private readonly IAuthServiceClient m_client;
		private readonly ITokenSigner m_tokenSigner;

		public AccessTokenProvider(
			ITokenSigner tokenSigner,
			IAuthServiceClient authServiceClient
		) {
			m_tokenSigner = tokenSigner;
			m_client = authServiceClient;
		}

		[GenerateSync]
		async Task<IAccessToken> INonCachingAccessTokenProvider.ProvisionAccessTokenAsync(
			IEnumerable<Claim> claimSet,
			IEnumerable<Scope> scopes
		) {
			List<Claim> claims = claimSet.ToList();

			scopes = scopes ?? Enumerable.Empty<Scope>();

			DateTime now = DateTime.UtcNow;

			string issuer = claims.FirstOrDefault( c => c.Type == Constants.Claims.ISSUER )?.Value;
			if( issuer == null ) {
				throw new InvalidOperationException( "missing issuer claim" );
			}

			var filteredClaims = claims
				.Where( t => t.Type != Constants.Claims.ISSUER )
				.ToDictionary( t => t.Type, t => (object)t.Value );

			var unsignedToken = new UnsignedToken(
				issuer: issuer,
				audience: Constants.ASSERTION_AUDIENCE,
				claims: filteredClaims,
				notBefore: now,
				expiresAt: now + Constants.ASSERTION_TOKEN_LIFETIME );

			string assertion = await m_tokenSigner
				.SignAsync( unsignedToken )
				.ConfigureAwait( false );

			return await m_client
				.ProvisionAccessTokenAsync( assertion, scopes )
				.ConfigureAwait( false );
		}
	}
}
