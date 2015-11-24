using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Request;
using D2L.Services;

namespace D2L.Security.OAuth2 {
	internal static class TestUtilities {
		private static ITokenSigner m_signer;

		static TestUtilities() {
			IPublicKeyDataProvider publicKeyDataProvider = new InMemoryPublicKeyDataProvider();

			m_signer = EcDsaTokenSignerFactory
				.Create( publicKeyDataProvider, EcDsaTokenSignerFactory.Curve.P256 );

			IAccessTokenValidator accessTokenValidator = AccessTokenValidatorFactory
				.CreateLocalValidator( publicKeyDataProvider );

			RequestAuthenticator = RequestAuthenticatorFactory.Create( accessTokenValidator );
		}

		public static IRequestAuthenticator RequestAuthenticator { get; private set; }

		public static async Task<string> GetAccessTokenValidForAMinute(
			long? userId = null,
			string scope = null,
			Guid? tenantId = null,
			DateTime? issuedAtTime = null
		) {
			issuedAtTime = issuedAtTime ?? DateTime.UtcNow;
			scope = scope ?? "*:*:*";
			tenantId = tenantId ?? Guid.NewGuid();

			var claims = new List<Claim>();

			claims.Add( new Claim( Constants.Claims.SCOPE, scope ) );
			claims.Add( new Claim( Constants.Claims.TENANT_ID, tenantId.ToString() ) );

			if( userId != null ) {
				claims.Add( new Claim( Constants.Claims.USER_ID, userId.Value.ToString() ) );
			}

			return await m_signer.SignAsync(
				new UnsignedToken(
					issuer: Constants.ACCESS_TOKEN_ISSUER,
					audience: Constants.ACCESS_TOKEN_AUDIENCE,
					claims: claims,
					notBefore: issuedAtTime.Value,
					expiresAt: issuedAtTime.Value + TimeSpan.FromMinutes( 1 )
				)
			).SafeAsync();
		}
	}
}
