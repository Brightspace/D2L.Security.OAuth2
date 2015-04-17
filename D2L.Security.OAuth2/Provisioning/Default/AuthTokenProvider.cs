using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning.Default {
	public sealed class AuthTokenProvider : IAuthTokenProvider {

		private readonly IAuthServiceClient m_client;
		private readonly bool m_disposeClient;

		public AuthTokenProvider(
			IAuthServiceClient authServiceClient,
			bool disposeAuthServiceClient = true
		) {
			m_client = authServiceClient;
			m_disposeClient = disposeAuthServiceClient;
		}

		Task<IAccessToken> IAuthTokenProvider.ProvisionAccessTokenAsync(
			ClaimSet claimSet,
			IEnumerable<Scope> scopes,
			SecurityToken signingToken
		) {
			if( claimSet == null ) {
				throw new ArgumentNullException( "claimSet" );
			}

			if( signingToken == null ) {
				throw new ArgumentNullException( "signingToken" );
			}

			scopes = scopes ?? Enumerable.Empty<Scope>();

			string assertion = BuildAssertion( claimSet, signingToken );

			return m_client.ProvisionAccessTokenAsync( assertion, scopes );
		}

		IAccessToken IAuthTokenProvider.ProvisionAccessToken(
			ClaimSet claimSet,
			IEnumerable<Scope> scopes,
			SecurityToken signingToken
		) {
			var @this = this as IAuthTokenProvider;

			var token = @this.ProvisionAccessTokenAsync( claimSet, scopes, signingToken ).Result;
			return token;
		}

		public void Dispose() {
			if( m_disposeClient ) {
				m_client.Dispose();
			}
		}

		private static string BuildAssertion( ClaimSet claimSet, SecurityToken signingToken ) {
			SigningCredentials signingCredentials = BuildSigningCredentials( signingToken );
			IEnumerable<Claim> claims = claimSet.ToClaims();
			DateTime expiry = DateTime.UtcNow.Add( ProvisioningConstants.AssertionGrant.ASSERTION_TOKEN_LIFETIME );

			var jwt = new JwtSecurityToken(
				audience: ProvisioningConstants.AssertionGrant.AUDIENCE,
				claims: claimSet.ToClaims(),
				expires: expiry,
				signingCredentials: signingCredentials
			);

			var jwtHandler = new JwtSecurityTokenHandler();
			string assertion = jwtHandler.WriteToken( jwt );

			return assertion;
		}

		private static SigningCredentials BuildSigningCredentials( SecurityToken signingToken ) {
			if( !signingToken.CanCreateKeyIdentifierClause<NamedKeySecurityKeyIdentifierClause>() ) {
				throw new ArgumentException( "Token must be named", "signingToken" );
			}

			var keyName = signingToken.CreateKeyIdentifierClause<NamedKeySecurityKeyIdentifierClause>();
			if( keyName.Name != ProvisioningConstants.AssertionGrant.KEY_ID_NAME ) {
				throw new ArgumentException(
					String.Format("Token must be named \"{0}\"", ProvisioningConstants.AssertionGrant.KEY_ID_NAME),
					"signingToken"
				);
			}

			if( signingToken.SecurityKeys.Count != 1 ) {
				throw new ArgumentException(
					"Token must contain a single SecurityKey",
					"signingToken"
				);
			}

			SecurityKey key = signingToken.SecurityKeys[0];

			string supportedAlgorithm = FindSupportedAlgorithm( key );
			if( supportedAlgorithm == null ) {
				throw new ArgumentException(
					"Token does not provide a supported signing algorithm",
					"signingToken"
				);
			}

			SigningCredentials signingCredentials = new SigningCredentials(
				key,
				supportedAlgorithm,
				SecurityAlgorithms.Sha256Digest,
				new SecurityKeyIdentifier( keyName )
			);

			return signingCredentials;
		}

		private static string[] SUPPORTED_ALGORITHMS = new string[] {
			SecurityAlgorithms.RsaSha256Signature
		};
		private static string FindSupportedAlgorithm( SecurityKey key ) {
			foreach( var algorithm in SUPPORTED_ALGORITHMS ) {
				if( key.IsSupportedAlgorithm( algorithm ) ) {
					return algorithm;
				}
			}

			return null;
		}
	}
}