using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace D2L.Security.AuthTokenProvisioning.Default {
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

		void IDisposable.Dispose() {
			if( m_disposeClient ) {
				m_client.Dispose();
			}
		}

		private static string BuildAssertion( ClaimSet claimSet, SecurityToken signingToken ) {
			SigningCredentials signingCredentials = BuildSigningCredentials( signingToken );
			IEnumerable<Claim> claims = claimSet.ToClaims();
			DateTime expiry = DateTime.UtcNow.Add( Constants.AssertionGrant.ASSERTION_TOKEN_LIFETIME );

			var jwt = new JwtSecurityToken(
				audience: Constants.AssertionGrant.AUDIENCE,
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
			if( keyName.Name != Constants.AssertionGrant.KEY_ID_NAME ) {
				throw new ArgumentException(
					String.Format("Token must be named \"{0}\"", Constants.AssertionGrant.KEY_ID_NAME),
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