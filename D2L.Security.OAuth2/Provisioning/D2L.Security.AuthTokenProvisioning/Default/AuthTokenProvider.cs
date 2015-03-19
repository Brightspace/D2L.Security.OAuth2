using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Linq;
using D2L.Security.AuthTokenProvisioning.Client;

namespace D2L.Security.AuthTokenProvisioning.Default {
	internal sealed class AuthTokenProvider : IAuthTokenProvider {

		private readonly IAuthServiceClient m_client;

		internal AuthTokenProvider(	IAuthServiceClient serviceInvoker ) {
			m_client = serviceInvoker;
		}

		Task<IAccessToken> IAuthTokenProvider.ProvisionAccessTokenAsync(
			ClaimSet claimSet,
			IEnumerable<Scope> scopes,
			SecurityToken signingToken
		) {
			var signingCredentials = BuildSigningCredentials( signingToken );
			var claims = claimSet.ToClaims();
			var expiry = DateTime.UtcNow.Add( Constants.AssertionGrant.ASSERTION_TOKEN_LIFETIME );

			var jwt = new JwtSecurityToken(
				audience: Constants.AssertionGrant.AUDIENCE,
				claims: claimSet.ToClaims(),
				expires: expiry,
				signingCredentials: signingCredentials
			);

			var jwtHandler = new JwtSecurityTokenHandler();
			var assertion = jwtHandler.WriteToken( jwt );

			return m_client.ProvisionAccessTokenAsync( assertion, scopes );
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

			var key = signingToken.SecurityKeys[0];

			var supportedAlgorithm = FindSupportedAlgorithm( key );
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