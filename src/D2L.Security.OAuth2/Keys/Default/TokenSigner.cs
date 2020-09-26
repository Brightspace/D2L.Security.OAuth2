using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Exceptions;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class TokenSigner : ITokenSigner {

		private readonly IPrivateKeyProvider m_privateKeyProvider;

		public TokenSigner(
			IPrivateKeyProvider privateKeyProvider
		) {
			m_privateKeyProvider = privateKeyProvider;
		}

		async Task<string> ITokenSigner.SignAsync( UnsignedToken token ) {
			JwtSecurityToken jwt;
			using( D2LSecurityToken securityToken = await m_privateKeyProvider
				.GetSigningCredentialsAsync()
				.ConfigureAwait( false )
			) {
				jwt = new JwtSecurityToken(
					issuer: token.Issuer,
					audience: token.Audience,
					claims: Enumerable.Empty<Claim>(),
					notBefore: token.NotBefore,
					expires: token.ExpiresAt,
					signingCredentials: securityToken.GetSigningCredentials()
				);

				var claims = token.Claims;
				foreach( var claim in claims ) {
					if( jwt.Payload.ContainsKey( claim.Key ) ) {
						throw new ValidationException( $"'{claim.Key}' is already part of the payload" );
					}
					jwt.Payload.Add( claim.Key, claim.Value );
				}

				var jwtHandler = new JwtSecurityTokenHandler();

				string signedRawToken = jwtHandler.WriteToken( jwt );

				return signedRawToken;
			}
		}
	}
}
