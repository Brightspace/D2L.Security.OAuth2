using Microsoft.IdentityModel.JsonWebTokens;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Validation.Exceptions;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;

namespace D2L.Security.OAuth2.Keys.Default {
	public sealed partial class TokenSigner : ITokenSigner {

		private readonly IPrivateKeyProvider m_privateKeyProvider;
		private readonly JsonWebTokenHandler m_tokenHandler = new() { SetDefaultTimesOnTokenCreation = false };

		public TokenSigner(
			IKeyManagementService keyManagementService
		) : this( (IPrivateKeyProvider)keyManagementService ) {}

		internal TokenSigner(
			IPrivateKeyProvider privateKeyProvider
		) {
			m_privateKeyProvider = privateKeyProvider;
		}

		[GenerateSync]
		async Task<string> ITokenSigner.SignAsync( UnsignedToken token ) {
			using( D2LSecurityToken securityToken = await m_privateKeyProvider
				.GetSigningCredentialsAsync()
				.ConfigureAwait( false )
			) {
				SecurityTokenDescriptor jwt = new SecurityTokenDescriptor() {
					Issuer = token.Issuer,
					Audience = token.Audience,
					NotBefore = token.NotBefore,
					Expires = token.ExpiresAt,
					SigningCredentials = securityToken.GetSigningCredentials(),
					Claims = new Dictionary<string, object>(),
				};

				var claims = token.Claims;
				foreach( var claim in claims ) {
					if( jwt.Claims.ContainsKey( claim.Key ) ) {
						throw new ValidationException( $"'{claim.Key}' is already part of the payload" );
					}
					jwt.Claims.Add( claim.Key, claim.Value );
				}

				string signedRawToken = m_tokenHandler.CreateToken( jwt );

				return signedRawToken;
			}
		}
	}
}
