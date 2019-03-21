using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Services;

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
				.SafeAsync()
			) {
				jwt = new JwtSecurityToken(
					issuer: token.Issuer,
					audience: token.Audience,
					claims: token.Claims,
					notBefore: token.NotBefore,
					expires: token.ExpiresAt,
					signingCredentials: securityToken.GetSigningCredentials()
				);

				var jwtHandler = new JwtSecurityTokenHandler();

				string signedRawToken = jwtHandler.WriteToken( jwt );

				return signedRawToken;
			}
		}

        async Task<string> ITokenSigner.SignAsync( UnsignedComplexToken token ) {
            JwtSecurityToken jwt;
            using( D2LSecurityToken securityToken = await m_privateKeyProvider
                .GetSigningCredentialsAsync()
                .SafeAsync()
            ) {
                jwt = new JwtSecurityToken(
                    issuer: token.Issuer,
                    audience: token.Audience,
                    claims: new List<Claim>(),
                    notBefore: token.NotBefore,
                    expires: token.ExpiresAt,
                    signingCredentials: securityToken.GetSigningCredentials()
                );

                var claims = token.Claims;
                foreach( var claim in claims ) {
                    jwt.Payload.Add( claim.Key, claim.Value );
                }

                var jwtHandler = new JwtSecurityTokenHandler();

                string signedRawToken = jwtHandler.WriteToken( jwt );

                return signedRawToken;
            }
        }
    }
}
