using System.IdentityModel.Tokens;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Local.Default {
	public sealed class JsonWebTokenSigner : IJsonWebTokenSigner {
		private readonly IPrivateKeyProvider m_privateKeyProvider;
		private readonly string m_issuer;

		internal JsonWebTokenSigner(
			IPrivateKeyProvider privateKeyProvider,
			string issuer
		) {
			m_privateKeyProvider = privateKeyProvider;
			m_issuer = issuer;
		}

		async Task<string> IJsonWebTokenSigner.SignAsync( UnsignedToken token ) {
			using( D2LSigningCredentials signingCredentials = await m_privateKeyProvider.GetSigningCredentialsAsync().SafeAsync() ) {
				var jwt = new JwtSecurityToken(
					issuer: m_issuer,
					audience: token.Audience,
					claims: token.Claims,
					notBefore: token.NotBefore,
					expires: token.ExpiresAt,
					signingCredentials: signingCredentials );

				var jwtHandler = new JwtSecurityTokenHandler();

				string signedRawToken = jwtHandler.WriteToken( jwt );

				return signedRawToken;
			}
		}
	}
}
