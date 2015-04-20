using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Local.Default {
	internal sealed class KeyManager : IKeyManager {
		private readonly IPublicKeyProvider m_publicKeyProvider;
		private readonly IPrivateKeyProvider m_privateKeyProvider;
		private readonly string m_issuer;

		public KeyManager(
			string issuer,
			IPublicKeyProvider publicKeyProvider,
			IPrivateKeyProvider privateKeyProvider
		) {
			m_issuer = issuer;
			m_publicKeyProvider = publicKeyProvider;
			m_privateKeyProvider = privateKeyProvider;
		}

		Task<JsonWebKey> IPublicKeyProvider.GetByIdAsync( Guid id ) {
			return m_publicKeyProvider.GetByIdAsync( id );
		}

		Task<IEnumerable<JsonWebKey>> IPublicKeyProvider.GetAllAsync() {
			return m_publicKeyProvider.GetAllAsync();
		}

		async Task<string> IKeyManager.SignAsync( UnsignedToken token ) {
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
