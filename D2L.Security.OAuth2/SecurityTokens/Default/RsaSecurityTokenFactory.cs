using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace D2L.Security.OAuth2.SecurityTokens.Default {
	public sealed class RsaSecurityTokenFactory : ISecurityTokenFactory {
		D2LSecurityToken ISecurityTokenFactory.Create( TimeSpan lifespan ) {
			var csp = new RSACryptoServiceProvider(
				dwKeySize: 2048
			) {
				PersistKeyInCsp = false
			};

			var key = new RsaSecurityKey( csp );

			var token = new D2LSecurityToken(
				lifespan,
				key
			);

			return token;
		}
	}
}
