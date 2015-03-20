using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace D2L.Security.AuthTokenProvisioning {
	public static class SigningTokenFactory {

		public static SecurityToken CreateSigningToken(
			SecurityKey key,
			Guid keyId
		) {
			var token = new KidSecurityToken(
				keyId.ToString(),
				key
			);

			return token;
		}

		public static SecurityToken CreateSigningToken(
			RSA rsa,
			Guid keyId
		) {
			var key = new RsaSecurityKey( rsa );

			SecurityToken token = CreateSigningToken( key, keyId );

			return token;
		}

	}
}
