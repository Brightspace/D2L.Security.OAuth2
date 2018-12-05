using System;
using System.Security.Cryptography;
using D2L.Security.OAuth2.Keys.Default;
using Microsoft.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.TestUtilities {
	internal static class D2LSecurityTokenUtility {
		public static D2LSecurityKey CreateActiveToken( Guid? id = null ) {
			return CreateTokenWithTimeRemaining(
				TimeSpan.FromHours( 1 ) - TimeSpan.FromSeconds( 1 ),
				id );
		}

		public static D2LSecurityKey CreateTokenWithTimeRemaining(
			TimeSpan remaining,
			Guid? id = null
		) {

			id = id ?? Guid.NewGuid();

			var validTo = DateTime.UtcNow + remaining;
			var validFrom = validTo - TimeSpan.FromHours( 1 );

			RSAParameters privateKey;
			using( var csp = new RSACryptoServiceProvider( Keys.Constants.GENERATED_RSA_KEY_SIZE ) {
				PersistKeyInCsp = false
			} ) {
				privateKey = csp.ExportParameters( includePrivateParameters: true );
			}

			return new D2LSecurityKey(
				id.Value,
				validFrom,
				validTo,
				keyFactory: () => {
					var csp = new RSACryptoServiceProvider() { PersistKeyInCsp = false };
					csp.ImportParameters( privateKey );
					var key = new RsaSecurityKey( csp );
					return ( key, csp );
				}
			);
		}
	}
}
