using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

using D2L.Security.OAuth2.Keys;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Utilities {
	internal static class D2LSecurityTokenUtility {
		public static D2LSecurityToken CreateActiveToken( Guid? id = null ) {
			return CreateTokenWithTimeRemaining(
				TimeSpan.FromHours( 1 ) - TimeSpan.FromSeconds( 1 ),
				id );
		}

		public static D2LSecurityToken CreateTokenWithTimeRemaining(
			TimeSpan remaining,
			Guid? id = null
		) {

			id = id ?? Guid.NewGuid();

			var validTo = DateTime.UtcNow + remaining;
			var validFrom = validTo - TimeSpan.FromHours( 1 );
			var csp = new RSACryptoServiceProvider( 2048 ) {
				PersistKeyInCsp = false
			};
			var key = new RsaSecurityKey( csp );

			return new D2LSecurityToken(
				id.Value,
				validFrom,
				validTo,
				key );
		}
	}
}
