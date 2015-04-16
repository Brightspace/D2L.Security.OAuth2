using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.SecurityTokens;

namespace D2L.Security.OAuth2.Tests.Utilities {
	public static class AccessTokenUtility  {

		public static string CreateJwt(
			D2LSecurityToken signingToken,
			string issuer = "someissuer",
			string keyId = "somekid",
			string audience = "someaudience",
			string tenantId = "sometenantid",
			string subject = "somesubject",
			IEnumerable<Claim> claims = null,
			DateTime? expiry = null
		) {
			
			claims = claims ?? Enumerable.Empty<Claim>();
			
			expiry = expiry ?? DateTime.UtcNow.Add( TimeSpan.FromHours( 1 ) );

			SigningCredentials credentials = null;

			var token = new JwtSecurityToken(
				issuer: issuer,
				audience: audience,
				claims: claims,
				signingCredentials: credentials,
				expires: expiry
			);

			var tokenHandler = new JwtSecurityTokenHandler();
			string serializedToken = tokenHandler.WriteToken( token );

			return serializedToken;
		}
		
	}
}
