using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.BrowserAuthTokens.Default {
	internal sealed class AuthTokenProvider : IAuthTokenProvider {

		// Used to sign assertion grant jwts
		private readonly SigningCredentials m_signingCredentials;

		internal AuthTokenProvider( X509Certificate2 signingCertificate ) {
			m_signingCredentials = new X509SigningCredentials( signingCertificate );
		}

		Task<string> IAuthTokenProvider.GetTokenForUserAsync( string tenantId, long userId, string xsrfToken ) {
			throw new NotImplementedException();
		}
		
		private string MakeJwt() {
			string userId = "dummyuserid";
			string tenantId = "dummytenantid";
			string tenantUrl = "dummytenanturl";
			string xsrf = "dummyxsrf";

			DateTime expiry = DateTime.UtcNow + Constants.ASSERTION_GRANT_JWT_LIFETIME;

			IList<Claim> claims = new List<Claim>();
			claims.Add( new Claim( "sub", userId ) );
			claims.Add( new Claim( "tenantid", tenantId ) );
			claims.Add( new Claim( "tenanturl", tenantUrl ) );
			claims.Add( new Claim( "xt", xsrf ) );
			
			JwtSecurityToken jwt = new JwtSecurityToken(
				"lms.dev.d2l",
				"https://api.brightspace.com/auth/token",
				claims,
				null,
				expiry,
				m_signingCredentials
				);

			JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
			return handler.WriteToken( jwt );
		}
	}
}