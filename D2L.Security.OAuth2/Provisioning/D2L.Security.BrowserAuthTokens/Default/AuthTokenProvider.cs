using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.BrowserAuthTokens.Invocation;

namespace D2L.Security.BrowserAuthTokens.Default {
	internal sealed class AuthTokenProvider : IAuthTokenProvider {

		// Used to sign assertion grant jwts
		private readonly SigningCredentials m_signingCredentials;
		private readonly IAuthServiceInvoker m_serviceInvoker;

		internal AuthTokenProvider( 
			X509Certificate2 signingCertificate,
			IAuthServiceInvoker serviceInvoker
			) {
			m_signingCredentials = new X509SigningCredentials( signingCertificate );
		}

		Task<string> IAuthTokenProvider.GetTokenForUserAsync( ProvisioningParameters provisioningParams ) {
			IEnumerable<Claim> claims = BuildClaims( provisioningParams );

			JwtSecurityToken jwt = new JwtSecurityToken(
				provisioningParams.ClientId,
				"https://api.brightspace.com/auth/token",
				claims,
				null,
				provisioningParams.Expiry,
				m_signingCredentials
				);

			JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
			string serializedAssertionToken = handler.WriteToken( jwt );

			
		}

		private static IEnumerable<Claim> BuildClaims( ProvisioningParameters provisioningParams ) {
			DateTime expiry = DateTime.UtcNow + Constants.AssertionGrant.ASSERTION_TOKEN_LIFETIME;

			IList<Claim> claims = new List<Claim>();
			AddClaim( claims, Constants.Claims.USER, provisioningParams.UserId );
			AddClaim( claims, Constants.Claims.TENANT_ID, provisioningParams.TenantId );
			AddClaim( claims, Constants.Claims.TENANT_URL, provisioningParams.TenantUrl );
			AddClaim( claims, Constants.Claims.XSRF, provisioningParams.Xsrf );

			return claims;
		}

		private static void AddClaim( IList<Claim> claims, string type, string value ) {
			if( value != null ) {
				claims.Add( new Claim( type, value ) );
			}
		}

		private string MakeJwt() {
			string userId = "dummyuserid";
			string tenantId = "dummytenantid";
			string tenantUrl = "dummytenanturl";
			string xsrf = "dummyxsrf";

			DateTime expiry = DateTime.UtcNow + Constants.AssertionGrant.ASSERTION_TOKEN_LIFETIME;

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