using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using D2L.Security.AuthTokenProvisioning.Invocation;

namespace D2L.Security.AuthTokenProvisioning.Default {
	internal sealed class AuthTokenProvider : IAuthTokenProvider {

		// Used to sign assertion grant jwts
		private readonly SigningCredentials m_signingCredentials;
		private readonly IAuthServiceInvoker m_serviceInvoker;

		internal AuthTokenProvider( 
			X509Certificate2 signingCertificate,
			IAuthServiceInvoker serviceInvoker
			) {
			m_signingCredentials = new X509SigningCredentials( signingCertificate );
			m_serviceInvoker = serviceInvoker;
		}

		async Task<IAccessToken> IAuthTokenProvider.ProvisionAccessTokenAsync( ProvisioningParameters provisioningParams ) {
			InvocationParameters invocationParams = CreateInvocationParams( provisioningParams );
			string assertionGrantResponse = await m_serviceInvoker.ProvisionAccessTokenAsync( invocationParams );

			IAccessToken accessToken = SerializationHelper.ExtractAccessToken( assertionGrantResponse );

			return accessToken;
		}

		IAccessToken IAuthTokenProvider.ProvisionAccessToken( ProvisioningParameters provisioningParams ) {
			InvocationParameters invocationParams = CreateInvocationParams( provisioningParams );
			string assertionGrantResponse = m_serviceInvoker.ProvisionAccessToken( invocationParams );

			IAccessToken accessToken = SerializationHelper.ExtractAccessToken( assertionGrantResponse );

			return accessToken;
		}

		private InvocationParameters CreateInvocationParams( ProvisioningParameters provisioningParams ) {
			IEnumerable<Claim> claims = BuildClaims( provisioningParams );

			JwtSecurityToken jwt = new JwtSecurityToken(
				provisioningParams.ClientId,
				Constants.AssertionGrant.AUDIENCE,
				claims,
				null,
				provisioningParams.Expiry,
				m_signingCredentials
				);

			JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
			string assertionToken = handler.WriteToken( jwt );

			InvocationParameters invocationParams = provisioningParams.ToInvocationParameters( assertionToken );

			return invocationParams;
		}

		private static IEnumerable<Claim> BuildClaims( ProvisioningParameters provisioningParams ) {
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
	}
}