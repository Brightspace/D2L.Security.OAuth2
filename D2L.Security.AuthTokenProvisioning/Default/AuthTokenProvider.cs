using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.AuthTokenProvisioning.Invocation;

namespace D2L.Security.AuthTokenProvisioning.Default {
	internal sealed class AuthTokenProvider : IAuthTokenProvider {

		private readonly IAuthServiceInvoker m_serviceInvoker;

		internal AuthTokenProvider(	IAuthServiceInvoker serviceInvoker ) {
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

			SigningCredentials signingCredentials = BuildSigningCredentials( provisioningParams );

			JwtSecurityToken jwt = new JwtSecurityToken(
				provisioningParams.ClientId,
				Constants.AssertionGrant.AUDIENCE,
				claims,
				null,
				provisioningParams.Expiry,
				signingCredentials
				);

			JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
			string assertionToken = handler.WriteToken( jwt );

			InvocationParameters invocationParams = provisioningParams.ToInvocationParameters( assertionToken );

			return invocationParams;
		}

		private static SigningCredentials BuildSigningCredentials( ProvisioningParameters provisioningParams ) {
			RsaSecurityKey rsaSecurityKey = new RsaSecurityKey( provisioningParams.SigningKey );
			SigningCredentials signingCredentials = new SigningCredentials(
				rsaSecurityKey,
				SecurityAlgorithms.RsaSha256Signature,
				SecurityAlgorithms.Sha256Digest
				);

			return signingCredentials;
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