using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using D2L.Security.BrowserAuthTokens.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.BrowserAuthTokens.Tests.Integration.FullStack {
	
	[TestFixture]
	internal sealed class FullStackTests {

		private readonly IAuthTokenProvider m_tokenProvider = 
			AuthTokenProviderFactory.Create(
				TestCredentials.LMS.CERTIFICATE,
				TestUris.AUTH_TOKEN_PROVISIONING_URI
				);

		[Test]
		public void IAuthTokenProvider_ProvisionAccessTokenAsync_Success() {
			string userId = "smUser";
			string tenantId = "smTenant";
			string tenantUrl = "smTenantUrl";
			string xsrf = "smXsrf";

			ProvisioningParameters provisioningParams = new ProvisioningParameters(
				TestCredentials.LMS.CLIENT_ID,
				TestCredentials.LMS.CLIENT_SECRET,
				new string[] { TestCredentials.LOReSScopes.MANAGE },
				tenantId,
				tenantUrl
				);
			provisioningParams.UserId = userId;
			provisioningParams.Xsrf = xsrf;

			Task<IAccessToken> task = m_tokenProvider.ProvisionAccessTokenAsync( provisioningParams );
			IAccessToken serializedAccessToken = task.Result;

			JwtSecurityToken token = new JwtSecurityToken( serializedAccessToken.Token );

			token.AssertHasClaim( Constants.Claims.XSRF, xsrf );
			token.AssertHasClaim( Constants.Claims.USER, userId );
			token.AssertHasClaim( Constants.Claims.TENANT_URL, tenantUrl );
			token.AssertHasClaim( Constants.Claims.TENANT_ID, tenantId );
		}

		[Explicit( "Remove Explicit attribute once auth server supports optional sub claims" )]
		[Test]
		public void IAuthTokenProvider_ProvisionAccessTokenAsync_NoUserId_Success() {
			string tenantId = "smTenant";
			string tenantUrl = "smTenantUrl";
			string xsrf = "smXsrf";

			ProvisioningParameters provisioningParams = new ProvisioningParameters(
				TestCredentials.LMS.CLIENT_ID,
				TestCredentials.LMS.CLIENT_SECRET,
				new string[] { TestCredentials.LOReSScopes.MANAGE },
				tenantId,
				tenantUrl
				);
			provisioningParams.Xsrf = xsrf;

			Task<IAccessToken> task = m_tokenProvider.ProvisionAccessTokenAsync( provisioningParams );
			IAccessToken serializedAccessToken = task.Result;

			JwtSecurityToken token = new JwtSecurityToken( serializedAccessToken.Token );

			token.AssertDoesNotHaveClaim( Constants.Claims.USER );
			token.AssertHasClaim( Constants.Claims.XSRF, xsrf );
			token.AssertHasClaim( Constants.Claims.TENANT_URL, tenantUrl );
			token.AssertHasClaim( Constants.Claims.TENANT_ID, tenantId );
		}

		[Test]
		public void IAuthTokenProvider_ProvisionAccessTokenAsync_NoXsrf_Success() {
			string tenantId = "smTenant";
			string tenantUrl = "smTenantUrl";
			string userId = "smUser";

			ProvisioningParameters provisioningParams = new ProvisioningParameters(
				TestCredentials.LMS.CLIENT_ID,
				TestCredentials.LMS.CLIENT_SECRET,
				new string[] { TestCredentials.LOReSScopes.MANAGE },
				tenantId,
				tenantUrl
				);
			provisioningParams.UserId = userId;

			Task<IAccessToken> task = m_tokenProvider.ProvisionAccessTokenAsync( provisioningParams );
			IAccessToken serializedAccessToken = task.Result;

			JwtSecurityToken token = new JwtSecurityToken( serializedAccessToken.Token );

			token.AssertDoesNotHaveClaim( Constants.Claims.XSRF );
			token.AssertHasClaim( Constants.Claims.USER, userId );
			token.AssertHasClaim( Constants.Claims.TENANT_URL, tenantUrl );
			token.AssertHasClaim( Constants.Claims.TENANT_ID, tenantId );
		}
	}
}
