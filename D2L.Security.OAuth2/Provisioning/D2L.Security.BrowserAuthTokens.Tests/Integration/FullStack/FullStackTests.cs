using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using D2L.Security.BrowserAuthTokens.Default;
using D2L.Security.BrowserAuthTokens.Invocation;
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
			IAccessToken accessToken = task.Result;


		}
	}
}
