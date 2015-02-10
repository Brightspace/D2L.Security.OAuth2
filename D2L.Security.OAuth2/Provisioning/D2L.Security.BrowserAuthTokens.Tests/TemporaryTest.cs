using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using D2L.Security.BrowserAuthTokens.Default;
using D2L.Security.BrowserAuthTokens.Invocation;
using D2L.Security.BrowserAuthTokens.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.BrowserAuthTokens.Tests {
	
	[TestFixture]
	internal sealed class TemporaryTest {
		
		[Test]
		public void ASSERTION_GRANT_TEMPORARY_TEST() {
			string accessToken = ReadResponse().Result;
		}

		private async Task<string> ReadResponse() {
			X509Certificate2 certificate = new X509Certificate2(
				Resources.lms_dev_d2l, 
				Resources.lms_dev_d2l_PASSWORD 
				);

			IAuthTokenProvider tokenProvider = AuthTokenProviderFactory.Create(
				certificate,
				TestUris.AUTH_TOKEN_PROVISIONING_URI
				);

			ProvisioningParameters provisioningParams = new ProvisioningParameters(
				TestCredentials.LMS.CLIENT_ID,
				TestCredentials.LMS.CLIENT_SECRET,
				new string[] { TestCredentials.LOReSScopes.MANAGE },
				"dummytenantID",
				"dummytenantURL"
				);

			provisioningParams.UserId = "1337";

			return await tokenProvider.ProvisionAccessToken( provisioningParams );
		}
	}
}
