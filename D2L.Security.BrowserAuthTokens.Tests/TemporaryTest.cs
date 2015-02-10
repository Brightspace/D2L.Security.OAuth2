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
			//string jwt = AsyncHelper.RunSync<string>( () => ReadResponse() );
			string accessToken = ReadResponse().Result;
		}

		private async Task<string> ReadResponse() {
			string password = "lms_dev_keypair";
			byte[] certificateRawData = Resources.lms_dev_d2l;
			X509Certificate2 certificate = new X509Certificate2( certificateRawData, password );

			string[] scopeFragments = new string[] { 
				"https://api.brightspace.com/auth/lores.manage" 
			};

			IAuthTokenProvider tokenProvider = AuthTokenProviderFactory.Create(
				certificate,
				TestUris.AUTH_TOKEN_PROVISIONING_URI
				);

			string clientId = "lms.dev.d2l";
			string clientSecret = "lms_secret";
			ProvisioningParameters provisioningParams = new ProvisioningParameters(
				clientId,
				clientSecret,
				scopeFragments,
				"dummytenantID",
				"dummytenantURL"
				);

			provisioningParams.UserId = "1337";

			return await tokenProvider.ProvisionAccessToken( provisioningParams );
		}
	}
}
