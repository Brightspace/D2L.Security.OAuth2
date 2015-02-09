using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using D2L.Security.BrowserAuthTokens.Default;
using D2L.Security.BrowserAuthTokens.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.BrowserAuthTokens.Tests {
	
	[TestFixture]
	internal sealed class TemporaryTest {
		
		[Test]
		public void MAKEJWT_TEST() {
			Task t = ReadResponse();
			t.Wait();
		}

		private async Task ReadResponse() {
			string password = "lms_dev_keypair";
			byte[] certificateRawData = Resources.lms_dev_d2l;
			X509Certificate2 certificate = new X509Certificate2( certificateRawData, password );

			string[] scopeFragments = new string[] { 
				"https://api.brightspace.com/auth/lores.manage" 
			};
			string scopes = SerializationHelper.SerializeScopes( scopeFragments );

			IAuthTokenProvider tokenProvider = AuthTokenProviderFactory.Create(
				certificate,
				TestUris.AUTH_TOKEN_PROVISIONING_URI
				);

		}
	}
}
