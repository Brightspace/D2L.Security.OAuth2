using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenValidation.Tests.Utilities;
using D2L.Security.BrowserAuthTokens.Default;
using D2L.Security.BrowserAuthTokens.Default.Serialization;
using NUnit.Framework;

namespace D2L.Security.BrowserAuthTokens.Tests {
	
	[TestFixture]
	internal sealed class TemporaryTest {

		[Test]
		public void THROWAWAY_TEST() {
			AuthServerInvoker.TEST();
		}

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

			string grantJwt = AuthServerInvoker.MakeJwt2( certificate );

			string jwt = await AuthServerInvoker.AuthenticateAndGetJwt(
				TestUris.AUTH_TOKEN_PROVISIONING_URI,
				grantJwt,
				scopes
				);
		}
	}
}
