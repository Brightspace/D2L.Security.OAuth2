using System.Net.Http;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Integration.FullStack {
	
	[TestFixture]
	internal sealed class FullStackTests {

		[Test]
		public void HttpRequestMessage_Cookie_NoXsrf_Success() {
			string cookieValue = TestTokens.VALID_NO_XSRF_JWT;

			HttpRequestMessage httpRequestMessage = new HttpRequestMessage();
			RequestBuilder.AddCookie( httpRequestMessage, cookieValue );

			IRequestAuthenticator requestAuthenticator = RequestAuthenticatorFactory.Create(
				TestUris.TOKEN_VERIFICATION_AUTHORITY_URI,
				Mode.SkipXsrfValidation
				);

			ID2LPrincipal principal;
			AuthenticationResult result = requestAuthenticator.AuthenticateAndExtract( httpRequestMessage, out principal );
		}

		[Test]
		public void HttpRequestMessage_Cookie_WithXsrf_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequestMessage_BearerToken_NoXsrf_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequestMessage_BearerToken_WithXsrf_Success() {
			Assert.Inconclusive();
		}








		[Test]
		public void IRequestAuthenticator_AuthenticateAndExtract_NoXsrf_HttpRequest_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void IRequestAuthenticator_AuthenticateAndExtract_WithXsrf_HttpRequest_Success() {
			Assert.Inconclusive();
		}
	}
}
